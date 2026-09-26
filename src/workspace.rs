use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: u64,
    pub name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contest {
    pub entry: Entry,
    pub next_challenge: u64,
    pub challenges: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Index {
    pub version: u32,
    pub next_contest: u64,
    pub current_contest: Option<u64>,
    pub contests: Vec<Contest>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    pub operation: String,
    pub contest: Option<u64>,
    pub id: u64,
    pub old: Option<String>,
    pub new: String,
}

pub struct Workspace {
    pub root: PathBuf,
    index: Index,
    _lock: File,
}

pub fn home() -> Result<PathBuf> {
    match std::env::var_os("CTF_HOME") {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        Some(_) => bail!("CTF_HOME must not be empty"),
        None => Ok(user_home()?.join("CTF")),
    }
}

pub fn user_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context("HOME is not set; set HOME or CTF_HOME")
}

impl Workspace {
    pub fn open() -> Result<Self> {
        Self::at(home()?)
    }

    pub fn at(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("create workspace {}", root.display()))?;
        let root = root.canonicalize()?;
        let meta = root.join(".ctf");
        directory(&meta)?;
        let lock_path = meta.join("lock");
        reject_link(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.lock().context("lock workspace")?;
        ensure!(
            fs::symlink_metadata(meta.join("pending.json"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "interrupted lifecycle operation; run `ctf doctor` before making changes"
        );
        let index_path = meta.join("index.json");
        reject_link(&index_path)?;
        let index = match fs::read(&index_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid workspace metadata (index.json); restore a backup rather than resetting IDs")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Index {
                version: 1, next_contest: 1, current_contest: None, contests: Vec::new(),
            },
            Err(error) => return Err(error.into()),
        };
        let ws = Self {
            root,
            index,
            _lock: lock,
        };
        ws.validate()?;
        if !index_path.exists() {
            ws.save()?;
        }
        Ok(ws)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.index.version == 1,
            "unsupported workspace metadata version"
        );
        validate_entries(&self.contest_entries(), self.index.next_contest)?;
        for contest in &self.index.contests {
            validate_entries(&contest.challenges, contest.next_challenge)?;
        }
        if let Some(id) = self.index.current_contest {
            self.contest(id)?;
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        atomic_json(&self.root.join(".ctf/index.json"), &self.index)
    }

    fn contest(&self, id: u64) -> Result<&Contest> {
        self.index
            .contests
            .iter()
            .find(|c| c.entry.id == id)
            .context("contest ID not found")
    }

    pub fn contest_entries(&self) -> Vec<Entry> {
        self.index
            .contests
            .iter()
            .map(|c| c.entry.clone())
            .collect()
    }

    pub fn challenge_entries(&self, id: u64) -> Result<Vec<Entry>> {
        Ok(self.contest(id)?.challenges.clone())
    }

    pub fn contest_name(&self, id: u64) -> Result<&str> {
        Ok(&self.contest(id)?.entry.name)
    }

    pub fn contest_path(&self, id: u64) -> Result<PathBuf> {
        checked_directory(&self.root.join(self.contest_name(id)?))
    }

    pub fn challenge_path(&self, contest: u64, id: u64) -> Result<PathBuf> {
        let entry = self
            .contest(contest)?
            .challenges
            .iter()
            .find(|c| c.id == id)
            .context("challenge ID not found")?;
        checked_directory(&self.contest_path(contest)?.join(&entry.name))
    }

    pub fn create_contest(&mut self, name: &str) -> Result<Entry> {
        validate_name(name)?;
        ensure!(
            !self.index.contests.iter().any(|c| c.entry.name == name),
            "contest already exists: {name}"
        );
        let entry = Entry {
            id: self.index.next_contest,
            name: name.into(),
        };
        self.index.next_contest = entry
            .id
            .checked_add(1)
            .context("contest ID space exhausted")?;
        // Reserve IDs before filesystem changes: a failed creation may leave a gap, never a reused ID.
        self.save()?;
        let path = self.root.join(name);
        fs::create_dir(&path).with_context(|| {
            format!(
                "create contest {} (existing directories are never adopted)",
                path.display()
            )
        })?;
        directory(&path.join(".ctf"))?;
        self.index.contests.push(Contest {
            entry: entry.clone(),
            next_challenge: 1,
            challenges: Vec::new(),
        });
        if self.index.current_contest.is_none() {
            self.index.current_contest = Some(entry.id);
        }
        self.save()?;
        Ok(entry)
    }

    pub fn create_challenge(&mut self, contest: u64, name: &str) -> Result<Entry> {
        validate_name(name)?;
        let path = self.contest_path(contest)?.join(name);
        let c = self
            .index
            .contests
            .iter_mut()
            .find(|c| c.entry.id == contest)
            .context("contest ID not found")?;
        ensure!(
            !c.challenges.iter().any(|e| e.name == name),
            "challenge already exists: {name}"
        );
        let entry = Entry {
            id: c.next_challenge,
            name: name.into(),
        };
        c.next_challenge = entry
            .id
            .checked_add(1)
            .context("challenge ID space exhausted")?;
        self.save()?;
        fs::create_dir(&path).with_context(|| {
            format!(
                "create challenge {} (existing directories are never adopted)",
                path.display()
            )
        })?;
        directory(&path.join(".ctf"))?;
        crate::attachments::save(&path, &crate::attachments::Metadata::default())?;
        self.index
            .contests
            .iter_mut()
            .find(|c| c.entry.id == contest)
            .context("contest ID not found")?
            .challenges
            .push(entry.clone());
        self.save()?;
        Ok(entry)
    }

    pub fn select_contest(&mut self, id: u64) -> Result<()> {
        self.contest_path(id)?;
        self.index.current_contest = Some(id);
        self.save()
    }

    fn begin(&self, pending: &Pending) -> Result<()> {
        atomic_json(&self.root.join(".ctf/pending.json"), pending)
    }

    fn finish(&self) -> Result<()> {
        fs::remove_file(self.root.join(".ctf/pending.json"))?;
        File::open(self.root.join(".ctf"))?.sync_all()?;
        Ok(())
    }

    /// Rename within one parent. The journal remains on any ambiguous commit failure.
    pub fn rename(
        &mut self,
        contest: Option<u64>,
        id: u64,
        name: &str,
    ) -> Result<(PathBuf, PathBuf)> {
        validate_name(name)?;
        let entries = match contest {
            Some(c) => self.challenge_entries(c)?,
            None => self.contest_entries(),
        };
        let entry = entries
            .iter()
            .find(|e| e.id == id)
            .context("ID not found")?;
        ensure!(
            !entries.iter().any(|e| e.name == name),
            "destination name already registered: {name}"
        );
        let parent = match contest {
            Some(c) => self.contest_path(c)?,
            None => self.root.clone(),
        };
        let old = checked_directory(&parent.join(&entry.name))?;
        let new = parent.join(name);
        ensure!(
            fs::symlink_metadata(&new).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "destination already exists or cannot be inspected"
        );
        checked_directory(&old.join(".ctf"))?;
        let mut locks = Vec::new();
        if contest.is_some() {
            locks.push(crate::attachments::lock(&old)?);
            crate::attachments::load(&old)?;
        } else {
            for c in self.challenge_entries(id)? {
                let path = self.challenge_path(id, c.id)?;
                locks.push(crate::attachments::lock(&path)?);
                crate::attachments::load(&path)?;
            }
        }
        self.begin(&Pending {
            operation: "rename".into(),
            contest,
            id,
            old: Some(entry.name.clone()),
            new: name.into(),
        })?;
        if let Err(error) = rustix::fs::renameat_with(
            rustix::fs::CWD,
            &old,
            rustix::fs::CWD,
            &new,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            self.finish()?; // Failed syscall did not move the directory.
            return Err(error).context("rename directory; destination was not replaced");
        }
        File::open(&parent)?.sync_all()?;
        match contest {
            Some(c) => {
                self.index
                    .contests
                    .iter_mut()
                    .find(|e| e.entry.id == c)
                    .context("contest missing")?
                    .challenges
                    .iter_mut()
                    .find(|e| e.id == id)
                    .context("challenge missing")?
                    .name = name.into()
            }
            None => {
                self.index
                    .contests
                    .iter_mut()
                    .find(|e| e.entry.id == id)
                    .context("contest missing")?
                    .entry
                    .name = name.into()
            }
        }
        self.save().context("directory renamed but metadata commit failed; run `ctf doctor` and inspect pending.json")?;
        self.finish()?;
        Ok((old, new))
    }

    pub fn adopt(&mut self, contest: Option<u64>, input: &Path) -> Result<Entry> {
        let parent = match contest {
            Some(c) => self.contest_path(c)?,
            None => self.root.clone(),
        };
        ensure!(
            !input
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
            "adoption path must not contain .."
        );
        let path = if input.components().count() == 1 && !input.is_absolute() {
            parent.join(input)
        } else if input.is_absolute() {
            input.to_path_buf()
        } else {
            std::env::current_dir()?.join(input)
        };
        // Check every existing component before canonicalization so aliases cannot hide symlinks.
        let mut prefix = PathBuf::new();
        for component in path.components() {
            prefix.push(component);
            reject_link(&prefix)?;
        }
        checked_directory(&path)?;
        let path = path.canonicalize()?;
        ensure!(
            path.parent() == Some(parent.as_path()),
            "adopt only a direct child of {}",
            parent.display()
        );
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("adoption name must be UTF-8")?;
        validate_name(name)?;
        ensure!(
            fs::symlink_metadata(path.join(".ctf"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "directory already contains .ctf; existing metadata is never overwritten or inferred"
        );
        let entries = match contest {
            Some(c) => self.challenge_entries(c)?,
            None => self.contest_entries(),
        };
        ensure!(
            !entries.iter().any(|e| e.name == name),
            "directory already registered"
        );
        let next = match contest {
            Some(c) => {
                &mut self
                    .index
                    .contests
                    .iter_mut()
                    .find(|e| e.entry.id == c)
                    .context("contest missing")?
                    .next_challenge
            }
            None => &mut self.index.next_contest,
        };
        let entry = Entry {
            id: *next,
            name: name.into(),
        };
        *next = next
            .checked_add(1)
            .context("permanent ID space exhausted")?;
        self.save()?; // Reservations survive failed adoption; IDs are never reused.
        self.begin(&Pending {
            operation: "adopt".into(),
            contest,
            id: entry.id,
            old: None,
            new: name.into(),
        })?;
        fs::create_dir(path.join(".ctf"))?;
        if let Some(c) = contest {
            crate::attachments::save(&path, &crate::attachments::Metadata::default())?;
            self.index
                .contests
                .iter_mut()
                .find(|e| e.entry.id == c)
                .context("contest missing")?
                .challenges
                .push(entry.clone());
        } else {
            self.index.contests.push(Contest {
                entry: entry.clone(),
                next_challenge: 1,
                challenges: Vec::new(),
            });
            if self.index.current_contest.is_none() {
                self.index.current_contest = Some(entry.id);
            }
        }
        File::open(path.join(".ctf"))?.sync_all()?;
        File::open(&path)?.sync_all()?;
        self.save()
            .context("adoption metadata commit failed; run `ctf doctor`")?;
        self.finish()?;
        Ok(entry)
    }

    fn cwd_ids(&self) -> Result<(Option<u64>, Option<u64>)> {
        let cwd = std::env::current_dir()?.canonicalize()?;
        for c in &self.index.contests {
            let path = self.root.join(&c.entry.name);
            if cwd.starts_with(&path) {
                self.contest_path(c.entry.id)?;
                for challenge in &c.challenges {
                    if cwd.starts_with(path.join(&challenge.name)) {
                        self.challenge_path(c.entry.id, challenge.id)?;
                        return Ok((Some(c.entry.id), Some(challenge.id)));
                    }
                }
                return Ok((Some(c.entry.id), None));
            }
        }
        Ok((None, None))
    }

    pub fn current_contest(&self) -> Result<u64> {
        self.cwd_ids()?
            .0
            .or(self.index.current_contest)
            .context("no current contest; run `ctf contest new NAME` or `ctf use ID`")
    }

    pub fn current_challenge(&self) -> Result<Option<u64>> {
        Ok(self.cwd_ids()?.1)
    }

    pub fn current_challenge_path(&self) -> Result<PathBuf> {
        let (contest, challenge) = self.cwd_ids()?;
        self.challenge_path(
            contest.context("run this command inside a challenge; use `ctf go ID`")?,
            challenge.context("run this command inside a challenge; use `ctf go ID`")?,
        )
    }
}

fn validate_entries(entries: &[Entry], next: u64) -> Result<()> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    ensure!(next > 0, "invalid next ID in metadata");
    for entry in entries {
        validate_name(&entry.name).context("invalid name in metadata")?;
        ensure!(
            entry.id > 0 && entry.id < next && ids.insert(entry.id),
            "invalid or duplicate permanent ID in metadata"
        );
        ensure!(names.insert(&entry.name), "duplicate name in metadata");
    }
    Ok(())
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.trim().is_empty() && name != "." && name != "..",
        "name must be nonempty and cannot be a dot component"
    );
    ensure!(name != ".ctf", "reserved name: {name}");
    ensure!(
        !name.chars().any(|c| c.is_control() || c == '/'),
        "name contains a control character or slash"
    );
    Ok(())
}

pub fn reject_link(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                !meta.file_type().is_symlink(),
                "symlink not allowed: {}",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub fn directory(path: &Path) -> Result<()> {
    reject_link(path)?;
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(error) => Err(error).with_context(|| format!("create directory {}", path.display())),
    }
}

fn checked_directory(path: &Path) -> Result<PathBuf> {
    reject_link(path)?;
    ensure!(path.is_dir(), "directory missing: {}", path.display());
    Ok(path.to_path_buf())
}

pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    reject_link(path)?;
    let parent = path.parent().context("metadata path has no parent")?;
    reject_link(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temp, value)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .with_context(|| format!("commit metadata {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn folded(value: &str) -> String {
    value.nfkc().flat_map(char::to_lowercase).collect()
}

fn score(name: &str, query: &str) -> Option<(usize, usize)> {
    if name == query {
        return Some((0, 0));
    }
    let chars: Vec<char> = name.chars().collect();
    let term: Vec<char> = query.chars().collect();
    if term.is_empty() {
        return Some((0, 0));
    }
    if let Some(start) = chars.windows(term.len()).position(|w| w == term) {
        return Some((if start == 0 { 1 } else { 2 }, start));
    }
    let mut cursor = 0;
    let mut penalty = 0;
    for c in term {
        let offset = chars[cursor..].iter().position(|n| *n == c)?;
        penalty += offset;
        cursor += offset + 1;
    }
    Some((3, penalty))
}

pub fn matches<'a>(entries: &'a [Entry], query: &[String]) -> Vec<&'a Entry> {
    let terms: Vec<String> = query
        .iter()
        .flat_map(|q| q.split_whitespace())
        .map(folded)
        .collect();
    let mut scored: Vec<_> = entries
        .iter()
        .filter_map(|entry| {
            let name = folded(&entry.name);
            let total = terms.iter().try_fold((0, 0), |(rank, distance), term| {
                score(&name, term).map(|(r, d)| (rank + r, distance + d))
            });
            total.map(|s| (s, entry))
        })
        .collect();
    scored.sort_by_key(|(s, entry)| (*s, entry.id));
    scored.into_iter().map(|(_, entry)| entry).collect()
}

pub fn resolve<'a>(entries: &'a [Entry], query: &[String]) -> Result<&'a Entry> {
    let joined = query.join(" ");
    ensure!(
        !joined.trim().is_empty(),
        "provide an ID or a nonempty query"
    );
    if let Ok(id) = joined.parse::<u64>() {
        return entries
            .iter()
            .find(|e| e.id == id)
            .with_context(|| format!("ID {id} not found"));
    }
    if let Some(entry) = entries.iter().find(|e| e.name == joined) {
        return Ok(entry);
    }
    let exact: Vec<_> = entries
        .iter()
        .filter(|e| folded(&e.name) == folded(&joined))
        .collect();
    let found = if exact.is_empty() {
        matches(entries, query)
    } else {
        exact
    };
    match found.as_slice() {
        [] => bail!("no matches for {joined:?}"),
        [entry] => Ok(entry),
        _ => {
            let candidates = found
                .iter()
                .take(10)
                .map(|e| format!("  {}\t{}", e.id, e.name))
                .collect::<Vec<_>>()
                .join("\n");
            let more = if found.len() > 10 {
                format!("\n  … {} more; narrow the query", found.len() - 10)
            } else {
                String::new()
            };
            bail!(
                "ambiguous query {joined:?} ({} matches); choose an ID:\n{candidates}{more}",
                found.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_rename_commit_leaves_recoverable_journal() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut ws = Workspace::at(temp.path().into())?;
        let contest = ws.create_contest("old")?;
        let index = temp.path().join(".ctf/index.json");
        let before = fs::read(&index)?;
        fs::remove_file(&index)?;
        fs::create_dir(&index)?; // Real persist failure after the directory rename.
        assert!(ws.rename(None, contest.id, "new").is_err());
        assert!(temp.path().join("new").is_dir());
        assert!(temp.path().join(".ctf/pending.json").is_file());
        fs::remove_dir(&index)?;
        fs::write(index, before)?;
        drop(ws);
        assert!(Workspace::at(temp.path().into()).is_err());
        assert!(crate::doctor::run(temp.path(), true).is_err());
        fs::rename(temp.path().join("new"), temp.path().join("old"))?;
        crate::doctor::run(temp.path(), true)?;
        assert_eq!(
            Workspace::at(temp.path().into())?.contest_entries()[0].id,
            contest.id
        );
        Ok(())
    }
    #[test]
    fn unicode_fuzzy_and_ambiguity() {
        let entries = vec![
            Entry {
                id: 4,
                name: "签到题".into(),
            },
            Entry {
                id: 9,
                name: "easyRSA".into(),
            },
            Entry {
                id: 20,
                name: "hard RSA".into(),
            },
        ];
        assert_eq!(resolve(&entries, &["签题".into()]).unwrap().id, 4);
        assert_eq!(matches(&entries, &["rsa".into(), "easy".into()])[0].id, 9);
        assert!(
            resolve(&entries, &["RSA".into()])
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
        assert_eq!(resolve(&entries, &["20".into()]).unwrap().name, "hard RSA");
        assert!(matches(&entries, &["longer than any entry in this set".into()]).is_empty());
        assert_eq!(folded("ＥＡＳＹ"), "easy");
    }

    #[test]
    fn ranking_is_exact_prefix_substring_then_subsequence() {
        let entries = vec![
            Entry {
                id: 1,
                name: "r-s-a".into(),
            },
            Entry {
                id: 2,
                name: format!("{}rsa", "x".repeat(200)),
            },
            Entry {
                id: 3,
                name: "RSA签到".into(),
            },
            Entry {
                id: 4,
                name: "rsa".into(),
            },
        ];
        let ids: Vec<_> = matches(&entries, &["RSA".into()])
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, [4, 3, 2, 1]);
        assert_eq!(resolve(&entries, &["RSA".into()]).unwrap().id, 4);
        assert_eq!(resolve(&entries, &["r签".into()]).unwrap().id, 3);
    }
    #[test]
    fn stable_ids_and_integrity() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut ws = Workspace::at(temp.path().into())?;
        let c = ws.create_contest("研究生网络安全创新大赛")?;
        let a = ws.create_challenge(c.id, "签到题")?;
        fs::remove_dir_all(ws.challenge_path(c.id, a.id)?)?;
        let b = ws.create_challenge(c.id, "easyRSA")?;
        assert_eq!((a.id, b.id), (1, 2));
        drop(ws);
        let ws = Workspace::at(temp.path().into())?;
        assert_eq!(ws.challenge_entries(c.id)?[1].id, 2);
        drop(ws);
        fs::write(temp.path().join(".ctf/index.json"), b"{broken")?;
        assert!(Workspace::at(temp.path().into()).is_err());
        assert_eq!(fs::read(temp.path().join(".ctf/index.json"))?, b"{broken");
        Ok(())
    }
}
