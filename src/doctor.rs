//! Read-only inspection does not use Workspace::open: damage must never initialize an index.
use crate::{
    attachments,
    workspace::{self, Entry, Index},
};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

struct Audit {
    root: PathBuf,
    fix: bool,
    problems: usize,
}

pub fn run(root: &Path, fix: bool) -> Result<()> {
    let mut audit = Audit {
        root: root.to_path_buf(),
        fix,
        problems: 0,
    };
    audit.inspect()?;
    if audit.problems != 0 {
        bail!(
            "{} unresolved issue(s); restore damaged metadata from backup or resolve reported paths explicitly",
            audit.problems
        );
    }
    Ok(())
}

impl Audit {
    fn report(&mut self, severity: &str, message: &str, path: &Path) -> Result<()> {
        // Debug-escape paths so hostile filenames cannot inject output records.
        writeln!(
            std::io::stdout().lock(),
            "{severity:<8} {message}: {:?}",
            path.strip_prefix(&self.root).unwrap_or(path)
        )?;
        if severity != "OK" && severity != "FIXED" {
            self.problems += 1;
        }
        Ok(())
    }

    fn check(&mut self, path: &Path, directory: bool, label: &str) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                self.report("ERROR", "unsafe symlink", path)?
            }
            Ok(meta)
                if if directory {
                    meta.is_dir()
                } else {
                    meta.is_file()
                } =>
            {
                return Ok(true);
            }
            Ok(_) => self.report("ERROR", "unexpected file type", path)?,
            Err(error) => self.report("ERROR", &format!("{label}: {error}"), path)?,
        }
        Ok(false)
    }

    fn entries(&mut self, entries: &[Entry], next: u64, path: &Path) -> Result<bool> {
        let before = self.problems;
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        if next == 0 || entries.iter().any(|e| e.id >= next) {
            self.report("ERROR", "invalid next permanent ID", path)?;
        }
        for entry in entries {
            if entry.id == 0 || !ids.insert(entry.id) {
                self.report("ERROR", "invalid or duplicate permanent ID", path)?;
            }
            if !names.insert(&entry.name) {
                self.report("ERROR", "duplicate name", path)?;
            }
            if workspace::validate_name(&entry.name).is_err() {
                self.report("ERROR", "unsafe metadata name/reference", path)?;
            }
        }
        Ok(before == self.problems)
    }

    fn inspect(&mut self) -> Result<()> {
        let root = self.root.clone();
        let meta = root.join(".ctf");
        if !self.check(&root, true, "workspace missing")?
            || !self.check(&meta, true, "workspace metadata missing")?
        {
            return Ok(());
        }
        let lock = meta.join("lock");
        if !self.check(&lock, false, "workspace lock missing")? {
            return Ok(());
        }
        let _guard = File::open(&lock)?;
        _guard.lock().context("lock workspace for inspection")?;
        let index_path = meta.join("index.json");
        if !self.check(
            &index_path,
            false,
            "workspace index missing; restore a backup",
        )? {
            return Ok(());
        }
        let mut index: Index = match serde_json::from_slice(&fs::read(&index_path)?) {
            Ok(index) => index,
            Err(_) => {
                self.report(
                    "ERROR",
                    "corrupt workspace metadata; restore a backup",
                    &index_path,
                )?;
                return Ok(());
            }
        };
        if index.version != 1 {
            self.report(
                "ERROR",
                "unsupported workspace metadata version",
                &index_path,
            )?;
            return Ok(());
        }
        let contests: Vec<_> = index.contests.iter().map(|c| c.entry.clone()).collect();
        let mut valid = self.entries(&contests, index.next_contest, &index_path)?;
        for contest in &index.contests {
            valid &= self.entries(&contest.challenges, contest.next_challenge, &index_path)?;
        }
        if !valid {
            return Ok(());
        } // Never follow ambiguous or unsafe metadata references.
        self.report("OK", "workspace metadata", &index_path)?;
        if index
            .current_contest
            .is_some_and(|id| !index.contests.iter().any(|c| c.entry.id == id))
        {
            if self.fix {
                index.current_contest = None;
                workspace::atomic_json(&index_path, &index)?;
            }
            self.report(
                if self.fix { "FIXED" } else { "FIXABLE" },
                "invalid current contest selection",
                &index_path,
            )?;
        }
        self.internal(&meta)?;
        self.unregistered(&root, &contests)?;
        for contest in index.contests {
            let path = root.join(&contest.entry.name);
            if !self.check(
                &path,
                true,
                &format!("contest #{} directory missing", contest.entry.id),
            )? {
                continue;
            }
            if self.check(&path.join(".ctf"), true, "contest metadata missing")? {
                self.internal(&path.join(".ctf"))?;
            }
            self.unregistered(&path, &contest.challenges)?;
            for challenge in contest.challenges {
                let path = path.join(&challenge.name);
                if self.check(
                    &path,
                    true,
                    &format!("challenge #{} directory missing", challenge.id),
                )? {
                    self.challenge(&path)?;
                }
            }
        }
        Ok(())
    }

    fn unregistered(&mut self, parent: &Path, entries: &[Entry]) -> Result<()> {
        for path in children(parent)? {
            let name = path.file_name().unwrap_or_default();
            if name == ".ctf" || entries.iter().any(|e| name == e.name.as_str()) {
                continue;
            }
            let kind = fs::symlink_metadata(&path)?.file_type();
            if kind.is_symlink() {
                self.report("ERROR", "unsafe managed-directory symlink", &path)?;
            } else if kind.is_dir() {
                self.report(
                    "WARN",
                    "unregistered directory; explicitly adopt or move it",
                    &path,
                )?;
            }
        }
        Ok(())
    }

    fn internal(&mut self, meta: &Path) -> Result<()> {
        for path in children(meta)? {
            let kind = fs::symlink_metadata(&path)?.file_type();
            if kind.is_symlink() {
                self.report("ERROR", "unsafe metadata symlink", &path)?;
            } else if kind.is_file()
                && path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .starts_with(".tmp")
            {
                self.disposable(&path, false, "abandoned metadata temporary file")?;
            } else if path.file_name().unwrap_or_default() == "pending.json" {
                self.report("ERROR", "interrupted lifecycle operation; inspect pending record before manual recovery", &path)?;
            }
        }
        Ok(())
    }

    fn disposable(&mut self, path: &Path, directory: bool, label: &str) -> Result<()> {
        if self.fix {
            if directory {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
            File::open(path.parent().context("residue has no parent")?)?.sync_all()?;
        }
        self.report(if self.fix { "FIXED" } else { "FIXABLE" }, label, path)
    }

    fn challenge(&mut self, path: &Path) -> Result<()> {
        let meta = path.join(".ctf");
        if !self.check(&meta, true, "challenge metadata missing")? {
            return Ok(());
        }
        let lock = meta.join("lock");
        let _guard = if lock.try_exists()? {
            if !self.check(&lock, false, "invalid challenge lock")? {
                return Ok(());
            }
            let file = File::open(&lock)?;
            file.lock()?;
            Some(file)
        } else if self.fix {
            Some(attachments::lock(path)?)
        } else {
            None
        };
        let index = meta.join("challenge.json");
        if !self.check(&index, false, "challenge metadata missing")? {
            return Ok(());
        }
        let data = match attachments::load(path) {
            Ok(data) => data,
            Err(error) => {
                self.report(
                    "ERROR",
                    &format!("malformed challenge metadata: {error}"),
                    &index,
                )?;
                return Ok(());
            }
        };
        self.internal(&meta)?;
        let archive = meta.join("archive");
        let archive_ok = if archive.try_exists()? || !data.attachments.is_empty() {
            self.check(&archive, true, "archive directory missing")?
        } else {
            false
        };
        for attachment in &data.attachments {
            self.check(
                &path.join(&attachment.filename),
                false,
                "working attachment copy missing",
            )?;
            if !archive_ok {
                continue;
            }
            let original = path.join(&attachment.original);
            if !self.check(&original, false, "archived original missing")? {
                continue;
            }
            let mut file = File::open(&original)?;
            if file.metadata()?.len() != attachment.bytes {
                self.report("ERROR", "recorded size mismatch", &original)?;
            }
            let mut hash = Sha256::new();
            let mut buffer = [0; 65536];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
            }
            if format!("{:x}", hash.finalize()) != attachment.sha256 {
                self.report("ERROR", "SHA-256 mismatch", &original)?;
            }
        }
        if archive_ok {
            for original in children(&archive)? {
                if data
                    .attachments
                    .iter()
                    .any(|a| path.join(&a.original) == original)
                {
                    continue;
                }
                if self.check(&original, false, "invalid orphan original")? {
                    self.disposable(&original, false, "orphan archived original")?;
                }
            }
        }
        let stage = meta.join("staging");
        if stage.try_exists()? && self.check(&stage, true, "invalid staging directory")? {
            for residue in children(&stage)? {
                if self.check(&residue, true, "invalid extraction staging entry")? {
                    self.disposable(&residue, true, "stale extraction directory")?;
                }
            }
        }
        for item in children(path)? {
            if item
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with(".tmp")
            {
                self.report(
                    "WARN",
                    "possible abandoned working temporary file; inspect manually",
                    &item,
                )?;
            }
        }
        Ok(())
    }
}

fn children(path: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}
