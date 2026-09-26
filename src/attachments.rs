use crate::workspace::{atomic_json, directory, reject_link, user_home, validate_name};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_ATTACHMENT: u64 = 1024 * 1024 * 1024;

pub fn lock(challenge: &Path) -> Result<File> {
    reject_link(&challenge.join(".ctf"))?;
    let path = challenge.join(".ctf/lock");
    reject_link(&path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock().context("lock challenge")?;
    Ok(file)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub filename: String,
    pub original: String,
    pub source: String,
    pub timestamp_unix: u64,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub version: u32,
    pub target: Option<String>,
    pub attachments: Vec<Attachment>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            version: 1,
            target: None,
            attachments: Vec::new(),
        }
    }
}

pub fn load(challenge: &Path) -> Result<Metadata> {
    reject_link(&challenge.join(".ctf"))?;
    let path = challenge.join(".ctf/challenge.json");
    reject_link(&path)?;
    let meta: Metadata = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("invalid challenge metadata")?;
    ensure!(meta.version == 1, "unsupported challenge metadata version");
    let mut filenames = std::collections::HashSet::new();
    let mut originals = std::collections::HashSet::new();
    for attachment in &meta.attachments {
        validate_name(&attachment.filename)?;
        ensure!(
            filenames.insert(&attachment.filename) && originals.insert(&attachment.original),
            "duplicate attachment metadata"
        );
        let original = attachment
            .original
            .strip_prefix(".ctf/archive/")
            .context("invalid original attachment path")?;
        validate_name(original)?;
        ensure!(
            attachment.sha256.len() == 64
                && attachment.sha256.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid attachment hash"
        );
    }
    Ok(meta)
}

pub fn save(challenge: &Path, meta: &Metadata) -> Result<()> {
    atomic_json(&challenge.join(".ctf/challenge.json"), meta)
}

pub fn import(challenge: &Path, source: &str) -> Result<Attachment> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .build();
        let agent: ureq::Agent = config.into();
        let mut response = agent.get(source).call().context("download attachment")?;
        let name = url_filename(source);
        store(challenge, source, &name, response.body_mut().as_reader())
    } else {
        let path = if let Some(rest) = source.strip_prefix("~/") {
            user_home()?.join(rest)
        } else {
            source.into()
        };
        let file =
            File::open(&path).with_context(|| format!("open attachment {}", path.display()))?;
        ensure!(
            file.metadata()?.is_file(),
            "attachment source must be a regular file"
        );
        let filename = path
            .file_name()
            .context("source has no filename")?
            .to_string_lossy();
        store(challenge, source, &safe_filename(&filename), file)
    }
}

fn safe_filename(name: &str) -> String {
    let name: String = name
        .chars()
        .map(|c| if c.is_control() || c == '/' { '_' } else { c })
        .collect();
    if validate_name(&name).is_ok() {
        name
    } else {
        "attachment.bin".into()
    }
}

fn url_filename(url: &str) -> String {
    let raw = url
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let mut bytes = Vec::new();
    let raw = raw.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%'
            && i + 2 < raw.len()
            && let (Some(a), Some(b)) = (
                (raw[i + 1] as char).to_digit(16),
                (raw[i + 2] as char).to_digit(16),
            )
        {
            bytes.push((a * 16 + b) as u8);
            i += 3;
            continue;
        }
        bytes.push(raw[i]);
        i += 1;
    }
    safe_filename(&String::from_utf8_lossy(&bytes))
}

pub fn store(challenge: &Path, source: &str, name: &str, reader: impl Read) -> Result<Attachment> {
    validate_name(name)?;
    let mut meta = load(challenge)?;
    let original_dir = challenge.join(".ctf/archive");
    directory(&original_dir)?;
    let mut original = tempfile::NamedTempFile::new_in(&original_dir)?;
    let bytes = std::io::copy(&mut reader.take(MAX_ATTACHMENT + 1), &mut original)?;
    ensure!(bytes <= MAX_ATTACHMENT, "attachment exceeds 1 GiB limit");
    original.as_file().sync_all()?;
    original.rewind()?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let len = original.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        hash.update(&buffer[..len]);
    }
    let sha256 = format!("{:x}", hash.finalize());
    original.rewind()?;
    let mut working = tempfile::NamedTempFile::new_in(challenge)?;
    std::io::copy(&mut original, &mut working)?;
    working.as_file().sync_all()?;
    let stem = Path::new(name)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy();
    let ext = Path::new(name)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let mut sequence = 1u64;
    let filename = loop {
        let candidate = if sequence == 1 {
            name.into()
        } else {
            format!("{stem}-{sequence}{ext}")
        };
        // Recorded names stay reserved even if a user deletes the working copy.
        if meta.attachments.iter().any(|a| a.filename == candidate) {
            sequence = sequence
                .checked_add(1)
                .context("filename space exhausted")?;
            continue;
        }
        match working.persist_noclobber(challenge.join(&candidate)) {
            Ok(_) => break candidate,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                working = error.file;
                sequence = sequence
                    .checked_add(1)
                    .context("filename space exhausted")?;
            }
            Err(error) => return Err(error.into()),
        }
    };
    let original_name = original
        .path()
        .file_name()
        .context("temporary original has no name")?
        .to_string_lossy()
        .into_owned();
    let attachment = Attachment {
        filename: filename.clone(),
        original: format!(".ctf/archive/{original_name}"),
        source: source.into(),
        timestamp_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        sha256,
        bytes,
    };
    // Keep the original before recording it. A failed metadata commit can leave an
    // unreferenced original, but must never leave metadata pointing at a lost original.
    let (file, original_path) = original.keep()?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)?;
    file.sync_all()?;
    File::open(&original_dir)?.sync_all()?;
    File::open(challenge)?.sync_all()?;
    meta.attachments.push(attachment);
    if let Err(error) = save(challenge, &meta) {
        let _ = fs::remove_file(challenge.join(&filename));
        bail!(
            "{error:#}; original preserved at {}",
            original_path.display()
        );
    }
    meta.attachments
        .pop()
        .context("attachment metadata missing")
}

pub fn clipboard() -> Result<String> {
    let candidates: &[(&str, &[&str])] = &[
        ("wl-paste", &["--no-newline", "--type", "text"]),
        ("xclip", &["-selection", "clipboard", "-out"]),
        ("xsel", &["--clipboard", "--output"]),
    ];
    for (program, args) in candidates {
        if let Ok(output) = Command::new(program).args(*args).output()
            && output.status.success()
        {
            return String::from_utf8(output.stdout).context("clipboard text is not UTF-8");
        }
    }
    bail!("could not read clipboard text; install wl-clipboard (Wayland), xclip, or xsel (X11)")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collisions_and_originals() -> Result<()> {
        let temp = tempfile::tempdir()?;
        directory(&temp.path().join(".ctf"))?;
        save(temp.path(), &Metadata::default())?;
        let first = store(temp.path(), "test", "附件.txt", &b"original"[..])?;
        let second = store(temp.path(), "test", "附件.txt", &b"second"[..])?;
        assert_eq!(second.filename, "附件-2.txt");
        fs::write(temp.path().join(&first.filename), "modified")?;
        assert_eq!(fs::read(temp.path().join(&first.original))?, b"original");
        assert_eq!(load(temp.path())?.attachments.len(), 2);
        assert_eq!(first.sha256, format!("{:x}", Sha256::digest(b"original")));
        assert!(
            fs::metadata(temp.path().join(&first.original))?
                .permissions()
                .readonly()
        );
        assert_eq!(
            url_filename("https://example.test/%E7%AD%BE%E5%88%B0.zip?q=x"),
            "签到.zip"
        );
        Ok(())
    }

    #[test]
    fn clipboard_text_is_stored_verbatim_and_failed_reads_leave_no_records() -> Result<()> {
        let temp = tempfile::tempdir()?;
        directory(&temp.path().join(".ctf"))?;
        save(temp.path(), &Metadata::default())?;
        let text = "中文\r\naGVsbG8=\n\\x41\n\0";
        let attachment = store(temp.path(), "clipboard", "clipboard.txt", text.as_bytes())?;
        assert_eq!(
            fs::read(temp.path().join(attachment.filename))?,
            text.as_bytes()
        );
        struct FailedReader;
        impl Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("simulated interrupted download"))
            }
        }
        assert!(store(temp.path(), "test", "bad.bin", FailedReader).is_err());
        assert!(!temp.path().join("bad.bin").exists());
        assert_eq!(load(temp.path())?.attachments.len(), 1);
        assert_eq!(fs::read_dir(temp.path().join(".ctf/archive"))?.count(), 1);
        Ok(())
    }
}
