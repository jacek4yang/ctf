use crate::workspace::validate_name;
use anyhow::{Context, Result, bail, ensure};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

fn supported(path: &Path) -> bool {
    let name = path.to_string_lossy().to_lowercase();
    [
        ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".gz", ".bz2", ".xz", ".txz", ".7z",
    ]
    .iter()
    .any(|ext| name.ends_with(ext))
}

pub fn select(challenge: &Path, input: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(input) = input {
        return Ok(input);
    }
    let archives: Vec<_> = fs::read_dir(challenge)?
        .map(|entry| {
            let entry = entry?;
            Ok((entry.file_type()?.is_file(), entry.path()))
        })
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|(file, path)| *file && supported(path))
        .map(|(_, path)| path)
        .collect();
    match archives.as_slice() {
        [path] => Ok(path.clone()),
        [] => bail!("no supported archive found; provide ZIP, TAR, GZIP, BZIP2, XZ, or 7z input"),
        _ => bail!("multiple archives found; specify one with `ctf extract FILE`"),
    }
}

fn safe_path(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.starts_with('/')
            && !name.contains('\\')
            && !(name.as_bytes().get(1) == Some(&b':') && name.as_bytes()[0].is_ascii_alphabetic()),
        "unsafe archive path: {name:?}"
    );
    let mut result = PathBuf::new();
    for part in name.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        validate_name(part).with_context(|| format!("unsafe archive path: {name:?}"))?;
        result.push(part);
    }
    ensure!(!result.as_os_str().is_empty(), "empty archive path");
    Ok(result)
}

struct Unpacker<'a> {
    root: &'a Path,
    bytes: u64,
    entries: usize,
    files: usize,
}

impl Unpacker<'_> {
    fn entry(&mut self, name: &str, directory: bool, reader: impl Read) -> Result<()> {
        self.entries += 1;
        ensure!(
            self.entries <= MAX_ENTRIES,
            "archive exceeds {MAX_ENTRIES} entries"
        );
        // A conventional tar root directory does not create a filesystem entry.
        if directory && matches!(name, "." | "./") {
            return Ok(());
        }
        let relative = safe_path(name)?;
        let output = self.root.join(relative);
        if directory {
            fs::create_dir_all(output)?;
            return Ok(());
        }
        fs::create_dir_all(output.parent().context("archive entry has no parent")?)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .with_context(|| format!("duplicate or conflicting archive entry: {name:?}"))?;
        let copied = std::io::copy(&mut reader.take(MAX_BYTES - self.bytes + 1), &mut file)?;
        self.bytes += copied;
        ensure!(
            self.bytes <= MAX_BYTES,
            "archive exceeds 1 GiB expanded size limit"
        );
        self.files += 1;
        Ok(())
    }

    fn tar(&mut self, reader: impl Read) -> Result<()> {
        let mut archive = tar::Archive::new(reader);
        for entry in archive.entries()? {
            let entry = entry?;
            let kind = entry.header().entry_type();
            ensure!(
                kind.is_file() || kind.is_dir(),
                "archive links and special files are not allowed"
            );
            let name = std::str::from_utf8(&entry.path_bytes())
                .context("archive path is not UTF-8")?
                .to_owned();
            self.entry(&name, kind.is_dir(), entry)?;
        }
        // TAR ends before its compression stream. Consume the trailer too so a
        // truncated/corrupt compressed archive cannot appear successful.
        let trailing = std::io::copy(
            &mut archive.into_inner().take(MAX_BYTES - self.bytes + 1),
            &mut std::io::sink(),
        )?;
        ensure!(
            self.bytes + trailing <= MAX_BYTES,
            "archive exceeds 1 GiB expanded size limit"
        );
        Ok(())
    }
}

/// Extract into an isolated new directory. Failure drops the whole staging tree;
/// existing challenge files and metadata are never extraction destinations.
pub fn extract(input: &Path, challenge: &Path) -> Result<(usize, PathBuf)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(input)
        .with_context(|| format!("open archive {}", input.display()))?;
    ensure!(file.metadata()?.is_file(), "archive must be a regular file");
    ensure!(
        file.metadata()?.len() <= MAX_BYTES,
        "archive input exceeds 1 GiB limit"
    );
    // Only unfinished extraction lives in reserved metadata storage. Completed
    // extracted-* directories remain user data and are never doctor cleanup targets.
    crate::workspace::directory(&challenge.join(".ctf"))?;
    let _lock = crate::attachments::lock(challenge)?;
    let staging = challenge.join(".ctf/staging");
    crate::workspace::directory(&staging)?;
    let stage = tempfile::Builder::new()
        .prefix("extracted-")
        .tempdir_in(&staging)?;
    let mut unpacker = Unpacker {
        root: stage.path(),
        bytes: 0,
        entries: 0,
        files: 0,
    };
    let name = input
        .file_name()
        .context("archive has no filename")?
        .to_string_lossy();
    let lower = name.to_lowercase();
    if lower.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(file)?;
        ensure!(
            zip.len() <= MAX_ENTRIES,
            "archive exceeds {MAX_ENTRIES} entries"
        );
        for i in 0..zip.len() {
            let entry = zip.by_index(i)?;
            if let Some(mode) = entry.unix_mode() {
                let kind = mode & 0o170000;
                ensure!(
                    matches!(kind, 0 | 0o040000 | 0o100000),
                    "archive links and special files are not allowed"
                );
            }
            let name = entry.name().to_owned();
            unpacker.entry(&name, entry.is_dir(), entry)?;
        }
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        unpacker.tar(flate2::read::MultiGzDecoder::new(file))?;
    } else if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") {
        unpacker.tar(bzip2::read::MultiBzDecoder::new(file))?;
    } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
        unpacker.tar(lzma_rust2::XzReader::new_mem_limit(file, true, 256 * 1024))?;
    } else if lower.ends_with(".xz") {
        unpacker.entry(
            &name[..name.len() - 3],
            false,
            lzma_rust2::XzReader::new_mem_limit(file, true, 256 * 1024),
        )?;
    } else if lower.ends_with(".7z") {
        unpacker.files = sevenz_process(input, stage.path())?;
    } else if lower.ends_with(".tar") {
        unpacker.tar(file)?;
    } else if lower.ends_with(".gz") {
        unpacker.entry(
            &name[..name.len() - 3],
            false,
            flate2::read::MultiGzDecoder::new(file),
        )?;
    } else if lower.ends_with(".bz2") {
        unpacker.entry(
            &name[..name.len() - 4],
            false,
            bzip2::read::MultiBzDecoder::new(file),
        )?;
    } else {
        bail!(
            "unsupported archive format; supported: zip, tar, tar.gz/tgz, tar.bz2/tbz2, tar.xz/txz, gz, bz2, xz, 7z"
        );
    }
    let count = unpacker.files;
    sync_tree(stage.path())?;
    let output = challenge.join(
        stage
            .path()
            .file_name()
            .context("staging directory has no name")?,
    );
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        stage.path(),
        rustix::fs::CWD,
        &output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(challenge)?.sync_all()?;
    File::open(staging)?.sync_all()?;
    Ok((count, output))
}

fn sync_tree(root: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut directories = vec![root.to_path_buf()];
    let mut cursor = 0;
    let mut entries = 0;
    let mut bytes = 0u64;
    while cursor < directories.len() {
        for entry in fs::read_dir(&directories[cursor])? {
            let path = entry?.path();
            let meta = fs::symlink_metadata(&path)?;
            entries += 1;
            ensure!(
                entries <= MAX_ENTRIES,
                "extracted tree exceeds {MAX_ENTRIES} entries including implicit directories"
            );
            if meta.is_dir() && !meta.file_type().is_symlink() {
                directories.push(path);
            } else {
                ensure!(
                    meta.is_file() && meta.nlink() == 1,
                    "unsafe extracted link or special file"
                );
                bytes = bytes
                    .checked_add(meta.len())
                    .context("expanded size overflow")?;
                ensure!(
                    bytes <= MAX_BYTES,
                    "archive exceeds 1 GiB expanded size limit"
                );
                crate::workspace::regular_file(&path)?.sync_all()?;
            }
        }
        cursor += 1;
    }
    for path in directories.into_iter().rev() {
        File::open(path)?.sync_all()?;
    }
    Ok(())
}

// 7z headers can allocate decoder dictionaries before exposing entries. Isolate
// that parser in this same binary with OS limits; even an allocator abort cannot
// bypass parent-owned staging cleanup. No shell or external archive executable.
fn sevenz_process(input: &Path, stage: &Path) -> Result<usize> {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut child = Command::new(std::env::current_exe()?)
        .arg("__unpack7z")
        .arg(input.canonicalize()?)
        .arg(stage.canonicalize()?)
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("wait for 7z decoder");
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("7z decoding exceeded 120 seconds; staging removed");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    ensure!(
        status.success(),
        "7z decoding failed (corrupt/encrypted/unsupported input or resource limit); staging removed"
    );
    let mut output = String::new();
    child
        .stdout
        .take()
        .context("missing decoder result")?
        .take(64)
        .read_to_string(&mut output)?;
    output.trim().parse().context("invalid internal 7z result")
}

pub fn unpack_7z(input: &Path, stage: &Path, parent: u32) -> Result<usize> {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))?;
    ensure!(
        rustix::process::getppid().is_some_and(|pid| pid.as_raw_nonzero().get() as u32 == parent),
        "7z parent exited before decoder startup"
    );
    for (resource, bound) in [
        (Resource::As, 1024 * 1024 * 1024),
        (Resource::Cpu, 120),
        (Resource::Core, 0),
    ] {
        let old = getrlimit(resource);
        setrlimit(
            resource,
            Rlimit {
                current: Some(old.current.unwrap_or(bound).min(bound)),
                maximum: old.maximum,
            },
        )?;
    }
    crate::workspace::reject_link(stage)?;
    ensure!(
        stage.is_dir() && fs::read_dir(stage)?.next().is_none(),
        "7z requires empty isolated staging"
    );
    let mut archive =
        sevenz_rust2::ArchiveReader::new(File::open(input)?, sevenz_rust2::Password::empty())
            .context("read 7z header; encrypted archives are not supported")?;
    archive.set_thread_count(1);
    ensure!(
        archive.archive().files.len() <= MAX_ENTRIES,
        "archive exceeds {MAX_ENTRIES} entries"
    );
    let mut total = 0u64;
    for entry in &archive.archive().files {
        safe_path(&entry.name)?;
        ensure!(!entry.is_anti_item, "7z anti-items are not supported");
        if entry.has_windows_attributes {
            let kind = (entry.windows_attributes >> 16) & 0o170000;
            ensure!(
                matches!(kind, 0 | 0o100000 | 0o040000) && entry.windows_attributes & 0x400 == 0,
                "archive links and special files are not allowed"
            );
        }
        total = total.checked_add(entry.size).context("7z size overflow")?;
        ensure!(
            total <= MAX_BYTES,
            "archive exceeds 1 GiB expanded size limit"
        );
    }
    for block in &archive.archive().blocks {
        for coder in &block.coders {
            ensure!(
                coder.encoder_method_id() != [0x06, 0xf1, 0x07, 0x01],
                "encrypted 7z archives are not supported"
            );
        }
    }
    let mut unpacker = Unpacker {
        root: stage,
        bytes: 0,
        entries: 0,
        files: 0,
    };
    archive.for_each_entries(|entry, reader| {
        unpacker
            .entry(&entry.name, entry.is_directory, reader)
            .map_err(|error| sevenz_rust2::Error::Other(error.to_string().into()))?;
        Ok(true)
    })?;
    Ok(unpacker.files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn expanded_size_and_entry_limits_are_enforced_before_commit() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut unpacker = Unpacker {
            root: temp.path(),
            bytes: MAX_BYTES - 1,
            entries: 0,
            files: 0,
        };
        assert!(unpacker.entry("too-large", false, &b"xx"[..]).is_err());
        let mut unpacker = Unpacker {
            root: temp.path(),
            bytes: 0,
            entries: MAX_ENTRIES,
            files: 0,
        };
        assert!(unpacker.entry("too-many", false, std::io::empty()).is_err());
        assert!(!temp.path().join("too-many").exists());
        Ok(())
    }
    #[test]
    fn traversal_paths() {
        for name in [
            "../escape",
            "/absolute",
            "C:/escape",
            "C:escape",
            "a/../../bad",
            "a\\..\\bad",
            ".ctf/index.json",
            "a/.ctf/target",
        ] {
            assert!(safe_path(name).is_err(), "accepted {name}");
        }
        assert_eq!(
            safe_path("./目录/附件.txt").unwrap(),
            PathBuf::from("目录/附件.txt")
        );
    }
    #[test]
    fn zip_rejection_is_transactional() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let zip_path = temp.path().join("bad.zip");
        let mut zip = zip::ZipWriter::new(File::create(&zip_path)?);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("good.txt", options)?;
        zip.write_all(b"good")?;
        zip.start_file("../escape.txt", options)?;
        zip.write_all(b"bad")?;
        zip.finish()?;
        assert!(extract(&zip_path, temp.path()).is_err());
        assert_eq!(fs::read_dir(temp.path())?.count(), 2); // input and reserved .ctf
        assert_eq!(fs::read_dir(temp.path().join(".ctf/staging"))?.count(), 0);
        Ok(())
    }
    #[test]
    fn tar_links_rejected_and_zip_unicode_preserved() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let tar_path = temp.path().join("links.tar");
        let mut tar = tar::Builder::new(File::create(&tar_path)?);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../outside")?;
        tar.append_data(&mut header, "link", std::io::empty())?;
        tar.finish()?;
        assert!(extract(&tar_path, temp.path()).is_err());
        let zip_path = temp.path().join("good.zip");
        let mut zip = zip::ZipWriter::new(File::create(&zip_path)?);
        zip.start_file("目录/签到.txt", zip::write::SimpleFileOptions::default())?;
        zip.write_all(b"hello")?;
        zip.finish()?;
        let (count, output) = extract(&zip_path, temp.path())?;
        assert_eq!(count, 1);
        assert_eq!(fs::read(output.join("目录/签到.txt"))?, b"hello");
        Ok(())
    }

    #[test]
    fn compressed_tar_checks_trailer_and_leaves_nested_archives() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o644);
        tar.append_data(&mut header, "nested.zip", &b"nested"[..])?;
        let tar_bytes = tar.into_inner()?;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&tar_bytes)?;
        let mut bytes = gzip.finish()?;
        let input = temp.path().join("test.tar.gz");
        fs::write(&input, &bytes)?;
        let (count, output) = extract(&input, temp.path())?;
        assert_eq!(count, 1);
        assert_eq!(fs::read(output.join("nested.zip"))?, b"nested");
        let crc = bytes.len() - 8;
        bytes[crc] ^= 0xff;
        fs::write(&input, bytes)?;
        assert!(extract(&input, temp.path()).is_err());
        assert_eq!(fs::read_dir(temp.path())?.count(), 3);
        Ok(())
    }

    #[test]
    fn tar_traversal_and_duplicate_files_are_rejected() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("bad.tar");
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.as_mut_bytes()[..13].copy_from_slice(b"../escape.txt");
        header.set_cksum();
        let mut tar = tar::Builder::new(File::create(&input)?);
        tar.append(&header, &b"x"[..])?;
        tar.finish()?;
        drop(tar);
        assert!(extract(&input, temp.path()).is_err());
        let mut unpacker = Unpacker {
            root: temp.path(),
            bytes: 0,
            entries: 0,
            files: 0,
        };
        unpacker.entry("duplicate", false, &b"first"[..])?;
        assert!(unpacker.entry("duplicate", false, &b"second"[..]).is_err());
        assert_eq!(fs::read(temp.path().join("duplicate"))?, b"first");
        unpacker.bytes = MAX_BYTES;
        assert!(unpacker.entry("too-large", false, &b"x"[..]).is_err());
        Ok(())
    }
}
