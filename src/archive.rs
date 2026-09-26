use crate::workspace::validate_name;
use anyhow::{Context, Result, bail, ensure};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

fn supported(path: &Path) -> bool {
    let name = path.to_string_lossy().to_lowercase();
    [
        ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".gz", ".bz2",
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
        [] => bail!(
            "no supported archive found; provide a .zip, .tar, .tar.gz, .tar.bz2, .gz, or .bz2 file"
        ),
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
    let file = File::open(input).with_context(|| format!("open archive {}", input.display()))?;
    ensure!(file.metadata()?.is_file(), "archive must be a regular file");
    let stage = tempfile::Builder::new()
        .prefix("extracted-")
        .tempdir_in(challenge)?;
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
        bail!("unsupported archive format; supported: zip, tar, tar.gz/tgz, tar.bz2/tbz2, gz, bz2");
    }
    let count = unpacker.files;
    Ok((count, stage.keep()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
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
        assert_eq!(fs::read_dir(temp.path())?.count(), 2);
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
