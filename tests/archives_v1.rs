use assert_cmd::Command;
use predicates::prelude::*;
use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
};

fn ctf(root: &Path) -> Command {
    let mut c = Command::new(assert_cmd::cargo::cargo_bin!("ctf"));
    c.env("CTF_HOME", root)
        .env_remove("CTF_CD_FILE")
        .current_dir(root.join("contest/challenge"));
    c
}
fn setup() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    for args in [vec!["contest", "new", "contest"], vec!["new", "challenge"]] {
        ctf(t.path())
            .current_dir(t.path())
            .args(args)
            .assert()
            .success();
    }
    t
}
fn extracted(root: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(root.join("contest/challenge"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("extracted-")
        })
        .collect()
}
fn xz(bytes: &[u8]) -> Vec<u8> {
    let mut writer =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap()
}
fn sevenz(path: &Path, name: &str, attributes: Option<u32>, encrypted: Option<bool>) {
    let mut writer = sevenz_rust2::ArchiveWriter::create(path).unwrap();
    if let Some(header) = encrypted {
        writer.set_content_methods(vec![
            sevenz_rust2::encoder_options::AesEncoderOptions::new("secret".into()).into(),
            sevenz_rust2::EncoderMethod::LZMA2.into(),
        ]);
        writer.set_encrypt_header(header);
    }
    let mut entry = sevenz_rust2::ArchiveEntry::new_file(name);
    if let Some(attributes) = attributes {
        entry.has_windows_attributes = true;
        entry.windows_attributes = attributes;
    }
    writer
        .push_archive_entry(entry, Some(Cursor::new("hello 中文\n".as_bytes())))
        .unwrap();
    writer.finish().unwrap();
}

#[test]
fn xz_tar_xz_txz_and_sevenz_preserve_bytes() {
    for extension in ["xz", "tar.xz", "txz", "7z"] {
        let temp = setup();
        let root = temp.path();
        let input = root.join(format!("hello.{extension}"));
        let content = "hello 中文\n";
        if extension == "7z" {
            sevenz(&input, "hello", None, None);
        } else if extension == "xz" {
            fs::write(&input, xz(content.as_bytes())).unwrap();
        } else {
            let mut tar = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "hello", content.as_bytes())
                .unwrap();
            fs::write(&input, xz(&tar.into_inner().unwrap())).unwrap();
        }
        ctf(root).arg("extract").arg(&input).assert().success();
        let output = extracted(root);
        assert_eq!(output.len(), 1);
        assert_eq!(
            fs::read(output[0].join("hello")).unwrap(),
            content.as_bytes()
        );
        ctf(root).arg("doctor").assert().success();
    }
}

#[test]
fn sevenz_rejects_traversal_links_encryption_and_cleans_staging() {
    for (name, attrs, encrypted) in [
        ("../escape", None, None),
        ("/absolute", None, None),
        (".ctf/evil", None, None),
        ("link", Some(0o120777 << 16 | 0x8000), None),
        ("device", Some(0o020600 << 16 | 0x8000), None),
        ("reparse", Some(0x400), None),
        ("secret", None, Some(false)),
        ("secret", None, Some(true)),
    ] {
        let temp = setup();
        let root = temp.path();
        let input = root.join("bad.7z");
        sevenz(&input, name, attrs, encrypted);
        let mut assertion = ctf(root)
            .arg("extract")
            .arg(input)
            .timeout(std::time::Duration::from_secs(10))
            .assert()
            .failure();
        if encrypted.is_some() {
            assertion = assertion.stderr(predicate::str::contains("encrypted"));
        }
        drop(assertion);
        assert!(extracted(root).is_empty());
        assert_eq!(
            fs::read_dir(root.join("contest/challenge/.ctf/staging"))
                .unwrap()
                .count(),
            0
        );
        assert!(!root.join("escape").exists());
    }
}

#[test]
fn corrupt_and_truncated_archives_leave_no_output() {
    for extension in ["xz", "tar.xz", "txz", "7z"] {
        let temp = setup();
        let root = temp.path();
        let input = root.join(format!("bad.{extension}"));
        fs::write(&input, b"invalid archive").unwrap();
        ctf(root).arg("extract").arg(&input).assert().failure();
        assert!(extracted(root).is_empty());
        if extension != "7z" {
            let mut encoded = xz(b"data");
            encoded.truncate(encoded.len() - 8);
            fs::write(&input, encoded).unwrap();
            ctf(root).arg("extract").arg(&input).assert().failure();
            assert!(extracted(root).is_empty());
        }
    }
}

#[test]
fn xz_tar_link_and_traversal_are_rejected() {
    for link in [true, false] {
        let temp = setup();
        let root = temp.path();
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        if link {
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("../outside").unwrap();
        }
        header.set_cksum();
        tar.append_data(&mut header, "entry", std::io::empty())
            .unwrap();
        let mut bytes = tar.into_inner().unwrap();
        if !link {
            bytes[..9].copy_from_slice(b"../escape");
            bytes[148..156].fill(b' ');
            let sum: u32 = bytes[..512].iter().map(|b| *b as u32).sum();
            bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        }
        let input = root.join("bad.txz");
        fs::write(&input, xz(&bytes)).unwrap();
        ctf(root).arg("extract").arg(input).assert().failure();
        assert!(extracted(root).is_empty());
    }
}

#[test]
fn sevenz_entry_count_and_archive_input_size_are_bounded() {
    let temp = setup();
    let root = temp.path();
    let input = root.join("many.7z");
    let mut writer = sevenz_rust2::ArchiveWriter::create(&input).unwrap();
    for n in 0..10_001 {
        writer
            .push_archive_entry(
                sevenz_rust2::ArchiveEntry::new_directory(&format!("d{n}")),
                None::<Cursor<&[u8]>>,
            )
            .unwrap();
    }
    writer.finish().unwrap();
    ctf(root)
        .arg("extract")
        .arg(&input)
        .assert()
        .failure()
        .stderr(predicate::str::contains("10000 entries"));
    assert!(extracted(root).is_empty());
    let sparse = root.join("large.xz");
    fs::File::create(&sparse)
        .unwrap()
        .set_len(1024 * 1024 * 1024 + 1)
        .unwrap();
    ctf(root)
        .arg("extract")
        .arg(sparse)
        .assert()
        .failure()
        .stderr(predicate::str::contains("input exceeds"));
    assert!(extracted(root).is_empty());
}
