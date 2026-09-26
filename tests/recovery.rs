use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::{fs, path::Path};

fn ctf(root: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("ctf"));
    cmd.env("CTF_HOME", root)
        .env_remove("CTF_CD_FILE")
        .current_dir(root)
        .timeout(std::time::Duration::from_secs(3));
    cmd
}
fn setup() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    ctf(temp.path())
        .args(["contest", "new", "contest"])
        .assert()
        .success();
    ctf(temp.path())
        .args(["new", "challenge"])
        .assert()
        .success();
    temp
}

#[test]
fn missing_index_is_never_reset_and_metadata_special_files_fail_closed() {
    let temp = setup();
    let root = temp.path();
    let index = root.join(".ctf/index.json");
    fs::remove_file(&index).unwrap();
    ctf(root)
        .args(["contest", "new", "do-not-create"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("IDs will not be reset"));
    assert!(!index.exists());
    assert!(!root.join("do-not-create").exists());
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &index,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    ctf(root).arg("list").assert().failure();
    ctf(root)
        .arg("doctor")
        .assert()
        .failure()
        .stdout(predicate::str::contains("unexpected file type"));
    fs::remove_file(&index).unwrap();
    fs::rename(root.join(".ctf"), root.join("saved-meta")).unwrap();
    ctf(root)
        .args(["contest", "new", "still-no-reset"])
        .assert()
        .failure();
    assert!(!root.join(".ctf").exists());
}

#[test]
fn completed_import_journals_are_fixable_but_uncommitted_ones_preserve_evidence() {
    let temp = setup();
    let root = temp.path();
    let challenge = root.join("contest/challenge");
    let source = root.join("source.txt");
    fs::write(&source, b"original").unwrap();
    ctf(root)
        .current_dir(&challenge)
        .arg("import")
        .arg(source)
        .assert()
        .success();
    let index = challenge.join(".ctf/challenge.json");
    let mut meta: Value = serde_json::from_slice(&fs::read(&index).unwrap()).unwrap();
    let journal = challenge.join(".ctf/import.json");
    let record = meta["attachments"][0].clone();
    fs::write(&journal, serde_json::to_vec(&record).unwrap()).unwrap();
    ctf(root)
        .current_dir(&challenge)
        .args(["target", "blocked"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("doctor"));
    ctf(root).args(["doctor", "--fix"]).assert().success();
    assert!(!journal.exists());
    meta["attachments"] = json!([]);
    fs::write(&index, serde_json::to_vec(&meta).unwrap()).unwrap();
    fs::write(&journal, serde_json::to_vec(&record).unwrap()).unwrap();
    let original = challenge.join(record["original"].as_str().unwrap());
    ctf(root)
        .args(["doctor", "--fix"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("interrupted attachment import"));
    assert!(journal.exists());
    assert_eq!(fs::read(original).unwrap(), b"original");
    assert_eq!(fs::read(challenge.join("source.txt")).unwrap(), b"original");
}

#[test]
fn shared_metadata_hardlinks_are_rejected_and_numeric_overflow_never_becomes_a_name() {
    let temp = setup();
    let root = temp.path();
    let index = root.join(".ctf/index.json");
    fs::hard_link(&index, root.join("linked-index")).unwrap();
    ctf(root).arg("list").assert().failure();
    ctf(root)
        .arg("doctor")
        .assert()
        .failure()
        .stdout(predicate::str::contains("hardlink"));
    fs::remove_file(root.join("linked-index")).unwrap();
    let huge = "99999999999999999999999999999";
    ctf(root).args(["new", huge]).assert().success();
    ctf(root)
        .args(["go", huge])
        .assert()
        .failure()
        .stderr(predicate::str::contains("out of range"));
}

#[test]
fn create_journal_residue_is_reported_without_reassigning_ids() {
    let temp = setup();
    let root = temp.path();
    let journal = root.join(".ctf/pending.json");
    fs::write(
        &journal,
        serde_json::to_vec(
            &json!({"operation":"create", "contest":1,"id":2,"old":null,"new":"partial"}),
        )
        .unwrap(),
    )
    .unwrap();
    fs::create_dir(root.join("contest/partial")).unwrap();
    ctf(root).args(["doctor", "--fix"]).assert().failure();
    assert!(journal.exists());
    fs::remove_dir(root.join("contest/partial")).unwrap();
    ctf(root).args(["doctor", "--fix"]).assert().success();
    assert!(!journal.exists());
}

#[test]
fn fifo_sources_are_rejected_without_waiting_for_a_writer() {
    let temp = setup();
    let root = temp.path();
    let fifo = root.join("pipe.tar");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    for command in ["import", "extract"] {
        ctf(root)
            .current_dir(root.join("contest/challenge"))
            .arg(command)
            .arg(&fifo)
            .assert()
            .failure()
            .stderr(predicate::str::contains("regular file"));
    }
}
