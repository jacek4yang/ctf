use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::symlink, path::Path};

fn ctf(root: &Path) -> Command {
    let mut c = Command::new(assert_cmd::cargo::cargo_bin!("ctf"));
    c.env("CTF_HOME", root)
        .env_remove("CTF_CD_FILE")
        .current_dir(root);
    c
}
fn setup() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    ctf(temp.path())
        .args(["contest", "new", "赛事"])
        .assert()
        .success();
    temp
}

#[test]
fn rename_preserves_ids_metadata_and_selection() {
    let temp = setup();
    let root = temp.path();
    ctf(root).args(["new", "题目"]).assert().success();
    let before = fs::read(root.join("赛事/题目/.ctf/challenge.json")).unwrap();
    for name in ["spaces 中文 [x]", "quote'\"$()$\\", "-leading"] {
        ctf(root)
            .args(["rename", "--", "1", name])
            .assert()
            .success();
        ctf(root)
            .args(["go", "1"])
            .assert()
            .success()
            .stdout(predicate::str::contains(name));
        assert_eq!(
            fs::read(root.join("赛事").join(name).join(".ctf/challenge.json")).unwrap(),
            before
        );
    }
    ctf(root)
        .args(["contest", "rename", "1", "renamed 中文"])
        .assert()
        .success();
    ctf(root)
        .args(["list"])
        .assert()
        .success()
        .stdout("1\t-leading\n");
    ctf(root)
        .args(["use", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("renamed 中文"));
    ctf(root).arg("doctor").assert().success();
}

#[test]
fn rename_rejects_collisions_invalid_names_and_symlinks() {
    let temp = setup();
    let root = temp.path();
    ctf(root).args(["new", "a"]).assert().success();
    fs::create_dir(root.join("赛事/existing")).unwrap();
    for name in ["existing", ".ctf", "../outside", "a/b", "a", ""] {
        ctf(root).args(["rename", "1", name]).assert().failure();
        assert!(root.join("赛事/a").is_dir());
        assert!(!root.join(".ctf/pending.json").exists());
    }
    fs::rename(root.join("赛事/a"), root.join("赛事/real")).unwrap();
    symlink("real", root.join("赛事/a")).unwrap();
    ctf(root).args(["rename", "1", "new"]).assert().failure();
}

#[test]
fn adoption_is_explicit_local_and_never_overwrites_metadata() {
    let temp = setup();
    let root = temp.path();
    fs::create_dir(root.join("外部")).unwrap();
    fs::write(root.join("外部/preserve"), b"user data").unwrap();
    ctf(root)
        .args(["contest", "adopt", "外部"])
        .assert()
        .success()
        .stdout("2\t外部\n");
    ctf(root).args(["use", "2"]).assert().success();
    fs::create_dir(root.join("外部/旧题")).unwrap();
    fs::write(root.join("外部/旧题/user.txt"), b"literal bytes").unwrap();
    ctf(root)
        .args(["adopt", "旧题"])
        .assert()
        .success()
        .stdout("1\t旧题\n");
    ctf(root).args(["adopt", "旧题"]).assert().failure();
    fs::create_dir_all(root.join("外部/incompatible/.ctf")).unwrap();
    fs::write(
        root.join("外部/incompatible/.ctf/challenge.json"),
        b"broken",
    )
    .unwrap();
    ctf(root).args(["adopt", "incompatible"]).assert().failure();
    symlink("旧题", root.join("外部/link")).unwrap();
    for path in ["link", "missing", ".ctf", "../赛事"] {
        ctf(root).args(["adopt", path]).assert().failure();
    }
    ctf(root)
        .arg("adopt")
        .arg(root.join("赛事"))
        .assert()
        .failure();
    assert_eq!(
        fs::read(root.join("外部/旧题/user.txt")).unwrap(),
        b"literal bytes"
    );
    assert_eq!(
        fs::read(root.join("外部/incompatible/.ctf/challenge.json")).unwrap(),
        b"broken"
    );
}

#[test]
fn pending_rename_is_detectable_and_never_guessed() {
    let temp = setup();
    let root = temp.path();
    ctf(root).args(["new", "old"]).assert().success();
    let pending = root.join(".ctf/pending.json");
    let record = json!({"operation":"rename", "contest":1, "id":1, "old":"old", "new":"new"});
    fs::write(&pending, serde_json::to_vec(&record).unwrap()).unwrap();
    fs::rename(root.join("赛事/old"), root.join("赛事/new")).unwrap();
    ctf(root)
        .args(["new", "blocked"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("doctor"));
    ctf(root)
        .args(["doctor", "--fix"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("interrupted rename"));
    assert!(pending.exists());
    assert!(root.join("赛事/new").exists());
    fs::rename(root.join("赛事/new"), root.join("赛事/old")).unwrap();
    ctf(root).args(["doctor", "--fix"]).assert().success();
    assert!(!pending.exists());
    ctf(root).args(["rename", "1", "new"]).assert().success();
    // Simulate a crash after the index commit but before journal removal.
    fs::write(&pending, serde_json::to_vec(&record).unwrap()).unwrap();
    ctf(root).args(["doctor", "--fix"]).assert().success();
    let index: Value =
        serde_json::from_slice(&fs::read(root.join(".ctf/index.json")).unwrap()).unwrap();
    assert_eq!(index["contests"][0]["challenges"][0]["id"], 1);
    ctf(root).args(["doctor", "--fix"]).assert().success();
}

#[test]
fn concurrent_adoptions_allocate_unique_ids() {
    let temp = setup();
    let root = temp.path();
    let mut children = Vec::new();
    for n in 0..8 {
        let name = format!("adopt-{n}");
        fs::create_dir(root.join("赛事").join(&name)).unwrap();
        children.push(
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("ctf"))
                .env("CTF_HOME", root)
                .current_dir(root)
                .args(["adopt", &name])
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    ctf(root).arg("doctor").assert().success();
    let index: Value =
        serde_json::from_slice(&fs::read(root.join(".ctf/index.json")).unwrap()).unwrap();
    assert_eq!(index["contests"][0]["next_challenge"], 9);
}

#[test]
fn failed_adoption_reserves_id_without_registering_half_metadata() {
    use std::os::unix::fs::PermissionsExt;
    let temp = setup();
    let root = temp.path();
    let path = root.join("赛事/readonly");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    if fs::write(path.join("probe"), b"").is_ok() {
        // Root can bypass directory permissions; the unprivileged CI run covers this case.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    ctf(root).args(["adopt", "readonly"]).assert().failure();
    assert!(!path.join(".ctf").exists());
    assert!(root.join(".ctf/pending.json").exists());
    ctf(root).args(["doctor", "--fix"]).assert().failure(); // Still an unregistered user directory.
    assert!(!root.join(".ctf/pending.json").exists());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    ctf(root)
        .args(["adopt", "readonly"])
        .assert()
        .success()
        .stdout("2\treadonly\n");
    ctf(root).arg("doctor").assert().success();
}
