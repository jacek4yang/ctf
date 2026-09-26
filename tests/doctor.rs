use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::symlink, path::Path};

fn ctf(home: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("ctf"));
    cmd.env("CTF_HOME", home)
        .env_remove("CTF_CD_FILE")
        .current_dir(home);
    cmd
}
fn setup() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    ctf(temp.path())
        .args(["contest", "new", "中文"])
        .assert()
        .success();
    ctf(temp.path()).args(["new", "题目"]).assert().success();
    temp
}
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn healthy_doctor_is_read_only_and_missing_workspace_is_not_initialized() {
    let temp = setup();
    let index = temp.path().join(".ctf/index.json");
    let before = fs::read(&index).unwrap();
    ctf(temp.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
    assert_eq!(fs::read(index).unwrap(), before);
    assert!(!temp.path().join("中文/题目/.ctf/lock").exists());
    let missing = temp.path().join("absent");
    ctf(temp.path())
        .env("CTF_HOME", &missing)
        .arg("doctor")
        .assert()
        .failure();
    assert!(!missing.exists());
}

#[test]
fn invalid_metadata_and_ids_are_not_guessed() {
    for case in [
        "corrupt",
        "version",
        "id",
        "duplicate",
        "name",
        "next",
        "outside",
    ] {
        let temp = setup();
        let index = temp.path().join(".ctf/index.json");
        let mut data: Value = serde_json::from_slice(&fs::read(&index).unwrap()).unwrap();
        match case {
            "version" => data["version"] = json!(99),
            "id" => data["contests"][0]["entry"]["id"] = json!(0),
            "duplicate" | "name" => {
                let mut c = data["contests"][0].clone();
                if case == "name" {
                    c["entry"]["id"] = json!(2);
                    data["next_contest"] = json!(3);
                }
                data["contests"].as_array_mut().unwrap().push(c);
            }
            "next" => data["next_contest"] = json!(1),
            "outside" => data["contests"][0]["entry"]["name"] = json!("../outside"),
            _ => {}
        }
        write(&index, &data);
        if case == "corrupt" {
            fs::write(&index, b"{").unwrap();
        }
        let before = fs::read(&index).unwrap();
        ctf(temp.path())
            .args(["doctor", "--fix"])
            .assert()
            .failure()
            .stdout(predicate::str::contains("ERROR"));
        assert_eq!(fs::read(index).unwrap(), before);
    }
}

#[test]
fn missing_unregistered_and_symlink_directories_are_reported() {
    let temp = setup();
    fs::rename(
        temp.path().join("中文/题目"),
        temp.path().join("中文/unmanaged"),
    )
    .unwrap();
    ctf(temp.path()).arg("doctor").assert().failure().stdout(
        predicate::str::contains("challenge #1 directory missing")
            .and(predicate::str::contains("unregistered")),
    );
    fs::rename(temp.path().join("中文"), temp.path().join("elsewhere")).unwrap();
    ctf(temp.path())
        .arg("doctor")
        .assert()
        .failure()
        .stdout(predicate::str::contains("contest #1 directory missing"));
    symlink(temp.path().join("elsewhere"), temp.path().join("中文")).unwrap();
    ctf(temp.path())
        .args(["doctor", "--fix"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("symlink"));
    assert!(temp.path().join("elsewhere/unmanaged").exists());
}

#[test]
fn attachments_damage_and_conservative_idempotent_repairs() {
    let temp = setup();
    let root = temp.path();
    let challenge = root.join("中文/题目");
    let source = root.join("source.txt");
    fs::write(&source, b"source").unwrap();
    ctf(root)
        .current_dir(&challenge)
        .arg("import")
        .arg(&source)
        .assert()
        .success();
    let meta: Value =
        serde_json::from_slice(&fs::read(challenge.join(".ctf/challenge.json")).unwrap()).unwrap();
    let original = challenge.join(meta["attachments"][0]["original"].as_str().unwrap());
    fs::remove_file(challenge.join("source.txt")).unwrap();
    fs::remove_file(&original).unwrap();
    ctf(root).arg("doctor").assert().failure().stdout(
        predicate::str::contains("working attachment copy missing")
            .and(predicate::str::contains("archived original missing")),
    );
    fs::write(&original, b"bad").unwrap();
    ctf(root).arg("doctor").assert().failure().stdout(
        predicate::str::contains("size mismatch").and(predicate::str::contains("SHA-256 mismatch")),
    );
    fs::write(&original, b"source").unwrap();
    fs::write(challenge.join("source.txt"), b"editable working copy").unwrap();
    fs::write(challenge.join(".ctf/archive/orphan"), b"orphan").unwrap();
    fs::create_dir_all(challenge.join(".ctf/staging/abandoned")).unwrap();
    fs::write(challenge.join(".ctf/staging/abandoned/partial"), b"partial").unwrap();
    fs::write(root.join(".ctf/.tmpAbandoned"), b"partial").unwrap();
    let index = root.join(".ctf/index.json");
    let mut data: Value = serde_json::from_slice(&fs::read(&index).unwrap()).unwrap();
    data["current_contest"] = json!(999);
    write(&index, &data);
    ctf(root)
        .arg("doctor")
        .assert()
        .failure()
        .stdout(predicate::str::contains("FIXABLE"));
    ctf(root)
        .args(["doctor", "--fix"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FIXED"));
    assert!(!challenge.join(".ctf/archive/orphan").exists());
    assert!(!challenge.join(".ctf/staging/abandoned").exists());
    ctf(root)
        .args(["doctor", "--fix"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FIXED").not());
    ctf(root).arg("doctor").assert().success();
    fs::write(challenge.join(".ctf/challenge.json"), b"bad").unwrap();
    fs::write(challenge.join(".ctf/archive/preserve"), b"unknown").unwrap();
    ctf(root).args(["doctor", "--fix"]).assert().failure();
    assert!(challenge.join(".ctf/archive/preserve").exists());
}
