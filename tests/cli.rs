use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use tempfile::TempDir;

fn ctf(home: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("ctf"));
    cmd.env("CTF_HOME", home)
        .env_remove("CTF_CD_FILE")
        .env_remove("CTF_LIMIT")
        .current_dir(home.parent().unwrap());
    cmd
}

fn setup() -> (TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("workspace");
    ctf(&home)
        .args(["contest", "new", "研究生网络安全创新大赛"])
        .assert()
        .success();
    (temp, home)
}

#[test]
fn unicode_navigation_search_and_completion() {
    let (_temp, home) = setup();
    for name in ["签到题", "easyRSA", "hard RSA", "quote's $name"] {
        ctf(&home).args(["new", name]).assert().success();
    }
    ctf(&home)
        .args(["contest", "list", "研究生"])
        .assert()
        .success()
        .stdout("1\t研究生网络安全创新大赛\n");
    ctf(&home)
        .args(["list", "rsa", "easy"])
        .assert()
        .success()
        .stdout("2\teasyRSA\n");
    ctf(&home).args(["go", "rsa"]).assert().failure().stderr(
        predicate::str::contains("ambiguous")
            .and(predicate::str::contains("2\teasyRSA"))
            .and(predicate::str::contains("3\thard RSA")),
    );
    ctf(&home)
        .args(["go", "签题"])
        .assert()
        .success()
        .stdout(predicate::str::contains("签到题"));
    ctf(&home)
        .args(["go", "3"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hard RSA"));
    ctf(&home).args(["go", "999"]).assert().failure();
    ctf(&home)
        .args(["go"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("terminal"));
    ctf(&home)
        .args(["__complete", "go", "签"])
        .assert()
        .success()
        .stdout("签到题\n");
    ctf(&home)
        .args(["__complete", "use", "研"])
        .assert()
        .success()
        .stdout("研究生网络安全创新大赛\n");
    let handoff = tempfile::NamedTempFile::new().unwrap();
    ctf(&home)
        .env("CTF_CD_FILE", handoff.path())
        .args(["go", "1"])
        .assert()
        .success()
        .stdout("");
    assert_eq!(
        fs::read_to_string(handoff.path()).unwrap(),
        format!(
            "{}\0",
            home.join("研究生网络安全创新大赛/签到题")
                .canonicalize()
                .unwrap()
                .display()
        )
    );
    ctf(&home)
        .args(["contest", "new", "other"])
        .assert()
        .success();
    ctf(&home).args(["use", "2"]).assert().success();
    ctf(&home).args(["list"]).assert().success().stdout("");
    ctf(&home)
        .current_dir(home.join("研究生网络安全创新大赛/签到题"))
        .args(["list", "easy"])
        .assert()
        .success()
        .stdout("2\teasyRSA\n");
}

#[test]
fn limits_ids_and_concurrent_allocation() {
    let (_temp, home) = setup();
    let mut children = Vec::new();
    for i in 0..30 {
        children.push(
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("ctf"))
                .env("CTF_HOME", &home)
                .env_remove("CTF_CD_FILE")
                .current_dir(home.parent().unwrap())
                .args(["new", &format!("challenge-{i:02}")])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let index: Value =
        serde_json::from_slice(&fs::read(home.join(".ctf/index.json")).unwrap()).unwrap();
    let entries = index["contests"][0]["challenges"].as_array().unwrap();
    let mut ids: Vec<_> = entries.iter().map(|e| e["id"].as_u64().unwrap()).collect();
    ids.sort();
    assert_eq!(ids, (1..=30).collect::<Vec<_>>());
    let output = ctf(&home)
        .args(["list"])
        .assert()
        .success()
        .stderr(predicate::str::contains("20 of 30"))
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(output).unwrap().lines().count(), 20);
    let output = ctf(&home)
        .args(["list", "--all"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(output).unwrap().lines().count(), 30);
    let output = ctf(&home)
        .env("CTF_LIMIT", "3")
        .args(["list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(output).unwrap().lines().count(), 3);
    let output = ctf(&home)
        .env("CTF_LIMIT", "3")
        .args(["list", "--limit", "5"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(output).unwrap().lines().count(), 5);
    ctf(&home).args(["list", "--limit", "0"]).assert().failure();
    ctf(&home)
        .env("CTF_LIMIT", "bad")
        .args(["list"])
        .assert()
        .failure();
    let permanent = entries[12]["id"].as_u64().unwrap();
    let name = entries[12]["name"].as_str().unwrap();
    ctf(&home)
        .args(["list", name])
        .assert()
        .success()
        .stdout(format!("{permanent}\t{name}\n"));
    fs::remove_dir_all(
        home.join("研究生网络安全创新大赛")
            .join(entries[0]["name"].as_str().unwrap()),
    )
    .unwrap();
    ctf(&home)
        .args(["new", "later"])
        .assert()
        .success()
        .stderr(predicate::str::contains("challenge 31"));
    ctf(&home)
        .args(["go", &permanent.to_string()])
        .assert()
        .success()
        .stdout(predicate::str::contains(name));
}

#[test]
fn attachment_import_target_and_metadata() {
    let (temp, home) = setup();
    ctf(&home).args(["new", "签到题"]).assert().success();
    let challenge = home.join("研究生网络安全创新大赛/签到题");
    let source = temp.path().join("附件.txt");
    fs::write(&source, "literal text\r\nbase64: aGVsbG8=\n").unwrap();
    for expected in ["附件.txt\n", "附件-2.txt\n"] {
        ctf(&home)
            .current_dir(&challenge)
            .arg("import")
            .arg(&source)
            .assert()
            .success()
            .stdout(expected);
    }
    let target = "nc 1.2.3.4 2333; $(touch SHOULD_NOT_EXIST)";
    ctf(&home)
        .current_dir(&challenge)
        .args(["target", target])
        .assert()
        .success();
    let meta: Value =
        serde_json::from_slice(&fs::read(challenge.join(".ctf/challenge.json")).unwrap()).unwrap();
    assert_eq!(meta["target"], target);
    assert_eq!(meta["attachments"].as_array().unwrap().len(), 2);
    assert!(!challenge.join("SHOULD_NOT_EXIST").exists());
    let original = challenge.join(meta["attachments"][0]["original"].as_str().unwrap());
    fs::write(challenge.join("附件.txt"), b"edited").unwrap();
    assert_eq!(fs::read(&original).unwrap(), fs::read(source).unwrap());
    ctf(&home)
        .current_dir(&challenge)
        .arg("info")
        .assert()
        .success()
        .stdout(predicate::str::contains("sha256"));
    fs::write(challenge.join(".ctf/challenge.json"), "broken").unwrap();
    ctf(&home)
        .current_dir(&challenge)
        .args(["target", "new"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid challenge metadata"));
    assert_eq!(
        fs::read_to_string(challenge.join(".ctf/challenge.json")).unwrap(),
        "broken"
    );
}

#[test]
fn http_import_preserves_bytes() {
    let (_temp, home) = setup();
    ctf(&home).args(["new", "web"]).assert().success();
    let challenge = home.join("研究生网络安全创新大赛/web");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/%E9%99%84%E4%BB%B6.bin?download=1",
        listener.local_addr().unwrap()
    );
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        let read = socket.read(&mut request).unwrap();
        assert!(read > 0);
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n\x00raw\xff",
            )
            .unwrap();
    });
    ctf(&home)
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .current_dir(&challenge)
        .args(["import", &url])
        .assert()
        .success()
        .stdout("附件.bin\n");
    server.join().unwrap();
    assert_eq!(
        fs::read(challenge.join("附件.bin")).unwrap(),
        b"\x00raw\xff"
    );
}

#[test]
fn invalid_names_and_metadata_are_rejected() {
    let (_temp, home) = setup();
    for name in ["../escape", ".ctf", "bad/name", "bad\nname", "", "..", "\t"] {
        ctf(&home).args(["new", name]).assert().failure();
    }
    let path = home.join(".ctf/index.json");
    let mut index: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    index["next_contest"] = 1.into();
    let bytes = serde_json::to_vec(&index).unwrap();
    fs::write(&path, &bytes).unwrap();
    ctf(&home)
        .args(["contest", "new", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ID"));
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn linux_names_and_contest_ambiguity() {
    let (_temp, home) = setup();
    for name in [
        "[极客大挑战 2019]EasySQL",
        "quote\"' $name",
        "back\\slash",
        "CON",
        "colon:asterisk*?",
        " spaced ",
    ] {
        ctf(&home).args(["new", name]).assert().success();
        ctf(&home)
            .args(["go", name])
            .assert()
            .success()
            .stdout(predicate::str::contains(name));
    }
    ctf(&home)
        .args(["list", "极客", "sql"])
        .assert()
        .success()
        .stdout("1\t[极客大挑战 2019]EasySQL\n");
    ctf(&home)
        .args(["contest", "new", "BUUCTF"])
        .assert()
        .success();
    ctf(&home)
        .args(["contest", "new", "BUUCTF training"])
        .assert()
        .success();
    ctf(&home)
        .args(["use", "buu"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ambiguous").and(predicate::str::contains("2\tBUUCTF")));
    ctf(&home).args(["use", "BUUCTF"]).assert().success();
    fs::remove_dir_all(home.join("BUUCTF")).unwrap();
    ctf(&home)
        .args(["contest", "new", "later"])
        .assert()
        .success()
        .stdout("4\tlater\n");
}

#[test]
fn paste_preserves_plain_text_with_mock_clipboard() {
    let (temp, home) = setup();
    ctf(&home).args(["new", "clipboard"]).assert().success();
    let challenge = home.join("研究生网络安全创新大赛/clipboard");
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let helper = bin.join("wl-paste");
    fs::write(
        &helper,
        "#!/bin/sh\nexec /bin/cat -- \"$CTF_TEST_CLIPBOARD\"\n",
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let input = temp.path().join("clipboard-source");
    let text = "中文\r\n  aGVsbG8=\n\\x41\n";
    fs::write(&input, text).unwrap();
    ctf(&home)
        .current_dir(&challenge)
        .env("PATH", &bin)
        .env("CTF_TEST_CLIPBOARD", &input)
        .arg("paste")
        .assert()
        .success()
        .stdout("clipboard.txt\n");
    assert_eq!(
        fs::read_to_string(challenge.join("clipboard.txt")).unwrap(),
        text
    );
    let meta: Value =
        serde_json::from_slice(&fs::read(challenge.join(".ctf/challenge.json")).unwrap()).unwrap();
    let original = meta["attachments"][0]["original"].as_str().unwrap();
    assert!(original.starts_with(".ctf/archive/"));
    assert_eq!(fs::read_to_string(challenge.join(original)).unwrap(), text);
}

#[test]
fn metadata_symlinks_are_rejected() {
    let (temp, home) = setup();
    ctf(&home).args(["new", "links"]).assert().success();
    let challenge = home.join("研究生网络安全创新大赛/links");
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, challenge.join(".ctf/archive")).unwrap();
    let source = temp.path().join("source.txt");
    fs::write(&source, "original").unwrap();
    ctf(&home)
        .current_dir(&challenge)
        .arg("import")
        .arg(&source)
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    fs::remove_file(challenge.join(".ctf/challenge.json")).unwrap();
    symlink(&source, challenge.join(".ctf/challenge.json")).unwrap();
    ctf(&home)
        .current_dir(&challenge)
        .args(["target", "no write"])
        .assert()
        .failure();
    assert_eq!(fs::read_to_string(source).unwrap(), "original");
}

#[test]
fn slow_import_does_not_block_navigation() {
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;
    let (_temp, home) = setup();
    ctf(&home).args(["new", "download"]).assert().success();
    let challenge = home.join("研究生网络安全创新大赛/download");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/slow.txt", listener.local_addr().unwrap());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
            .unwrap();
        ready_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        socket.write_all(b"data").unwrap();
    });
    let mut download = std::process::Command::new(assert_cmd::cargo::cargo_bin!("ctf"))
        .env("CTF_HOME", &home)
        .env("NO_PROXY", "127.0.0.1")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .current_dir(&challenge)
        .args(["import", &url])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    ctf(&home)
        .timeout(Duration::from_secs(2))
        .args(["go", "1"])
        .assert()
        .success();
    ctf(&home)
        .timeout(Duration::from_secs(2))
        .args(["list"])
        .assert()
        .success();
    release_tx.send(()).unwrap();
    assert!(download.wait().unwrap().success());
    server.join().unwrap();
}
