use crate::workspace::{Workspace, home, matches, reject_link};
use anyhow::{Context, Result};
use clap::ValueEnum;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Clone, Copy, ValueEnum)]
pub enum Shell {
    Bash,
}

pub fn print_init(shell: Shell) -> Result<()> {
    write!(
        std::io::stdout().lock(),
        "{}",
        match shell {
            Shell::Bash => include_str!("../shell/init.bash"),
        }
    )?;
    print_completions(shell)
}

pub fn print_completions(shell: Shell) -> Result<()> {
    write!(
        std::io::stdout().lock(),
        "{}",
        match shell {
            Shell::Bash => include_str!("../shell/complete.bash"),
        }
    )?;
    Ok(())
}

pub fn change_dir(path: &Path) -> Result<()> {
    let path = path
        .to_str()
        .context("shell integration requires a UTF-8 workspace path")?;
    if let Some(destination) = std::env::var_os("CTF_CD_FILE") {
        let destination = Path::new(&destination);
        reject_link(destination)?;
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(destination)
            .context("open shell directory handoff file")?;
        file.write_all(path.as_bytes())?;
        file.write_all(b"\0")?;
    } else {
        eprintln!("Enable Bash directory switching with: eval \"$(ctf init bash)\"");
        writeln!(std::io::stdout().lock(), "{path}")?;
    }
    Ok(())
}

pub fn complete(words: &[String]) -> Result<()> {
    let current = words.last().map(String::as_str).unwrap_or_default();
    let static_words: Option<&[&str]> = if words.len() <= 1 {
        Some(&[
            "contest",
            "use",
            "new",
            "list",
            "go",
            "import",
            "paste",
            "extract",
            "target",
            "info",
            "doctor",
            "init",
            "completions",
            "--help",
            "--version",
        ])
    } else if words[0] == "contest" && words.len() == 2 {
        Some(&["new", "list"])
    } else if words[0] == "doctor" {
        Some(&["--fix", "--help"])
    } else if matches!(words[0].as_str(), "init" | "completions") {
        Some(&["bash"])
    } else if current.starts_with('-')
        && (words[0] == "list"
            || (words[0] == "contest" && words.get(1).is_some_and(|s| s == "list")))
    {
        Some(&["--all", "--limit", "--help"])
    } else {
        None
    };
    if let Some(options) = static_words {
        for option in options.iter().filter(|s| s.starts_with(current)) {
            writeln!(std::io::stdout().lock(), "{option}")?;
        }
        return Ok(());
    }
    let contests = words.first().is_some_and(|s| s == "use")
        || (words.first().is_some_and(|s| s == "contest")
            && words.get(1).is_some_and(|s| s == "list"));
    let challenges = words.first().is_some_and(|s| s == "go" || s == "list");
    if !(contests || challenges) || !home()?.join(".ctf/index.json").is_file() {
        return Ok(());
    }
    if let Ok(ws) = Workspace::open() {
        let entries = if contests {
            ws.contest_entries()
        } else {
            match ws.current_contest().and_then(|id| ws.challenge_entries(id)) {
                Ok(entries) => entries,
                Err(_) => return Ok(()),
            }
        };
        for entry in matches(&entries, &[current.into()]) {
            writeln!(std::io::stdout().lock(), "{}", entry.name)?;
        }
    }
    Ok(())
}
