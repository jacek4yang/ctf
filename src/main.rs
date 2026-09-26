mod archive;
mod attachments;
mod shell;
mod workspace;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use workspace::{Entry, Workspace, matches, resolve};

#[derive(Parser)]
#[command(version, about = "Manage CTF workspaces, contests, and challenges")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage contests
    Contest {
        #[command(subcommand)]
        command: ContestCommand,
    },
    /// Select a contest and enter its directory
    Use { query: Vec<String> },
    /// Create a challenge and enter its directory
    New { name: String },
    /// List challenges in the current contest
    List {
        query: Vec<String>,
        #[arg(long)]
        all: bool,
        /// Maximum results (default: CTF_LIMIT or 20)
        #[arg(short, long, value_parser = clap::value_parser!(u32).range(1..))]
        limit: Option<u32>,
    },
    /// Enter a challenge by permanent ID, exact name, or unique fuzzy match
    Go { query: Vec<String> },
    /// Import a local file or HTTP(S) attachment into the current challenge
    Import { source: String },
    /// Save clipboard text verbatim as an attachment
    Paste,
    /// Extract one archive safely (or select the only archive in the directory)
    Extract { archive: Option<PathBuf> },
    /// Store a target string without executing it
    Target { text: String },
    /// Show the current contest/challenge and attachment metadata
    Info,
    /// Print shell integration, including dynamic completion
    Init { shell: shell::Shell },
    /// Print dynamic shell completion setup (included by init)
    Completions { shell: shell::Shell },
    #[command(name = "__complete", hide = true)]
    Complete {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        words: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ContestCommand {
    /// Create a contest
    New { name: String },
    /// List contests by permanent ID
    List {
        query: Vec<String>,
        #[arg(long)]
        all: bool,
        #[arg(short, long, value_parser = clap::value_parser!(u32).range(1..))]
        limit: Option<u32>,
    },
}

fn main() {
    if let Err(error) = run() {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
        {
            return;
        }
        eprintln!("ctf: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { shell } => return shell::print_init(shell),
        Command::Completions { shell } => return shell::print_completions(shell),
        Command::Complete { words } => return shell::complete(&words),
        _ => {}
    }
    let mut ws = Workspace::open()?;
    match cli.command {
        Command::Contest {
            command: ContestCommand::New { name },
        } => {
            let entry = ws.create_contest(&name)?;
            writeln!(io::stdout().lock(), "{}\t{}", entry.id, entry.name)?;
        }
        Command::Contest {
            command: ContestCommand::List { query, all, limit },
        } => {
            list(&ws.contest_entries(), &query, all, limit)?;
        }
        Command::Use { query } => {
            let entries = ws.contest_entries();
            let entry = if query.is_empty() {
                drop(ws);
                let entry = choose(&entries, &query, "contest")?;
                ws = Workspace::open()?;
                entry
            } else {
                choose(&entries, &query, "contest")?
            };
            ws.select_contest(entry.id)?;
            shell::change_dir(&ws.contest_path(entry.id)?)?;
        }
        Command::New { name } => {
            let contest = ws.current_contest()?;
            let entry = ws.create_challenge(contest, &name)?;
            eprintln!("Created challenge {}: {}", entry.id, entry.name);
            shell::change_dir(&ws.challenge_path(contest, entry.id)?)?;
        }
        Command::List { query, all, limit } => {
            let contest = ws.current_contest()?;
            list(&ws.challenge_entries(contest)?, &query, all, limit)?;
        }
        Command::Go { query } => {
            let contest = ws.current_contest()?;
            let entries = ws.challenge_entries(contest)?;
            let entry = if query.is_empty() {
                drop(ws);
                let entry = choose(&entries, &query, "challenge")?;
                ws = Workspace::open()?;
                entry
            } else {
                choose(&entries, &query, "challenge")?
            };
            shell::change_dir(&ws.challenge_path(contest, entry.id)?)?;
        }
        Command::Import { source } => {
            let path = ws.current_challenge_path()?;
            drop(ws);
            let _lock = attachments::lock(&path)?;
            let attachment = attachments::import(&path, &source)?;
            writeln!(io::stdout().lock(), "{}", attachment.filename)?;
        }
        Command::Paste => {
            let path = ws.current_challenge_path()?;
            drop(ws);
            let _lock = attachments::lock(&path)?;
            let text = attachments::clipboard()?;
            let attachment =
                attachments::store(&path, "clipboard", "clipboard.txt", text.as_bytes())?;
            writeln!(io::stdout().lock(), "{}", attachment.filename)?;
        }
        Command::Extract { archive: input } => {
            let path = ws.current_challenge_path()?;
            drop(ws);
            let input = archive::select(&path, input)?;
            let (count, output) = archive::extract(&input, &path)?;
            writeln!(
                io::stdout().lock(),
                "Extracted {count} files to {}",
                output.display()
            )?;
        }
        Command::Target { text } => {
            let path = ws.current_challenge_path()?;
            drop(ws);
            let _lock = attachments::lock(&path)?;
            let mut meta = attachments::load(&path)?;
            meta.target = Some(text);
            attachments::save(&path, &meta)?;
        }
        Command::Info => {
            let contest = ws.current_contest()?;
            writeln!(io::stdout().lock(), "Workspace: {}", ws.root.display())?;
            writeln!(
                io::stdout().lock(),
                "Contest: {contest}\t{}",
                ws.contest_name(contest)?
            )?;
            if let Some(challenge) = ws.current_challenge()? {
                let path = ws.challenge_path(contest, challenge)?;
                writeln!(
                    io::stdout().lock(),
                    "Challenge: {challenge}\t{}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                )?;
                writeln!(io::stdout().lock(), "Directory: {}", path.display())?;
                writeln!(
                    io::stdout().lock(),
                    "{}",
                    serde_json::to_string_pretty(&attachments::load(&path)?)?
                )?;
            }
        }
        Command::Init { .. } | Command::Completions { .. } | Command::Complete { .. } => {
            unreachable!()
        }
    }
    Ok(())
}

fn result_limit(limit: Option<u32>) -> Result<usize> {
    let limit = match limit {
        Some(n) => n as usize,
        None => match std::env::var("CTF_LIMIT") {
            Ok(value) => value
                .parse()
                .context("CTF_LIMIT must be a positive integer")?,
            Err(std::env::VarError::NotPresent) => 20,
            Err(error) => return Err(error.into()),
        },
    };
    if limit == 0 {
        bail!("result limit must be positive");
    }
    Ok(limit)
}

fn list(entries: &[Entry], query: &[String], all: bool, limit: Option<u32>) -> Result<()> {
    let results = matches(entries, query);
    let limit = if all {
        usize::MAX
    } else {
        result_limit(limit)?
    };
    for entry in results.iter().take(limit) {
        writeln!(io::stdout().lock(), "{}\t{}", entry.id, entry.name)?;
    }
    if results.len() > limit {
        eprintln!(
            "Showing {limit} of {} matches; use --all or --limit N.",
            results.len()
        );
    }
    Ok(())
}

fn choose(entries: &[Entry], query: &[String], kind: &str) -> Result<Entry> {
    if !query.is_empty() {
        return resolve(entries, query).cloned();
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        bail!("provide a {kind} ID or name (interactive selection requires a terminal)");
    }
    for entry in entries.iter().take(20) {
        eprintln!("{}\t{}", entry.id, entry.name);
    }
    if entries.len() > 20 {
        eprintln!("… {} more; type a name to search", entries.len() - 20);
    }
    eprint!("{kind} ID or query: ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.trim().is_empty() {
        bail!("selection cancelled");
    }
    resolve(entries, &[line.trim().to_owned()]).cloned()
}
