//! pq-sync: keeps Proton Pass and 1Password in step. Proton stays the
//! source of truth; 1Password is the everyday front.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pq::private_file::{ensure_private_dir, read_private, write_private};
use pq::process;
use pq::sync::api::{OpApi, ProtonApi};
use pq::sync::config::{self, Config};
use pq::sync::engine;
use pq::sync::lock::RunLock;
use pq::sync::onepassword::OnePassword;
use pq::sync::proton::Proton;
use pq::sync::secrets::{self, Secret};
use pq::sync::state::State;
use pq::sync::{launchd, tty};
use pq::text::printable;

#[derive(Parser)]
#[command(name = "pq-sync", version)]
#[command(about = "Keep Proton Pass and 1Password in step (Proton is the source of truth)")]
#[command(long_about = "Keep Proton Pass and 1Password in step.

New items are copied both ways. Edits made in Proton Pass are written to
1Password; edits made in 1Password are reported, to be made in Proton Pass,
which stays the source of truth. Items gone from one side are archived or
trashed on the other, never deleted for good.

Start with `pq-sync setup`, then `pq-sync run --dry-run`.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Store the tokens in the Keychain, write the config, check both sides
    Setup {
        /// HTTP proxy for pass-cli, e.g. http://100.94.76.106:8888
        #[arg(long, value_name = "URL")]
        proton_proxy: Option<String>,
        /// Ask for the tokens again even if they are stored
        #[arg(long)]
        replace: bool,
    },
    /// Sync once
    Run {
        /// Show what would change; write nothing
        #[arg(long)]
        dry_run: bool,
        /// No output; keep the report for `pq-sync status` (for the agent)
        #[arg(long)]
        quiet: bool,
        /// Allow archiving or trashing many items of a vault in one run
        #[arg(long)]
        allow_mass_delete: bool,
        /// Use your own 1Password sign-in (desktop app) instead of the
        /// service account: for a first large copy, at the keyboard
        #[arg(long)]
        as_me: bool,
    },
    /// Show the last run's report
    Status,
    /// Run pq-sync in the background every INTERVAL seconds (macOS)
    InstallAgent {
        #[arg(long, value_name = "SECONDS", default_value_t = 1800)]
        interval: u64,
    },
    /// Stop running pq-sync in the background
    UninstallAgent,
}

fn main() -> ExitCode {
    // Before any secret is in memory.
    process::protect_memory();
    let cli = Cli::parse();
    let quiet = matches!(cli.command, Command::Run { quiet: true, .. });
    match dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let message = printable(&format!("{e:#}"));
            if quiet {
                // The agent has nowhere to print: keep the error for status
                // (unless it is kept already, with what the run did).
                if e.downcast_ref::<Kept>().is_none() {
                    let _ = keep_report(&format!("Run failed: {message}\n"));
                }
                let _ = notify("The last sync failed. Run: pq-sync status");
            } else {
                eprintln!("pq-sync: {message}");
            }
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Setup {
            proton_proxy,
            replace,
        } => setup(proton_proxy, replace),
        Command::Run {
            dry_run,
            quiet,
            allow_mass_delete,
            as_me,
        } => run(dry_run, quiet, allow_mass_delete, as_me),
        Command::Status => status(),
        Command::InstallAgent { interval } => {
            let program = std::env::current_exe()
                .and_then(|path| path.canonicalize())
                .context("Failed to find the pq-sync program")?;
            let path = launchd::install(&program, interval)?;
            println!(
                "Installed {} (every {} minutes).",
                path.display(),
                interval / 60
            );
            println!(
                "After an upgrade, run `pq-sync run` once in a terminal so macOS can ask \
                 about the Keychain."
            );
            Ok(())
        }
        Command::UninstallAgent => {
            match launchd::uninstall()? {
                Some(path) => println!("Removed {}.", path.display()),
                None => println!("No agent installed."),
            }
            Ok(())
        }
    }
}

fn state_dir() -> Result<PathBuf> {
    let dir = config::state_dir()?;
    ensure_private_dir(&dir, "state")?;
    Ok(dir)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `YYYY-MM-DD HH:MM UTC` for a Unix time.
fn utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let (hour, minute) = ((seconds % 86_400) / 3600, (seconds % 3600) / 60);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

/// A run's failure, already kept with the report of what it did first.
#[derive(Debug)]
struct Kept(String);

impl std::fmt::Display for Kept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Kept {}

fn keep_report(text: &str) -> Result<()> {
    let dir = state_dir()?;
    write_private(
        &dir.join("last-run.txt"),
        &format!("{}\n{text}", utc(now())),
        "report",
    )
}

/// A macOS notification. It says only that something needs attention:
/// notifications show on screen, and titles are not for the screen.
fn notify(message: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    std::process::Command::new("/usr/bin/osascript")
        .args([
            "-e",
            &format!("display notification \"{message}\" with title \"pq-sync\""),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("Failed to run osascript")?;
    Ok(())
}

/// Fail fast when the proxy pass-cli needs is down (Tailscale off, say),
/// rather than after minutes of pass-cli retries.
fn check_proxy(proxy: &str) -> Result<()> {
    if proxy.is_empty() {
        return Ok(());
    }
    let host_port = proxy
        .split_once("://")
        .map_or(proxy, |(_, rest)| rest)
        .trim_end_matches('/');
    let address = host_port
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
        .with_context(|| format!("the proxy {} is not a host:port", printable(proxy)))?;
    TcpStream::connect_timeout(&address, Duration::from_secs(5)).with_context(|| {
        format!(
            "the proxy {} is unreachable (is Tailscale up?); nothing was synced",
            printable(proxy)
        )
    })?;
    Ok(())
}

fn proton(config: &Config, dir: &Path) -> Result<Proton> {
    let session_dir = dir.join("proton-session");
    ensure_private_dir(&session_dir, "Proton session")?;
    Ok(Proton {
        program: PathBuf::from(&config.pass_cli),
        session_dir,
        proxy: (!config.proton_proxy.is_empty()).then(|| config.proton_proxy.clone()),
        token: secrets::get(Secret::ProtonToken)?,
    })
}

fn run(dry_run: bool, quiet: bool, allow_mass_delete: bool, as_me: bool) -> Result<()> {
    let config = Config::load(&config::config_path()?)?;
    let dir = state_dir()?;
    let _lock = RunLock::acquire(&dir.join("run.lock"))?;
    let key = secrets::state_key()?;
    let state_path = dir.join("state.json");
    let mut state = State::load(&state_path, &key)?;

    check_proxy(&config.proton_proxy)?;
    let mut proton = proton(&config, &dir)?;
    proton.ensure_session()?;

    let token = if as_me {
        if !std::io::stdin().is_terminal() {
            bail!("--as-me signs in through the 1Password app: run it at the keyboard");
        }
        None
    } else {
        Some(
            secrets::get(Secret::OpToken)?
                .context("no 1Password service account token is stored; run: pq-sync setup")?,
        )
    };
    let mut op = OnePassword::new(&config.op, token);

    let mut settings = config.engine();
    settings.dry_run = dry_run;
    settings.allow_mass_delete = allow_mass_delete;
    if as_me {
        // An owner's own sign-in is not held to a service account's quota.
        settings.op_requests_per_day = usize::MAX / 2;
        settings.op_writes_per_run = usize::MAX / 2;
    }
    let mut save = |state: &State| state.save(&state_path);
    let (report, result) = engine::run(
        &mut proton,
        &mut op,
        &mut state,
        &key,
        &settings,
        now(),
        &mut save,
    );

    let text = report.to_string();
    if let Err(e) = result {
        // What the run did before it failed is reported once only: keep it.
        let error = format!("{e:#}");
        if !dry_run {
            keep_report(&format!("{text}Run failed: {}\n", printable(&error)))?;
        }
        if !quiet {
            print!("{text}");
        }
        return Err(Kept(error).into());
    }
    if !dry_run {
        keep_report(&text)?;
    }
    if quiet {
        if config.notify && report.needs_attention() {
            notify("Some items need your attention. Run: pq-sync status")?;
        }
    } else {
        print!("{text}");
    }
    Ok(())
}

/// The absolute path of `program` on PATH.
fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                candidate
                    .metadata()
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            }
            #[cfg(not(unix))]
            candidate.is_file()
        })
}

fn setup(proton_proxy: Option<String>, replace: bool) -> Result<()> {
    let config_path = config::config_path()?;
    let mut config = Config::load(&config_path)?;
    if let Some(proxy) = proton_proxy {
        config.proton_proxy = proxy;
    }
    for (program, slot) in [("pass-cli", &mut config.pass_cli), ("op", &mut config.op)] {
        if !Path::new(slot.as_str()).is_absolute() {
            match which(program) {
                Some(path) => *slot = path.display().to_string(),
                None => bail!("{program} is not on PATH; install it first"),
            }
        }
    }
    config.save(&config_path)?;
    println!("Config: {}", config_path.display());
    secrets::state_key()?;

    for (secret, how, prefix) in [
        (
            Secret::ProtonToken,
            "Create one with `pass-cli personal-access-token create --name pq-sync \
             --expiration 1y` (through the proxy where Proton is blocked), then grant it \
             the editor role on each vault to sync (`pass-cli personal-access-token access \
             grant --help`).",
            "pst_",
        ),
        (
            Secret::OpToken,
            "First create the 1Password vaults it will fill (named \"Proton · <vault>\"), then \
             a service account with read and write access to them (1Password.com > \
             Developer > Service Accounts, or `op service-account create`).",
            "ops_",
        ),
    ] {
        if !replace && secrets::get(secret)?.is_some() {
            println!(
                "{} already stored (--replace to change it).",
                secret.describe()
            );
            continue;
        }
        println!("\n{how}");
        let value = tty::read_secret(&format!("Paste the {}", secret.describe()))?;
        if !value.expose().starts_with(prefix) {
            bail!(
                "that does not look like a {} (it starts {prefix}...)",
                secret.describe()
            );
        }
        secrets::set(secret, &value)?;
        println!("Stored in the Keychain.");
    }

    println!("\nChecking both sides...");
    check_proxy(&config.proton_proxy)?;
    let dir = state_dir()?;
    let mut proton = proton(&config, &dir)?;
    proton.ensure_session()?;
    let proton_vaults = proton.vaults()?;
    let token = secrets::get(Secret::OpToken)?.context("no 1Password token stored")?;
    let op_vaults = OnePassword::new(&config.op, Some(token)).vaults()?;
    for vault in &proton_vaults {
        let target = format!("{}{}", config.vault_prefix, vault.name);
        let found = op_vaults.iter().any(|v| v.name == target);
        println!(
            "  Proton '{}' -> 1Password '{}': {}",
            printable(&vault.name),
            printable(&target),
            if found {
                "ready"
            } else {
                "missing: create it and grant the service account"
            }
        );
    }
    println!("\nNext: pq-sync run --dry-run, then pq-sync run, then pq-sync install-agent.");
    Ok(())
}

fn status() -> Result<()> {
    let dir = config::state_dir()?;
    println!("Config: {}", config::config_path()?.display());
    println!("State:  {}", dir.display());
    if let Ok(path) = launchd::plist_path() {
        println!(
            "Agent:  {}",
            if path.exists() {
                "installed"
            } else {
                "not installed"
            }
        );
    }
    let key = secrets::state_key()?;
    let state = State::load(&dir.join("state.json"), &key)?;
    println!(
        "Pairs:  {} vaults, {} items; 1Password requests in the last day: {}",
        state.vaults.len(),
        state.items.len(),
        state.op_requests_today(now())
    );
    match read_private(&dir.join("last-run.txt")) {
        Some(report) => print!("\nLast run, {report}"),
        None => println!("\nNo run yet."),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::utc;

    #[test]
    fn unix_times_format_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_800_000_000), "2027-01-15 08:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
