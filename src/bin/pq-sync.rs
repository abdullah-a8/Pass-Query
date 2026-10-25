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
use pq::sync::report::Report;
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
        #[arg(long, conflicts_with = "as_me")]
        replace: bool,
        /// Create missing "Proton · <vault>" vaults in 1Password (the
        /// service account must be allowed to create vaults)
        #[arg(long)]
        create_vaults: bool,
        /// No tokens: check both sides with your own sign-ins, for
        /// `pq-sync run --as-me`
        #[arg(long)]
        as_me: bool,
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
        /// Use your own sign-ins, the 1Password app and your pass-cli
        /// login, instead of pq-sync's tokens, and create missing vaults:
        /// at the keyboard
        #[arg(long)]
        as_me: bool,
    },
    /// Show the last run's report, and what still needs you
    Status {
        /// Forget the items that needed you (once you have dealt with them)
        #[arg(long)]
        clear: bool,
    },
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
    let dry_run = matches!(cli.command, Command::Run { dry_run: true, .. });
    match dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let message = printable(&format!("{e:#}"));
            // A dry run keeps nothing: its error is printed even when quiet.
            if quiet && !dry_run {
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
            create_vaults,
            as_me,
        } => setup(proton_proxy, replace, create_vaults, as_me),
        Command::Run {
            dry_run,
            quiet,
            allow_mass_delete,
            as_me,
        } => run(dry_run, quiet, allow_mass_delete, as_me),
        Command::Status { clear } => status(clear),
        Command::InstallAgent { interval } => {
            for secret in [Secret::ProtonToken, Secret::OpToken] {
                if secrets::get(secret)?.is_none() {
                    bail!(
                        "the agent syncs with pq-sync's own tokens, and no {} is stored: run \
                         `pq-sync setup` first, or keep syncing by hand with `pq-sync run --as-me`",
                        secret.describe()
                    );
                }
            }
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

/// Most lines kept of what needs the owner.
const ATTENTION_LINES: usize = 500;

/// Add what needs the owner to what is kept until `status --clear`: each
/// such item is reported once, and the next run's report replaces this one.
fn keep_attention(report: &Report) -> Result<()> {
    let lines = report.attention();
    if lines.is_empty() {
        return Ok(());
    }
    let path = state_dir()?.join("attention.txt");
    let mut kept = read_private(&path).unwrap_or_default();
    kept.push_str(&format!("{}\n{lines}", utc(now())));
    let all: Vec<&str> = kept.lines().collect();
    let start = all.len().saturating_sub(ATTENTION_LINES);
    let kept: String = all[start..]
        .iter()
        .map(|line| format!("{line}\n"))
        .collect();
    write_private(&path, &kept, "attention list")
}

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
    let host_port = proxy_host_port(proxy);
    let addresses: Vec<_> = host_port
        .to_socket_addrs()
        .map(|addresses| addresses.take(4).collect())
        .unwrap_or_default();
    if addresses.is_empty() {
        bail!("the proxy {} is not a host:port", printable(host_port));
    }
    // A name can resolve to IPv6 and IPv4 while the proxy listens on one.
    if !addresses
        .iter()
        .any(|address| TcpStream::connect_timeout(address, Duration::from_secs(5)).is_ok())
    {
        bail!(
            "the proxy {} is unreachable (is Tailscale up?); nothing was synced",
            printable(host_port)
        );
    }
    Ok(())
}

/// A proxy URL's `host:port`, without its scheme, path or credentials: the
/// only part that may be shown.
fn proxy_host_port(proxy: &str) -> &str {
    let rest = proxy.split_once("://").map_or(proxy, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or(rest);
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
}

/// The Proton side: pq-sync's own session and token, or with `as_me` the
/// owner's own pass-cli login.
fn proton(config: &Config, dir: &Path, as_me: bool) -> Result<Proton> {
    let (session_dir, token) = if as_me {
        (None, None)
    } else {
        let session_dir = dir.join("proton-session");
        ensure_private_dir(&session_dir, "Proton session")?;
        (Some(session_dir), secrets::get(Secret::ProtonToken)?)
    };
    Ok(Proton {
        program: PathBuf::from(&config.pass_cli),
        session_dir,
        proxy: (!config.proton_proxy.is_empty()).then(|| config.proton_proxy.clone()),
        token,
    })
}

/// `--as-me` asks the 1Password app, which may prompt: only at a terminal.
fn at_the_keyboard() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("--as-me uses your own sign-ins, which may ask you: run it at the keyboard");
    }
    Ok(())
}

fn run(dry_run: bool, quiet: bool, allow_mass_delete: bool, as_me: bool) -> Result<()> {
    let config = Config::load(&config::config_path()?)?;
    // A relative program would be found from wherever pq-sync runs, and be
    // handed the tokens.
    for (name, program) in [("pass_cli", &config.pass_cli), ("op", &config.op)] {
        if !Path::new(program).is_absolute() {
            bail!("the config's {name} must be an absolute path; run: pq-sync setup");
        }
    }
    let dir = state_dir()?;
    let _lock = RunLock::acquire(&dir.join("run.lock"))?;
    let key = secrets::state_key()?;
    let state_path = dir.join("state.json");
    let mut state = State::load(&state_path, &key)?;

    if as_me {
        at_the_keyboard()?;
    }
    check_proxy(&config.proton_proxy)?;
    let mut proton = proton(&config, &dir, as_me)?;
    proton.ensure_session()?;

    let token = if as_me {
        None
    } else {
        Some(
            secrets::get(Secret::OpToken)?
                .context("no 1Password service account token is stored; run: pq-sync setup")?,
        )
    };
    let mut op = OnePassword::new(&config.op, token);

    let mut settings = config.engine();
    // The owner's own sign-in is not the service account's quota.
    settings.record_op_requests = !as_me;
    settings.dry_run = dry_run;
    settings.allow_mass_delete = allow_mass_delete;
    if as_me {
        // An owner's own sign-in is not held to a service account's quota,
        // and may create the vaults it needs.
        settings.op_requests_per_day = usize::MAX / 2;
        settings.op_writes_per_run = usize::MAX / 2;
        settings.create_op_vaults = true;
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
            keep_attention(&report)?;
        }
        if !quiet {
            print!("{text}");
        }
        return Err(Kept(error).into());
    }
    if !dry_run {
        keep_report(&text)?;
        keep_attention(&report)?;
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
        // A relative entry would be resolved from wherever pq-sync runs.
        .filter(|dir| dir.is_absolute())
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

/// The tokens setup asks for: what each is, how to make it, its prefix.
const TOKENS: [(Secret, &str, &str); 2] = [
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
         Developer > Service Accounts, or `op service-account create`; add \
         `--can-create-vaults` for `setup --create-vaults`).",
        "ops_",
    ),
];

fn setup(
    proton_proxy: Option<String>,
    replace: bool,
    create_vaults: bool,
    as_me: bool,
) -> Result<()> {
    if as_me {
        at_the_keyboard()?;
    }
    let dir = state_dir()?;
    // Not while a run uses the session or the config.
    let _lock = RunLock::acquire(&dir.join("run.lock"))?;
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
    if create_vaults {
        config.create_op_vaults = true;
    }
    config.save(&config_path)?;
    println!("Config: {}", config_path.display());
    secrets::state_key()?;

    // With your own sign-ins there are no tokens to store.
    let tokens = if as_me { &[][..] } else { &TOKENS[..] };
    for &(secret, how, prefix) in tokens {
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
        if secret == Secret::ProtonToken {
            // The old token's session must not outlive it: log in afresh.
            let session = dir.join("proton-session");
            if session.exists() {
                std::fs::remove_dir_all(&session).with_context(|| {
                    format!("Failed to remove the old session in {}", session.display())
                })?;
            }
        }
    }

    println!("\nChecking both sides...");
    check_proxy(&config.proton_proxy)?;
    let mut proton = proton(&config, &dir, as_me)?;
    proton.ensure_session()?;
    let proton_vaults = proton.vaults()?;
    let token = if as_me {
        None
    } else {
        Some(secrets::get(Secret::OpToken)?.context("no 1Password token stored")?)
    };
    let op_vaults = OnePassword::new(&config.op, token).vaults()?;
    let created = as_me || config.create_op_vaults;
    for vault in &proton_vaults {
        let target = format!("{}{}", config.vault_prefix, vault.name);
        let found = op_vaults.iter().any(|v| v.name == target);
        println!(
            "  Proton '{}' -> 1Password '{}': {}",
            printable(&vault.name),
            printable(&target),
            match (found, created) {
                (true, _) => "ready",
                (false, true) => "missing: created on the first run",
                (false, false) => "missing: create it and grant the service account",
            }
        );
    }
    if as_me {
        println!(
            "\nNext: pq-sync run --as-me --dry-run, then pq-sync run --as-me. Syncing in the \
             background (install-agent) needs pq-sync's own tokens: pq-sync setup."
        );
    } else {
        println!("\nNext: pq-sync run --dry-run, then pq-sync run, then pq-sync install-agent.");
    }
    Ok(())
}

fn status(clear: bool) -> Result<()> {
    let dir = config::state_dir()?;
    let attention = dir.join("attention.txt");
    if clear {
        if attention.exists() {
            std::fs::remove_file(&attention)
                .with_context(|| format!("Failed to remove {}", attention.display()))?;
        }
        println!("Cleared the list of items that needed you.");
        return Ok(());
    }
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
    if let Some(kept) = read_private(&attention) {
        print!("\nNeeds you, from earlier runs (`pq-sync status --clear` once done):\n{kept}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{proxy_host_port, utc};

    #[test]
    fn only_a_proxys_host_and_port_are_shown() {
        assert_eq!(
            proxy_host_port("http://user:pa55@100.94.76.106:8888/"),
            "100.94.76.106:8888"
        );
        assert_eq!(proxy_host_port("http://proxy:3128"), "proxy:3128");
        assert_eq!(proxy_host_port("proxy:3128"), "proxy:3128");
    }

    #[test]
    fn unix_times_format_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_800_000_000), "2027-01-15 08:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
