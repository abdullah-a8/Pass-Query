<p align="center">
  <img src="./assets/pq_banner.png" alt="pq - Pass Query">
</p>

## Features

- **Fuzzy Search** — Uses fzf for interactive fuzzy selection when multiple items match
- **Auto Clipboard** — Copies the username, then the password when you press Enter, and clears the password from the clipboard after 45 seconds unless you have copied something else since (`wl-copy` on Wayland, `xclip` or `xsel` on X11, `pbcopy` on macOS)
- **Smart Caching** — First search takes ~8-10s, later searches <1s. The cache is used for up to a day, and a search that finds nothing in it checks Proton Pass again automatically
- **Secure Caching** — Only item titles are cached, never passwords or credentials
- **Parallel Search** — Searches up to 10 vaults concurrently with progress indicators
- **Print Mode** — Output credentials to stdout instead of clipboard

## Requirements

- [pass-cli](https://protonpass.github.io/pass-cli/) 2.0.3 or newer, installed and logged in (`pass-cli login`)
- [fzf](https://github.com/junegunn/fzf) for fuzzy selection (`brew install fzf` on macOS, `sudo apt install fzf` on Linux)
- A clipboard tool: `pbcopy` (built into macOS), [wl-clipboard](https://github.com/bugaevc/wl-clipboard) on Wayland, or `xclip` / `xsel` on X11. Not needed with `-p`
- Rust 1.88+ (for building from source)

## Installation

### Prebuilt binary

Download the archive for your platform from the [latest release](https://github.com/abdullah-a8/Pass-Query/releases/latest). Each holds `pq` and `pq-sync`:

| Platform | Archive |
|---|---|
| Linux x86_64 | `pq-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `pq-<version>-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple silicon | `pq-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `pq-<version>-x86_64-apple-darwin.tar.gz` |

The Linux binaries are static and run on any distribution. Verify the download, then install it:

```
shasum -a 256 -c pq-v0.5.1-x86_64-unknown-linux-musl.tar.gz.sha256 &&
gh attestation verify pq-v0.5.1-x86_64-unknown-linux-musl.tar.gz \
    --repo abdullah-a8/Pass-Query \
    --signer-workflow abdullah-a8/Pass-Query/.github/workflows/release.yml \
    --source-ref refs/tags/v0.5.1 &&
tar -xzf pq-v0.5.1-x86_64-unknown-linux-musl.tar.gz &&
mkdir -p ~/.local/bin &&
install pq-v0.5.1-x86_64-unknown-linux-musl/pq pq-v0.5.1-x86_64-unknown-linux-musl/pq-sync ~/.local/bin/
```

`gh attestation verify` checks that the archive was built by this repository's release workflow from the `v0.5.1` tag. Each step runs only if the one before it succeeded.

### From source

```
cargo install --locked --git https://github.com/abdullah-a8/Pass-Query
```

Or from a clone:

```
git clone https://github.com/abdullah-a8/Pass-Query
cd Pass-Query
cargo install --locked --path .
```

## Usage

```
pq <search-term>         Search logins and copy credentials to clipboard
pq -p <search-term>      Print credentials to stdout instead
pq -r <search-term>      Fetch fresh vault data instead of using the cache
pq -a <search-term>      Search all item types, not just logins
pq --clear-after 90 <search-term>   Clear the password after 90 seconds (0: never; default 45)
pq --help                Show help
```

## How It Works

1. Searches all Proton Pass vaults in parallel (up to 10 concurrent)
2. Uses cached vault listings up to a day old for speed (only titles cached, never passwords); trashed items are skipped
3. If nothing in the cache matches, or the chosen item no longer exists, searches once more with fresh data
4. If several matches are found, opens fzf for fuzzy selection. Matches that share a title are labelled with their username (or email), read with `pass-cli item view --field`; the password is read only for the item you pick
5. Fetches credentials fresh from pass-cli (never from cache)
6. Copies the username to the clipboard (if the item has one) and waits for Enter
7. Copies the password to the clipboard
8. Clears the password from the clipboard after 45 seconds, unless something else has been copied since

Clearing is done by a small background helper that pq starts just before copying the password, so it still happens if pq is interrupted. The helper receives only a salted hash of the password, never the password itself. When the time is up it reads the clipboard and clears it only if the clipboard still holds the password. The command-line clipboard tools offer no way to make that check and the clear one atomic step, so something copied in the instant between them would be cleared too.

## Privacy

- pq reads credentials only through pass-cli and never stores them: the cache holds titles, item types and IDs, and vault names.
- The cache file is private to you (0600, in a 0700 directory). pq ignores a cache that is a link or that anyone else could have written, and fetches fresh data instead.
- Credentials reach the clipboard tool through its standard input, never as a command-line argument.
- At startup pq disables core dumps and, on Linux, makes itself non-dumpable, so its memory does not end up in a crash dump or get read by your other processes. This is best effort: if the system refuses, for example in a restrictive sandbox, pq runs without it. pass-cli, fzf and the clipboard tools are separate programs and protect their own memory.
- On Proton Business plans, pass-cli reports item reads to your organisation. Labelling matches that share a title reads each one's username, so it is recorded as a read of each of those items.

## Cache Location

Cache is stored at `~/.cache/pp-pass-cli/vault-cache.json` (or `$XDG_CACHE_HOME/pp-pass-cli/vault-cache.json`).

**Security Note:** The cache only contains vault names, item titles, item types and item/share IDs. Passwords and usernames are never cached and are always fetched fresh from pass-cli when needed.

## pq-sync: Proton Pass to 1Password

`pq-sync`, installed alongside `pq`, keeps 1Password in step with Proton Pass, so you can keep Proton as the place your passwords and aliases live and use 1Password's apps and autofill every day. It syncs logins, secure notes, credit cards and identities through the two official CLIs, `pass-cli` and `op`.

What it does on each run:

- **New items** are copied both ways. A copy into Proton carries what `pass-cli item create` accepts; anything it cannot carry (custom fields, a login's note) is listed for you to copy by hand.
- **Edits made in Proton** are written to 1Password, field by field. Fields you added in 1Password are kept.
- **Edits made in 1Password** are reported, not written: `pass-cli` can update an item only with the new values on its command line, where other programs can read them. Make the edit in Proton and both sides agree.
- **The same field edited differently on both sides** keeps Proton's value, and the conflict is reported.
- **Items gone from one side** are archived in 1Password or moved to the Proton trash, never deleted for good. If more than 10% of a vault's items (and more than 3) vanish in one run, nothing is deleted in that vault until you run `pq-sync run --allow-mass-delete`.
- **Moves** between vaults on either side are followed.
- **Passkeys and attachments are never synced.** `op item get` does not show passkeys, and editing an item from its JSON would drop them. So pq-sync stops writing to a 1Password item once it may hold one: when it was created in 1Password, has files attached, was changed in 1Password since pq-sync last wrote it, or was paired without a record that pq-sync made it (after the state file was lost, say). Its Proton changes are then reported for you to make in 1Password. Items you leave to Proton keep syncing on their own.
- **Aliases stay in Proton.** 1Password cannot create Proton or SimpleLogin aliases. A login that uses an alias carries the address like any other.

Each Proton vault `X` pairs with a 1Password vault named `Proton · X`, which you create. pq-sync uses a 1Password service account, and service accounts cannot reach your built-in Personal or Private vault. Save new logins into a `Proton · …` vault so they reach Proton.

### Setting it up (macOS)

1. In 1Password, create a vault `Proton · <name>` for each Proton vault you want synced, then a [service account](https://developer.1password.com/docs/service-accounts/get-started/) with read and write access to those vaults.
2. Create a Proton personal access token for pq-sync and give it the editor role on the vaults to sync:
   ```
   pass-cli personal-access-token create --name pq-sync --expiration 1y
   pass-cli personal-access-token access grant --help
   ```
3. Run `pq-sync setup`. It asks for both tokens (input hidden) and stores them in the macOS Keychain with a key for the state file. It also records where `pass-cli` and `op` are, and checks both sides. If Proton is blocked where you are, add `--proton-proxy http://host:port`; only pass-cli's traffic goes through it.
4. Run `pq-sync run --dry-run` to see what would change, then `pq-sync run`. For a first large copy, `pq-sync run --as-me` uses your own sign-ins instead of the tokens (see below), which avoids the service account's request limits.
5. Run `pq-sync install-agent` to sync every 30 minutes in the background. `pq-sync status` shows the last run's report, plus everything earlier runs found that needs you; clear that list with `pq-sync status --clear` once you have dealt with it. You get a notification when something needs you.

### Without tokens

If you only want to sync by hand, pq-sync can use the sign-ins you already have: the 1Password app (with its CLI integration turned on) and your own `pass-cli login`. `--as-me` stores no tokens: only the state file's key, which pq-sync makes itself, goes in the Keychain. Tokens an earlier `pq-sync setup` stored stay there, for the agent.

1. Run `pq-sync setup --as-me`. It records where `pass-cli` and `op` are and checks both sides, and asks for no tokens.
2. Run `pq-sync run --as-me --dry-run`, then `pq-sync run --as-me`. Missing `Proton · <name>` vaults are created in 1Password on the first run. They are your own vaults: if you add tokens later, give the service account read and write access to them. A service account's vaults are fixed when it is made, so that means a new one. Until then, a vault the sign-in cannot reach is skipped, and nothing that vanished elsewhere is deleted, since it may have moved there. `pq-sync setup` names such vaults.

`--as-me` only runs at the keyboard: the 1Password app may ask you to approve it, and a background sync would fail whenever the app is locked or your pass-cli session has ended. So `install-agent` needs the tokens. Your own pass-cli login also sees every Proton vault, not just the ones a token was given, shared vaults included, so every one is synced unless the config's `include_vaults` or `exclude_vaults` says otherwise. A name two Proton vaults share (someone's shared vault called `Personal`, say) is never paired: rename one.

With tokens, `pq-sync setup --create-vaults` lets the background sync create missing vaults too; create the service account with `--can-create-vaults`.

### On Linux

There is no Keychain or LaunchAgent on Linux, so pq-sync takes its secrets from the environment, and you schedule it yourself:

1. Do steps 1 and 2 above. Then put the three secrets in a file only you can read, for example `~/.config/pq-sync/env` with mode 0600. Make the state key once, with `openssl rand -hex 32`, and keep it: the state's hashes only match under the key that made them.
   ```
   PQ_SYNC_PROTON_TOKEN=pst_...
   PQ_SYNC_OP_TOKEN=ops_...
   PQ_SYNC_STATE_KEY=<64 hex digits>
   ```
2. With those variables exported, run `pq-sync setup`, `pq-sync run --dry-run` and `pq-sync run`, as on macOS. Setup finds the tokens already set and asks for nothing.
3. To sync in the background, run `pq-sync run --quiet` every 30 minutes from a systemd user timer (`EnvironmentFile=` pointing at that file) or from cron. `install-agent` is macOS only.

### What pq-sync keeps

- **Tokens and the state key:** in the login Keychain. Only the `pq-sync` binary that stored them can read them without asking; after an upgrade, run `pq-sync run` once in a terminal so macOS can ask. On Linux, wherever you keep the environment file.
- **State:** `~/.local/state/pq-sync/state.json` (or `$XDG_STATE_HOME/pq-sync/`), private like pq's cache. It holds which item mirrors which, by ID, and a keyed hash of each field, never a value. The last report, with item titles, sits beside it.
- **Proton session:** pq-sync keeps its own pass-cli session in that directory, apart from yours.
- **Secrets in transit:** item contents reach the CLIs only through their standard input, and tokens only through the environment, never as command-line arguments.

## License

MIT, see [LICENSE](LICENSE).
