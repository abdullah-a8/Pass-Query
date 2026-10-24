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

Download the archive for your platform from the [latest release](https://github.com/abdullah-a8/Pass-Query/releases/latest):

| Platform | Archive |
|---|---|
| Linux x86_64 | `pq-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `pq-<version>-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple silicon | `pq-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `pq-<version>-x86_64-apple-darwin.tar.gz` |

The Linux binaries are static and run on any distribution. Verify the download, then install it:

```
shasum -a 256 -c pq-v0.5.0-x86_64-unknown-linux-musl.tar.gz.sha256 &&
gh attestation verify pq-v0.5.0-x86_64-unknown-linux-musl.tar.gz \
    --repo abdullah-a8/Pass-Query \
    --signer-workflow abdullah-a8/Pass-Query/.github/workflows/release.yml \
    --source-ref refs/tags/v0.5.0 &&
tar -xzf pq-v0.5.0-x86_64-unknown-linux-musl.tar.gz &&
install pq-v0.5.0-x86_64-unknown-linux-musl/pq ~/.local/bin/
```

`gh attestation verify` checks that the archive was built by this repository's release workflow from the `v0.5.0` tag. Each step runs only if the one before it succeeded.

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
- pq disables core dumps and, on Linux, makes itself non-dumpable, so its memory cannot end up in a crash dump or be read by your other processes. pass-cli, fzf and the clipboard tools are separate programs and protect their own memory.
- On Proton Business plans, pass-cli reports item reads to your organisation. Labelling matches that share a title reads each one's username, so it is recorded as a read of each of those items.

## Cache Location

Cache is stored at `~/.cache/pp-pass-cli/vault-cache.json` (or `$XDG_CACHE_HOME/pp-pass-cli/vault-cache.json`).

**Security Note:** The cache only contains vault names, item titles, item types and item/share IDs. Passwords and usernames are never cached and are always fetched fresh from pass-cli when needed.

## License

MIT, see [LICENSE](LICENSE).
