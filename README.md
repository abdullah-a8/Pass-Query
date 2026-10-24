<p align="center">
  <img src="./assets/pq_banner.png" alt="pq - Pass Query">
</p>

## Features

- **Fuzzy Search** — Uses fzf for interactive fuzzy selection when multiple items match
- **Auto Clipboard** — Copies username first, then password after 0.5 seconds (`pbcopy` on macOS, `wl-copy` on Linux/Wayland)
- **Smart Caching** — First search takes ~8-10s, later searches <1s. The cache is used for up to a day, and a search that finds nothing in it checks Proton Pass again automatically
- **Secure Caching** — Only item titles are cached, never passwords or credentials
- **Parallel Search** — Searches up to 10 vaults concurrently with progress indicators
- **Print Mode** — Output credentials to stdout instead of clipboard

## Requirements

- [pass-cli](https://protonpass.github.io/pass-cli/) installed and logged in (`pass-cli login`)
- [fzf](https://github.com/junegunn/fzf) for fuzzy selection (`brew install fzf` on macOS, `sudo apt install fzf` on Linux)
- A clipboard tool: `pbcopy` (built into macOS) or [wl-clipboard](https://github.com/bugaevc/wl-clipboard) / `wl-copy` on Linux/Wayland
- Rust 1.88+ (for building from source)

## Installation

```
cargo install --git https://github.com/abdullah-a8/Pass-Query
```

Or build from source:

```
git clone https://github.com/abdullah-a8/Pass-Query
cd Pass-Query
cargo install --path .
```

## Usage

```
pq <search-term>         Search logins and copy credentials to clipboard
pq -p <search-term>      Print credentials to stdout instead
pq -r <search-term>      Fetch fresh vault data instead of using the cache
pq -a <search-term>      Search all item types, not just logins
pq --help                Show help
```

## How It Works

1. Searches all Proton Pass vaults in parallel (up to 10 concurrent)
2. Uses cached vault listings up to a day old for speed (only titles cached, never passwords); trashed items are skipped
3. If nothing in the cache matches, or the chosen item no longer exists, searches once more with fresh data
4. If multiple matches are found, fetches each match's account identifier (username/email) and opens fzf for fuzzy selection
5. Fetches credentials fresh from pass-cli (never from cache)
6. Copies username to clipboard (if available)
7. Waits 0.5 seconds
8. Copies password to clipboard

## Cache Location

Cache is stored at `~/.cache/pp-pass-cli/vault-cache.json` (or `$XDG_CACHE_HOME/pp-pass-cli/vault-cache.json`).

**Security Note:** The cache only contains vault names, item titles, item types and item/share IDs. Passwords and usernames are never cached and are always fetched fresh from pass-cli when needed.

## License

MIT
