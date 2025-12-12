<p align="center">
  <img src="./assets/pq_banner.png" alt="pq - Pass Query">
</p>

## Features

- **Fuzzy Search** — Uses fzf for interactive fuzzy selection when multiple items match
- **Auto Clipboard** — Copies username first, then password after 0.5 seconds (Wayland)
- **Smart Caching** — First search takes ~8-10s, subsequent searches <1s (5-minute cache)
- **Secure Caching** — Only item titles are cached, never passwords or credentials
- **Parallel Search** — Searches up to 10 vaults concurrently with progress indicators
- **Print Mode** — Output credentials to stdout instead of clipboard

## Requirements

- [pass-cli](https://protonpass.github.io/pass-cli/) installed and logged in
- [fzf](https://github.com/junegunn/fzf) for fuzzy selection
- [wl-clipboard](https://github.com/bugaevc/wl-clipboard) for Wayland clipboard support
- Rust 1.85+ (for building from source)

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
pq <search-term>         Search and copy credentials to clipboard
pq -p <search-term>      Print credentials to stdout instead
pq -r <search-term>      Force refresh cache before searching
pq --help                Show help
```

## How It Works

1. Searches all Proton Pass vaults in parallel (up to 10 concurrent)
2. Uses cached vault listings for speed (only titles cached, never passwords)
3. If multiple matches found, opens fzf for fuzzy selection
4. Fetches credentials fresh from pass-cli (never from cache)
5. Copies username to clipboard (if available)
6. Waits 0.5 seconds
7. Copies password to clipboard

## Cache Location

Cache is stored at `~/.cache/pp-pass-cli/vault-cache.json` (or `$XDG_CACHE_HOME/pp-pass-cli/vault-cache.json`).

**Security Note:** The cache only contains vault names and item titles. Passwords and usernames are never cached and are always fetched fresh from pass-cli when needed.

## License

MIT
