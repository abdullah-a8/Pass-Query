# pq - Pass Query

Fast fuzzy password search for Proton Pass CLI.

## Features

- **Fuzzy Search** — Uses fzf for interactive fuzzy selection when multiple items match
- **Auto Clipboard** — Copies username first, then password after 3 seconds (Wayland)
- **Smart Caching** — First search takes ~8-10s, subsequent searches <1s (5-minute cache)
- **Parallel Search** — Searches all vaults concurrently for speed

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
cd pq
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

1. Searches all Proton Pass vaults in parallel
2. If multiple matches found, opens fzf for fuzzy selection
3. Copies username to clipboard
4. Waits 3 seconds for you to paste
5. Copies password to clipboard

## License

MIT
