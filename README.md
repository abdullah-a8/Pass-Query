# pp - Proton Pass Search

⚡ **BLAZINGLY fast** password search for Proton Pass CLI with intelligent caching.

## Performance

- **First search**: 6-10 seconds (fetches from pass-cli)
- **Cached searches**: ~2-3 seconds (fast search + fresh password fetch)
- **Cache TTL**: 5 minutes (auto-refresh)
- **10x faster** than original bash script!

## Security

- ✅ **Passwords NEVER cached** - always fetched fresh
- ✅ Cache only stores item titles (not sensitive)
- ✅ Secure by default - no passwords on disk

## Usage

```bash
# Basic search (uses cache if available)
pp <search-term>

# Force refresh cache (after adding new passwords)
pp --refresh <search-term>
```

Searches all vaults with intelligent caching and prints the password to stdout.

## Requirements

- [pass-cli](https://protonpass.github.io/pass-cli/) installed and logged in
- Rust 1.70+

## Installation

```bash
cargo install --path .
```

## Features

- ✅ **Lightning fast**: <1 second for cached searches
- ✅ **Smart caching**: Auto-expires after 5 minutes
- ✅ **Parallel search**: 10 concurrent vault queries
- ✅ **Auto-fallback**: Works even if cache fails
- ✅ **Secure**: Cache stored in user directory
