//! pq: fast fuzzy search over Proton Pass through `pass-cli`, and
//! `pq-sync`, which keeps Proton Pass and 1Password in step.
//!
//! The library holds the modules both binaries share; `src/main.rs` is `pq`
//! and `src/bin/pq-sync.rs` is the sync tool.

pub mod cache;
pub mod clipboard;
pub mod lookup;
pub mod models;
pub mod pass_cli;
pub mod private_file;
pub mod process;
pub mod search;
pub mod selection;
pub mod sync;
pub mod text;
