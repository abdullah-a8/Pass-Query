//! pq-sync: keeps Proton Pass and 1Password in step, through their official
//! CLIs (`pass-cli` and `op`). Proton stays the source of truth.
//!
//! - [`record`]: the canonical item both sides map to, and keyed field hashes.
//! - [`proton_json`]: pass-cli's item JSON and create templates.
//! - [`op_json`]: op's item JSON, create JSON and in-place edits.
//! - [`secret`]: text that holds secrets and never prints them.

pub mod op_json;
pub mod proton_json;
pub mod record;
pub mod secret;
