//! pq-sync: keeps Proton Pass and 1Password in step, through their official
//! CLIs (`pass-cli` and `op`). Proton stays the source of truth.
//!
//! - [`record`]: the canonical item both sides map to, and keyed field hashes.
//! - [`proton_json`]: pass-cli's item JSON and create templates.
//! - [`op_json`]: op's item JSON, create JSON and in-place edits.
//! - [`exec`]: bounded subprocesses; secrets only through stdin or env.
//! - [`merge`]: the field-level three-way merge of one paired item.
//! - [`secret`]: text that holds secrets and never prints them.
//! - [`state`]: the private state file: pairs, change markers, field hashes.

pub mod exec;
pub mod merge;
pub mod op_json;
pub mod proton_json;
pub mod record;
pub mod secret;
pub mod state;
