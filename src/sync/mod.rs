//! pq-sync: keeps Proton Pass and 1Password in step, through their official
//! CLIs (`pass-cli` and `op`). Proton stays the source of truth.
//!
//! - [`record`]: the canonical item both sides map to, and keyed field hashes.
//! - [`proton_json`]: pass-cli's item JSON and create templates.
//! - [`op_json`]: op's item JSON, create JSON and in-place edits.
//! - [`engine`]: one sync run over both sides.
//! - [`report`]: what a run did and what it needs from the owner.
//! - [`api`]: what the engine needs from each side, as traits.
//! - [`proton`]: the `pass-cli` adapter.
//! - [`onepassword`]: the `op` adapter.
//! - [`exec`]: bounded subprocesses; secrets only through stdin or env.
//! - [`merge`]: the field-level three-way merge of one paired item.
//! - [`secret`]: text that holds secrets and never prints them.
//! - [`state`]: the private state file: pairs, change markers, field hashes.
//! - [`config`], [`secrets`], [`lock`], [`tty`], [`launchd`]: what the
//!   `pq-sync` binary needs around a run.

pub mod api;
pub mod config;
pub mod engine;
mod engine_tests;
pub mod exec;
mod fake_cli;
pub mod launchd;
pub mod lock;
mod memory;
pub mod merge;
pub mod onepassword;
pub mod op_json;
pub mod proton;
pub mod proton_json;
pub mod record;
pub mod report;
pub mod secret;
pub mod secrets;
pub mod state;
pub mod tty;
