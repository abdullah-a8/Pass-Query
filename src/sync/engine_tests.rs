//! The engine against in-memory Proton and 1Password.

#![cfg(test)]

use super::engine::{Config, run};
use super::memory::{MemoryOp, MemoryProton};
use super::record::{FieldKind, Kind, Record};
use super::report::{Event, Report};
use super::state::State;

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const NOW: u64 = 1_800_000_000;

fn login(title: &str, username: &str, password: &str) -> Record {
    let mut r = Record::new(Kind::Login);
    r.set("title", title, FieldKind::Text);
    r.set("username", username, FieldKind::Text);
    r.set("password", password, FieldKind::Concealed);
    r.set_urls(&["https://example.com/Login"]);
    r
}

struct World {
    proton: MemoryProton,
    op: MemoryOp,
    state: State,
    config: Config,
    saves: usize,
}

impl World {
    /// Proton vault "Personal" (p-share) paired by name with 1Password's
    /// "Proton · Personal" (ov1).
    fn new() -> Self {
        let mut proton = MemoryProton::default();
        proton.vault("ps1", "Personal");
        let mut op = MemoryOp::default();
        op.vault("ov1", "Proton · Personal");
        World {
            proton,
            op,
            state: State::new(KEY),
            config: Config::default(),
            saves: 0,
        }
    }

    fn sync(&mut self) -> Report {
        let saves = &mut self.saves;
        let mut save = |_: &State| {
            *saves += 1;
            Ok(())
        };
        run(
            &mut self.proton,
            &mut self.op,
            &mut self.state,
            KEY,
            &self.config,
            NOW,
            &mut save,
        )
        .unwrap()
    }

    fn op_ids(&self) -> Vec<String> {
        self.op.in_vault("ov1")
    }

    fn only_op_item(&self) -> Record {
        let ids = self.op_ids();
        assert_eq!(ids.len(), 1, "{ids:?}");
        self.op.record("ov1", &ids[0])
    }
}

fn has(report: &Report, matches: impl Fn(&Event) -> bool) -> bool {
    report.events.iter().any(matches)
}

#[test]
fn proton_items_are_copied_to_1password_and_then_left_alone() {
    let mut w = World::new();
    let record = login("Site", "alice", "pw1");
    w.proton.add("ps1", record.clone());
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::CreatedInOp { .. })),
        "{report}"
    );
    assert_eq!(w.state.vaults.len(), 1);
    assert_eq!(w.state.items.len(), 1);
    // The copy reads back as the same record.
    assert_eq!(w.only_op_item(), record);
    assert!(w.saves > 0);

    // Nothing changed: the second run reads no item and writes nothing.
    let (views, gets, writes) = (w.proton.views, w.op.gets, w.op.writes.len());
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
    assert_eq!(
        (w.proton.views, w.op.gets, w.op.writes.len()),
        (views, gets, writes)
    );
}

#[test]
fn a_proton_edit_reaches_1password() {
    let mut w = World::new();
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    w.proton.edit("ps1", &id, |r| {
        r.set("password", "pw2", FieldKind::Concealed)
    });
    let report = w.sync();
    assert!(
        has(
            &report,
            |e| matches!(e, Event::UpdatedOp { fields, .. } if fields == &["password"])
        ),
        "{report}"
    );
    assert_eq!(w.only_op_item().value("password"), "pw2");
}

#[test]
fn proton_edits_to_an_item_changed_in_1password_are_reported_not_written() {
    // A change in 1Password may have added a passkey the CLI cannot see.
    let mut w = World::new();
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_ids()[0].clone();
    w.op.edit_by_owner("ov1", &op_id, |r| {
        r.add_custom("Mine/hint", "blue", FieldKind::Text);
    });
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Guarded { .. })),
        "{report}"
    );
    w.proton.edit("ps1", &id, |r| {
        r.set("password", "pw2", FieldKind::Concealed)
    });
    let writes = w.op.writes.len();
    let report = w.sync();
    assert!(
        has(
            &report,
            |e| matches!(e, Event::Blocked { fields, .. } if fields == &["password"])
        ),
        "{report}"
    );
    assert_eq!(w.op.writes.len(), writes);
    let item = w.only_op_item();
    assert_eq!(item.value("password"), "pw1");
    assert_eq!(item.value("x:Mine/hint"), "blue");
}

#[test]
fn a_1password_edit_is_reported_once_and_never_written_to_proton() {
    let mut w = World::new();
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_ids()[0].clone();
    w.op.edit_by_owner("ov1", &op_id, |r| {
        r.set("password", "rotated", FieldKind::Concealed)
    });

    let report = w.sync();
    assert!(
        has(
            &report,
            |e| matches!(e, Event::OpOnlyChange { fields, .. } if fields == &["password"])
        ),
        "{report}"
    );
    assert!(w.proton.writes.is_empty());
    assert_eq!(w.proton.record("ps1", &id).value("password"), "pw1");

    let report = w.sync();
    assert!(report.events.is_empty(), "reported once: {report}");

    // The owner applies it in Proton: both sides agree, nothing is written.
    let writes = w.op.writes.len();
    w.proton.edit("ps1", &id, |r| {
        r.set("password", "rotated", FieldKind::Concealed)
    });
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
    assert_eq!(w.op.writes.len(), writes);
}

#[test]
fn a_conflict_keeps_protons_value_and_is_reported_for_1password() {
    let mut w = World::new();
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_ids()[0].clone();
    w.op.edit_by_owner("ov1", &op_id, |r| {
        r.set("password", "from-1p", FieldKind::Concealed)
    });
    w.proton.edit("ps1", &id, |r| {
        r.set("password", "from-proton", FieldKind::Concealed)
    });
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Conflict { .. })),
        "{report}"
    );
    // The 1Password item changed outside pq-sync, so Proton's value is
    // reported for it rather than written over it.
    assert!(
        has(&report, |e| matches!(e, Event::Blocked { .. })),
        "{report}"
    );
    assert_eq!(w.only_op_item().value("password"), "from-1p");
    assert_eq!(w.proton.record("ps1", &id).value("password"), "from-proton");
}

#[test]
fn a_1password_item_is_created_in_proton_with_what_pass_cli_can_take() {
    let mut w = World::new();
    let mut record = login("New in 1P", "bob", "pw");
    record.set("note", "a note", FieldKind::Text);
    w.op.add_native("ov1", &record);
    let report = w.sync();
    assert!(
        has(
            &report,
            |e| matches!(e, Event::CreatedInProton { missing, .. } if missing == &["note"])
        ),
        "{report}"
    );
    let items = w.proton.active_in("ps1");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1.record.value("password"), "pw");
    assert_eq!(items[0].1.record.value("note"), "");

    // The missing note is not a Proton deletion: nothing is written back.
    let writes = w.op.writes.len();
    let report = w.sync();
    assert!(
        !has(&report, |e| matches!(
            e,
            Event::UpdatedOp { .. } | Event::Blocked { .. }
        )),
        "{report}"
    );
    assert_eq!(w.op.writes.len(), writes);
    assert_eq!(w.only_op_item().value("note"), "a note");
}

#[test]
fn trashing_in_proton_archives_in_1password_and_archiving_trashes_in_proton() {
    let mut w = World::new();
    let a = w.proton.add("ps1", login("A", "a", "1"));
    for n in 0..9 {
        w.proton.add("ps1", login(&format!("Keep {n}"), "k", "k"));
    }
    let b = w.proton.add("ps1", login("B", "b", "2"));
    w.sync();
    let op_b = w
        .state
        .items
        .iter()
        .find(|p| p.proton_item == b)
        .unwrap()
        .op_item
        .clone();

    w.proton.trash_item("ps1", &a);
    w.op.archive_by_owner("ov1", &op_b);
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::ArchivedInOp { .. })),
        "{report}"
    );
    assert!(
        has(&report, |e| matches!(e, Event::TrashedInProton { .. })),
        "{report}"
    );
    assert!(!w.proton.items[&("ps1".into(), b.clone())].active);
    assert_eq!(w.op.in_vault("ov1").len(), 9);
    assert_eq!(w.state.items.len(), 9);
}

#[test]
fn many_items_vanishing_at_once_deletes_nothing() {
    let mut w = World::new();
    let ids: Vec<String> = (0..10)
        .map(|n| w.proton.add("ps1", login(&format!("Item {n}"), "u", "p")))
        .collect();
    w.sync();
    for id in &ids[..5] {
        w.proton.trash_item("ps1", id);
    }
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(
            e,
            Event::BrakeHeld { vanished: 5, .. }
        )),
        "{report}"
    );
    assert_eq!(w.op.in_vault("ov1").len(), 10);
    assert_eq!(
        w.state.items.len(),
        10,
        "the pairs stay for when the items come back"
    );

    w.config.allow_mass_delete = true;
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::ArchivedInOp { .. })),
        "{report}"
    );
    assert_eq!(w.op.in_vault("ov1").len(), 5);
}

#[test]
fn a_move_between_proton_vaults_moves_the_1password_copy() {
    let mut w = World::new();
    w.proton.vault("ps2", "Work");
    w.op.vault("ov2", "Proton · Work");
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    w.proton.move_by_owner("ps1", &id, "ps2");
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Moved { .. })),
        "{report}"
    );
    assert!(w.op.in_vault("ov1").is_empty());
    assert_eq!(w.op.in_vault("ov2").len(), 1);
    assert!(w.op.archived.is_empty(), "moved, not archived");
    assert_eq!(w.state.items.len(), 1);
}

#[test]
fn a_copy_made_before_a_crash_is_paired_not_duplicated() {
    let mut w = World::new();
    w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    // The state from before the run is lost (the copy exists in 1Password).
    w.state = State::new(KEY);
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Paired { .. })),
        "{report}"
    );
    assert_eq!(w.op_ids().len(), 1);
    assert_eq!(w.state.items.len(), 1);
}

#[test]
fn a_1password_item_that_gained_a_passkey_is_never_edited_again() {
    let mut w = World::new();
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_ids()[0].clone();
    w.op.add_passkey("ov1", &op_id);
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Guarded { .. })),
        "{report}"
    );

    w.proton.edit("ps1", &id, |r| {
        r.set("password", "pw2", FieldKind::Concealed)
    });
    let writes = w.op.writes.len();
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Blocked { .. })),
        "{report}"
    );
    assert_eq!(w.op.writes.len(), writes);
    assert_eq!(w.only_op_item().value("password"), "pw1");
}

#[test]
fn a_value_1password_stores_differently_is_not_written_again_and_again() {
    let mut w = World::new();
    w.op.lowercase_urls = true;
    w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let writes = w.op.writes.len();
    for _ in 0..3 {
        let report = w.sync();
        assert!(report.events.is_empty(), "{report}");
    }
    assert_eq!(w.op.writes.len(), writes);
}

#[test]
fn the_write_budget_spreads_a_large_first_copy_over_runs() {
    let mut w = World::new();
    w.config.op_writes_per_run = 3;
    for n in 0..5 {
        w.proton.add("ps1", login(&format!("Item {n}"), "u", "p"));
    }
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::OpStopped(_))),
        "{report}"
    );
    assert_eq!(w.op_ids().len(), 3);
    w.sync();
    assert_eq!(w.op_ids().len(), 5);
}

#[test]
fn a_rate_limit_stops_1password_requests_and_keeps_what_was_done() {
    let mut w = World::new();
    for n in 0..4 {
        w.proton.add("ps1", login(&format!("Item {n}"), "u", "p"));
    }
    // Two listings, then room for two creates (two requests each).
    w.op.rate_limit_at = Some(6);
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::OpStopped(_))),
        "{report}"
    );
    assert_eq!(w.op_ids().len(), 2);
    assert_eq!(w.state.items.len(), 2);
    w.op.rate_limit_at = None;
    w.sync();
    assert_eq!(w.op_ids().len(), 4);
}

#[test]
fn a_dry_run_writes_nothing() {
    let mut w = World::new();
    w.config.dry_run = true;
    w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.op.add_native("ov1", &login("Other", "bob", "pw"));
    let report = w.sync();
    assert!(report.dry_run);
    assert!(
        has(&report, |e| matches!(e, Event::CreatedInOp { .. })),
        "{report}"
    );
    assert!(
        has(&report, |e| matches!(e, Event::CreatedInProton { .. })),
        "{report}"
    );
    assert!(w.op.writes.is_empty() && w.proton.writes.is_empty());
    assert_eq!(w.state, State::new(KEY));
    assert_eq!(w.saves, 0);
}

#[test]
fn a_vault_without_a_1password_counterpart_is_reported() {
    let mut w = World::new();
    w.proton.vault("ps2", "Work");
    w.proton.add("ps2", login("Site", "alice", "pw1"));
    let report = w.sync();
    assert!(
        has(
            &report,
            |e| matches!(e, Event::Vault(m) if m.contains("'Proton · Work'"))
        ),
        "{report}"
    );
    assert!(w.op.writes.is_empty());

    w.config.create_op_vaults = true;
    w.sync();
    assert!(w.op.vaults.iter().any(|v| v.name == "Proton · Work"));
    assert_eq!(w.state.vaults.len(), 2);
}
