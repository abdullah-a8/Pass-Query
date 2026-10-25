//! The engine against in-memory Proton and 1Password.

#![cfg(test)]

use super::api::OpApi;
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
        let (report, result) = self.try_sync();
        result.unwrap();
        report
    }

    /// A run that may fail, with what it did up to the failure.
    fn try_sync(&mut self) -> (Report, anyhow::Result<()>) {
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
    }

    fn op_item_of(&self, proton_item: &str) -> String {
        self.state
            .items
            .iter()
            .find(|p| p.proton_item == proton_item)
            .unwrap()
            .op_item
            .clone()
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

#[test]
fn a_1password_move_is_found_with_a_change_already_reported() {
    let mut w = World::new();
    w.proton.vault("ps2", "Work");
    w.op.vault("ov2", "Proton · Work");
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_item_of(&id);
    w.op.edit_by_owner("ov1", &op_id, |r| {
        r.set("password", "pw2", FieldKind::Concealed)
    });
    w.sync();
    w.proton
        .edit("ps1", &id, |r| r.set("username", "alice2", FieldKind::Text));
    w.op.move_item(&op_id, "ov1", "ov2").unwrap();
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Moved { .. })),
        "{report}"
    );
    assert!(w.proton.active_in("ps1").is_empty());
    let moved = w.proton.active_in("ps2");
    assert_eq!(moved.len(), 1, "moved, not copied and trashed");
    assert_eq!(moved[0].1.record.value("username"), "alice2");
}

#[test]
fn an_unread_1password_item_holds_back_deletions_it_could_explain() {
    let mut w = World::new();
    w.proton.vault("ps2", "Work");
    w.op.vault("ov2", "Proton · Work");
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_item_of(&id);
    w.op.move_item(&op_id, "ov1", "ov2").unwrap();
    // The vault list and both item lists, then a rate limit: the moved
    // item cannot be read.
    w.op.rate_limit_at = Some(w.op.requests() + 3);
    let report = w.sync();
    assert!(
        !has(&report, |e| matches!(e, Event::TrashedInProton { .. })),
        "{report}"
    );
    assert_eq!(w.proton.active_in("ps1").len(), 1);

    w.op.rate_limit_at = None;
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Moved { .. })),
        "{report}"
    );
    assert_eq!(w.proton.active_in("ps2").len(), 1);
}

#[test]
fn a_run_that_fails_still_returns_what_it_reported() {
    let mut w = World::new();
    let a = w.proton.add("ps1", login("A", "a", "1"));
    let b = w.proton.add("ps1", login("B", "b", "2"));
    w.sync();
    for id in [&a, &b] {
        let op_id = w.op_item_of(id);
        w.op.edit_by_owner("ov1", &op_id, |r| {
            r.set("password", "changed", FieldKind::Concealed)
        });
    }
    // Both listings and the first read, then the token is refused.
    w.op.signed_out_at = Some(w.op.requests() + 3);
    let (report, result) = w.try_sync();
    assert!(result.is_err());
    assert!(
        has(&report, |e| matches!(e, Event::OpOnlyChange { .. })),
        "{report}"
    );
}

#[test]
fn a_copy_whose_reply_was_lost_is_paired_though_1password_changed_it() {
    let mut w = World::new();
    w.op.lowercase_urls = true;
    w.op.lose_create_reply = true;
    w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    assert_eq!(w.state.items.len(), 0);

    w.op.lose_create_reply = false;
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Paired { .. })),
        "{report}"
    );
    assert_eq!(w.op_ids().len(), 1);
    assert_eq!(w.proton.active_in("ps1").len(), 1);
    assert!(w.state.pending.is_empty());
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
}

#[test]
fn deletions_done_before_a_failure_are_saved() {
    let mut w = World::new();
    let a = w.proton.add("ps1", login("A", "a", "1"));
    let b = w.proton.add("ps1", login("B", "b", "2"));
    w.sync();
    w.proton.trash_item("ps1", &a);
    w.proton.trash_item("ps1", &b);
    // Both listings and the first archive, then the token is refused.
    w.op.signed_out_at = Some(w.op.requests() + 4);
    let (_, result) = w.try_sync();
    assert!(result.is_err());
    assert_eq!(w.op.archived.len(), 1);
    assert_eq!(w.state.items.len(), 1);
}

#[test]
fn a_blocked_conflict_settles_once_proton_takes_1passwords_value() {
    let mut w = World::new();
    let op_id = w.op.add_native("ov1", &login("Site", "alice", "pw1"));
    w.sync();
    let id = w.state.items[0].proton_item.clone();
    w.proton.edit("ps1", &id, |r| {
        r.set("password", "from-proton", FieldKind::Concealed)
    });
    w.op.edit_by_owner("ov1", &op_id, |r| {
        r.set("password", "from-1password", FieldKind::Concealed)
    });
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Blocked { .. })),
        "{report}"
    );

    w.proton.edit("ps1", &id, |r| {
        r.set("password", "from-1password", FieldKind::Concealed)
    });
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
    assert!(w.state.items[0].reported.is_empty());
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
}

#[test]
fn a_used_up_daily_budget_stops_the_listings_too() {
    let mut w = World::new();
    w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    w.config.op_requests_per_day = w.state.op_requests_today(NOW);
    let requests = w.op.requests();
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::OpStopped(_))),
        "{report}"
    );
    assert_eq!(w.op.requests(), requests);
}

#[test]
fn each_run_counts_only_its_own_requests() {
    let mut w = World::new();
    w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let (made, counted) = (w.op.requests(), w.state.op_requests_today(NOW));
    w.sync();
    assert_eq!(
        w.state.op_requests_today(NOW) - counted,
        w.op.requests() - made
    );
}

#[test]
fn an_item_paired_without_a_record_of_its_copy_is_guarded() {
    let mut w = World::new();
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    // The state is lost: the reference alone does not prove the copy is
    // pq-sync's, and it may have gained a passkey since.
    w.state = State::new(KEY);
    w.sync();
    assert!(w.state.items[0].op_guarded);
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
}

#[test]
fn a_proton_move_does_not_hide_a_passkey_added_before_it() {
    let mut w = World::new();
    w.proton.vault("ps2", "Work");
    w.op.vault("ov2", "Proton · Work");
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_item_of(&id);
    w.op.add_passkey("ov1", &op_id);
    let moved = w.proton.move_by_owner("ps1", &id, "ps2");
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Guarded { .. })),
        "{report}"
    );
    w.proton.edit("ps2", &moved, |r| {
        r.set("password", "pw2", FieldKind::Concealed)
    });
    let writes = w.op.writes.len();
    w.sync();
    assert_eq!(w.op.writes.len(), writes);
}

#[test]
fn a_1password_move_does_not_hide_a_passkey_added_before_it() {
    let mut w = World::new();
    w.proton.vault("ps2", "Work");
    w.op.vault("ov2", "Proton · Work");
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_item_of(&id);
    w.op.add_passkey("ov1", &op_id);
    w.op.move_item(&op_id, "ov1", "ov2").unwrap();
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Moved { .. })),
        "{report}"
    );
    assert!(
        has(&report, |e| matches!(e, Event::Guarded { .. })),
        "{report}"
    );
    assert!(w.state.items[0].op_guarded);
}

#[test]
fn an_item_with_less_than_a_1password_item_is_not_paired_with_it() {
    let mut w = World::new();
    let mut bare = Record::new(Kind::Login);
    bare.set("title", "Bank", FieldKind::Text);
    w.proton.add("ps1", bare);
    w.op.add_native("ov1", &login("Bank", "me", "secret"));
    let report = w.sync();
    assert!(
        !has(&report, |e| matches!(e, Event::Paired { .. })),
        "{report}"
    );
}

#[test]
fn the_brake_holds_just_over_a_tenth() {
    let mut w = World::new();
    let ids: Vec<String> = (0..31)
        .map(|n| w.proton.add("ps1", login(&format!("Item {n}"), "u", "p")))
        .collect();
    w.sync();
    w.sync();
    for id in &ids[..4] {
        w.proton.trash_item("ps1", id);
    }
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(
            e,
            Event::BrakeHeld { vanished: 4, .. }
        )),
        "{report}"
    );
}

#[test]
fn creating_a_vault_counts_as_a_write() {
    let mut w = World::new();
    w.config.create_op_vaults = true;
    w.config.op_writes_per_run = 1;
    w.proton.vault("ps2", "Work");
    w.proton.vault("ps3", "Home");
    w.sync();
    assert_eq!(w.op.vaults.len(), 2);
}

#[test]
fn requests_not_made_by_the_service_account_are_not_counted() {
    let mut w = World::new();
    w.config.record_op_requests = false;
    w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    assert!(w.op.requests() > 0);
    assert_eq!(w.state.op_requests_today(NOW), 0);
    assert_eq!(w.state.items.len(), 1, "the state is still saved");
}

#[test]
fn a_dry_run_says_which_vaults_it_would_create() {
    let mut w = World::new();
    w.config.create_op_vaults = true;
    w.config.dry_run = true;
    w.proton.vault("ps2", "Work");
    let report = w.sync();
    assert!(
        has(
            &report,
            |e| matches!(e, Event::Vault(m) if m.contains("would create 'Proton · Work'"))
        ),
        "{report}"
    );
    assert_eq!(w.op.vaults.len(), 1);
}

#[test]
fn a_vault_name_two_proton_vaults_share_pairs_with_neither() {
    let mut w = World::new();
    // Someone else's shared vault, also named "Personal", listed first.
    w.proton.vaults.insert(
        0,
        super::api::Vault {
            id: "shared".into(),
            name: "Personal".into(),
        },
    );
    w.proton.add("shared", login("Theirs", "them", "pw"));
    w.proton.add("ps1", login("Mine", "me", "pw"));
    w.op.add_native("ov1", &login("From 1Password", "me", "pw"));
    let report = w.sync();
    assert!(
        has(
            &report,
            |e| matches!(e, Event::Vault(m) if m.contains("2 Proton vaults are named 'Personal'"))
        ),
        "{report}"
    );
    let reported = report
        .events
        .iter()
        .filter(|e| matches!(e, Event::Vault(m) if m.contains("named 'Personal'")))
        .count();
    assert_eq!(reported, 1, "{report}");
    assert!(w.state.vaults.is_empty());
    assert!(w.op.writes.is_empty() && w.proton.writes.is_empty());
}

#[test]
fn a_paired_vault_this_sign_in_cannot_reach_holds_back_deletions() {
    let mut w = World::new();
    w.proton.vault("ps2", "Work");
    w.op.vault("ov2", "Proton · Work");
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    let op_id = w.op_item_of(&id);
    // Moved in 1Password into a vault the next sign-in cannot see.
    w.op.move_item(&op_id, "ov1", "ov2").unwrap();
    w.op.vaults.retain(|v| v.id != "ov2");
    let report = w.sync();
    assert!(
        !has(&report, |e| matches!(e, Event::TrashedInProton { .. })),
        "{report}"
    );
    assert_eq!(w.proton.active_in("ps1").len(), 1);
}

#[test]
fn a_paired_proton_vault_out_of_reach_holds_back_deletions() {
    let mut w = World::new();
    w.proton.vault("ps2", "Work");
    w.op.vault("ov2", "Proton · Work");
    let id = w.proton.add("ps1", login("Site", "alice", "pw1"));
    w.sync();
    // Moved in Proton into a vault the next sign-in cannot see.
    w.proton.move_by_owner("ps1", &id, "ps2");
    w.proton.vaults.retain(|v| v.id != "ps2");
    let report = w.sync();
    assert!(
        !has(&report, |e| matches!(e, Event::ArchivedInOp { .. })),
        "{report}"
    );
    assert_eq!(w.op.in_vault("ov1").len(), 1);
}

#[test]
fn the_vault_lists_say_which_vaults_sync() {
    let mut config = Config::default();
    assert!(config.syncs("Personal"));
    config.include_vaults = vec!["Work".into()];
    assert!(!config.syncs("Personal") && config.syncs("Work"));
    config.exclude_vaults = vec!["Work".into()];
    assert!(!config.syncs("Work"));
}

/// A Proton login as Proton keeps an address typed as "email or username":
/// in its email field, the username empty.
fn email_login(title: &str, email: &str, password: &str) -> Record {
    let mut r = Record::new(Kind::Login);
    r.set("title", title, FieldKind::Text);
    r.set("email", email, FieldKind::Text);
    r.set("password", password, FieldKind::Concealed);
    r
}

/// The value of 1Password field `id` of the only item in "ov1", if any.
fn op_field(w: &World, id: &str) -> Option<String> {
    let ids = w.op_ids();
    let raw = &w.op.items[&("ov1".to_string(), ids[0].clone())];
    raw["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == id)
        .map(|f| f["value"].as_str().unwrap_or("").to_string())
}

#[test]
fn a_proton_login_by_email_has_the_email_as_its_1password_username() {
    let mut w = World::new();
    w.proton
        .add("ps1", email_login("Site", "me@example.com", "pw1"));
    w.sync();
    assert_eq!(op_field(&w, "username").as_deref(), Some("me@example.com"));
    assert_eq!(op_field(&w, "pqsync-email"), None, "no second copy of it");
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
}

#[test]
fn a_proton_login_with_both_keeps_the_email_beside_the_username() {
    let mut w = World::new();
    let mut both = email_login("Site", "me@example.com", "pw1");
    both.set("username", "alice", FieldKind::Text);
    w.proton.add("ps1", both);
    w.sync();
    assert_eq!(op_field(&w, "username").as_deref(), Some("alice"));
    assert_eq!(
        op_field(&w, "pqsync-email").as_deref(),
        Some("me@example.com")
    );
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
}

#[test]
fn a_1password_login_by_email_reaches_proton_as_its_email() {
    let mut w = World::new();
    w.op.add_native("ov1", &{
        let mut r = Record::new(Kind::Login);
        r.set("title", "Site", FieldKind::Text);
        r.set("username", "me@example.com", FieldKind::Text);
        r.set("password", "pw1", FieldKind::Concealed);
        r
    });
    w.sync();
    let items = w.proton.active_in("ps1");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1.record.value("email"), "me@example.com");
    assert_eq!(items[0].1.record.value("username"), "");
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
}

#[test]
fn a_change_of_email_moves_with_it_into_the_username() {
    let mut w = World::new();
    let id = w
        .proton
        .add("ps1", email_login("Site", "me@example.com", "pw1"));
    w.sync();
    w.proton.edit("ps1", &id, |r| {
        r.set("email", "new@example.com", FieldKind::Text)
    });
    w.sync();
    assert_eq!(op_field(&w, "username").as_deref(), Some("new@example.com"));
    assert_eq!(op_field(&w, "pqsync-email"), None);
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
}

#[test]
fn a_username_stays_the_sign_in_when_an_email_is_added() {
    let mut w = World::new();
    // Proton's username field holding an address, its email empty.
    let id = w
        .proton
        .add("ps1", login("Site", "signin@example.com", "pw1"));
    w.sync();
    w.proton.edit("ps1", &id, |r| {
        r.set("email", "contact@example.com", FieldKind::Text)
    });
    w.sync();
    assert_eq!(
        op_field(&w, "username").as_deref(),
        Some("signin@example.com")
    );
    assert_eq!(
        op_field(&w, "pqsync-email").as_deref(),
        Some("contact@example.com")
    );
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
}

#[test]
fn a_username_cleared_in_1password_is_reported() {
    let mut w = World::new();
    let id = w.proton.add("ps1", login("Site", "me@example.com", "pw1"));
    w.sync();
    let op_id = w.op_item_of(&id);
    w.op.edit_by_owner("ov1", &op_id, |r| r.set("username", "", FieldKind::Text));
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(
            e,
            Event::OpOnlyChange { fields, .. } if fields == &["username".to_string()]
        )),
        "{report}"
    );
}

/// Turn the pair of the only item into one an older pq-sync made of a
/// Proton login by email: its 1Password item with an empty username and
/// the email in pq-sync's section (the version as pq-sync left it), its
/// base with the email, not a username, and no layout.
fn make_legacy(w: &mut World, email: &str) {
    let id = w.op_ids()[0].clone();
    let raw = w.op.items.get_mut(&("ov1".to_string(), id)).unwrap();
    let fields = raw["fields"].as_array_mut().unwrap();
    for field in fields.iter_mut() {
        if field["id"] == "username" {
            field["value"] = "".into();
        }
    }
    fields.push(serde_json::json!({
        "id": "pqsync-email", "type": "EMAIL", "label": "email", "value": email,
        "section": { "id": "pq-sync", "label": "Proton Pass" },
    }));
    let mut old = Record::new(Kind::Login);
    old.set("email", email, FieldKind::Text);
    let pair = &mut w.state.items[0];
    pair.base.remove("username");
    pair.base
        .insert("email".to_string(), old.field_hashes(KEY)["email"].clone());
    pair.equivalents.clear();
    pair.op_layout = 0;
}

#[test]
fn a_login_laid_out_before_is_laid_out_again_once() {
    let mut w = World::new();
    w.proton
        .add("ps1", email_login("Site", "me@example.com", "pw1"));
    w.sync();
    make_legacy(&mut w, "me@example.com");

    let report = w.sync();
    assert!(
        report
            .events
            .iter()
            .all(|e| matches!(e, Event::UpdatedOp { .. }))
            && !report.events.is_empty(),
        "{report}"
    );
    assert_eq!(op_field(&w, "username").as_deref(), Some("me@example.com"));
    assert_eq!(op_field(&w, "pqsync-email"), None);
    assert!(w.proton.writes.is_empty(), "Proton is not touched");
    let writes = w.op.writes.len();
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
    assert_eq!(w.op.writes.len(), writes);
}

#[test]
fn a_dry_run_says_which_logins_it_would_lay_out_again() {
    let mut w = World::new();
    w.proton
        .add("ps1", email_login("Site", "me@example.com", "pw1"));
    w.sync();
    make_legacy(&mut w, "me@example.com");
    w.config.dry_run = true;
    let writes = w.op.writes.len();
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::UpdatedOp { .. })),
        "{report}"
    );
    assert_eq!(w.op.writes.len(), writes);
    assert_eq!(op_field(&w, "username").as_deref(), Some(""));
}

#[test]
fn a_guarded_login_laid_out_before_is_reported_not_edited() {
    let mut w = World::new();
    w.proton
        .add("ps1", email_login("Site", "me@example.com", "pw1"));
    w.sync();
    make_legacy(&mut w, "me@example.com");
    w.state.items[0].op_guarded = true;
    let writes = w.op.writes.len();
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Blocked { .. })),
        "{report}"
    );
    assert_eq!(w.op.writes.len(), writes);
    let report = w.sync();
    assert!(report.events.is_empty(), "reported once: {report}");
    assert_eq!(w.state.items[0].op_layout, 0, "read as before");
}

#[test]
fn a_login_changed_after_the_listing_is_not_laid_out() {
    let mut w = World::new();
    w.proton
        .add("ps1", email_login("Site", "me@example.com", "pw1"));
    w.sync();
    make_legacy(&mut w, "me@example.com");
    // A passkey saved between the listing and the read.
    w.op.change_on_get = Some(w.op_ids()[0].clone());
    let writes = w.op.writes.len();
    w.sync();
    assert_eq!(w.op.writes.len(), writes, "not edited");
    assert_eq!(op_field(&w, "username").as_deref(), Some(""));
    w.op.change_on_get = None;
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::Guarded { .. })),
        "the merge sees the change and guards it: {report}"
    );
    assert_eq!(w.op.writes.len(), writes);
}

#[test]
fn a_login_laid_out_before_merges_as_before_until_laid_out() {
    let mut w = World::new();
    let id = w
        .proton
        .add("ps1", email_login("Site", "me@example.com", "pw1"));
    w.sync();
    make_legacy(&mut w, "me@example.com");
    w.proton.edit("ps1", &id, |r| {
        r.set("password", "pw2", FieldKind::Concealed)
    });
    let report = w.sync();
    assert!(
        report.events.iter().all(
            |e| matches!(e, Event::UpdatedOp { fields, .. } if fields == &["password".to_string()])
        ),
        "only the password, no false 1Password change: {report}"
    );
    assert_eq!(w.only_op_item().value("password"), "pw2");
    // Next run, both sides as left: laid out.
    let report = w.sync();
    assert!(
        has(&report, |e| matches!(e, Event::UpdatedOp { .. })),
        "{report}"
    );
    assert_eq!(op_field(&w, "username").as_deref(), Some("me@example.com"));
    let report = w.sync();
    assert!(report.events.is_empty(), "{report}");
}
