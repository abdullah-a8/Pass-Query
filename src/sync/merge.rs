//! The field-level three-way merge of one paired item.
//!
//! The base is the keyed hash of each field at the last point both sides
//! agreed. Comparing each side's current hash with it says which side
//! changed which field:
//!
//! | Proton | 1Password | Outcome |
//! |---|---|---|
//! | same | same | nothing |
//! | changed | same | write the Proton value to 1Password |
//! | same | changed | report: apply it in Proton by hand (pass-cli can only update an item with its values on the command line) |
//! | changed | changed, equal | agree: new base |
//! | changed | changed, different | conflict: Proton wins, reported |
//!
//! A field Proton could not receive when the item was created from
//! 1Password (`proton_missing`) counts as unchanged in Proton until a value
//! appears there. A guarded 1Password item (it may hold data the CLI cannot
//! see, such as a passkey) is never written: what would have been written is
//! reported instead.

use std::collections::{BTreeMap, BTreeSet};

use super::record::{FieldHash, Record};

pub struct MergeInput<'a> {
    pub base: &'a BTreeMap<String, FieldHash>,
    pub proton: &'a Record,
    pub op: &'a Record,
    pub key: &'a [u8],
    pub proton_missing: &'a BTreeSet<String>,
    pub op_guarded: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergePlan {
    /// Fields whose Proton value goes to 1Password (an absent value clears
    /// the field there).
    pub write_to_op: BTreeSet<String>,
    /// Fields changed in 1Password only, to apply in Proton by hand.
    pub op_only_changes: BTreeSet<String>,
    /// Fields changed differently on both sides. Proton's value wins: they
    /// are also in `write_to_op`, or in `blocked` when the item is guarded.
    pub conflicts: BTreeSet<String>,
    /// Fields that would have been written to a guarded 1Password item.
    pub blocked: BTreeSet<String>,
    /// The base once `write_to_op` has been written.
    pub new_base: BTreeMap<String, FieldHash>,
    /// `proton_missing` once the merge is applied.
    pub proton_missing: BTreeSet<String>,
}

impl MergePlan {
    /// Nothing to write, report or record.
    pub fn is_settled(&self, base: &BTreeMap<String, FieldHash>) -> bool {
        self.write_to_op.is_empty()
            && self.op_only_changes.is_empty()
            && self.blocked.is_empty()
            && &self.new_base == base
    }
}

pub fn plan(input: MergeInput<'_>) -> MergePlan {
    let proton = input.proton.field_hashes(input.key);
    let op = input.op.field_hashes(input.key);
    let all: BTreeSet<&String> = input
        .base
        .keys()
        .chain(proton.keys())
        .chain(op.keys())
        .collect();

    let mut plan = MergePlan::default();
    for key in all {
        let base = input.base.get(key);
        let in_proton = proton.get(key);
        let in_op = op.get(key);
        // Still missing from Proton: its absence there is not a change.
        if input.proton_missing.contains(key) && in_proton.is_none() {
            plan.proton_missing.insert(key.clone());
            if let Some(base) = base {
                plan.new_base.insert(key.clone(), base.clone());
            }
            if in_op != base {
                plan.op_only_changes.insert(key.clone());
            }
            continue;
        }
        let proton_changed = in_proton != base;
        let op_changed = in_op != base;
        let agreed = match (proton_changed, op_changed) {
            (false, false) => base,
            (false, true) => {
                plan.op_only_changes.insert(key.clone());
                base
            }
            (true, true) if in_proton == in_op => in_proton,
            (true, op_changed) => {
                if op_changed {
                    plan.conflicts.insert(key.clone());
                }
                if input.op_guarded {
                    plan.blocked.insert(key.clone());
                    base
                } else {
                    plan.write_to_op.insert(key.clone());
                    in_proton
                }
            }
        };
        if let Some(hash) = agreed {
            plan.new_base.insert(key.clone(), hash.clone());
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::record::{FieldKind, Kind};

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn login(fields: &[(&str, &str)]) -> Record {
        let mut record = Record::new(Kind::Login);
        for (key, value) in fields {
            let kind = if *key == "password" {
                FieldKind::Concealed
            } else {
                FieldKind::Text
            };
            record.set(key, *value, kind);
        }
        record
    }

    fn keys(keys: &[&str]) -> BTreeSet<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    struct Case {
        base: Record,
        proton: Record,
        op: Record,
        missing: BTreeSet<String>,
        guarded: bool,
    }

    impl Case {
        fn new(base: Record, proton: Record, op: Record) -> Self {
            Case {
                base,
                proton,
                op,
                missing: BTreeSet::new(),
                guarded: false,
            }
        }

        fn plan(&self) -> MergePlan {
            plan(MergeInput {
                base: &self.base.field_hashes(KEY),
                proton: &self.proton,
                op: &self.op,
                key: KEY,
                proton_missing: &self.missing,
                op_guarded: self.guarded,
            })
        }
    }

    fn agreed() -> Record {
        login(&[("title", "Site"), ("username", "me"), ("password", "old")])
    }

    #[test]
    fn nothing_changed_is_settled() {
        let case = Case::new(agreed(), agreed(), agreed());
        let plan = case.plan();
        assert!(plan.is_settled(&agreed().field_hashes(KEY)), "{plan:?}");
        assert_eq!(plan.new_base, agreed().field_hashes(KEY));
    }

    #[test]
    fn a_proton_change_is_written_to_1password() {
        let proton = login(&[("title", "Site"), ("username", "me"), ("password", "new")]);
        let plan = Case::new(agreed(), proton.clone(), agreed()).plan();
        assert_eq!(plan.write_to_op, keys(&["password"]));
        assert!(plan.op_only_changes.is_empty() && plan.conflicts.is_empty());
        assert_eq!(plan.new_base, proton.field_hashes(KEY));
    }

    #[test]
    fn a_field_removed_in_proton_is_cleared_in_1password() {
        let proton = login(&[("title", "Site"), ("password", "old")]);
        let plan = Case::new(agreed(), proton.clone(), agreed()).plan();
        assert_eq!(plan.write_to_op, keys(&["username"]));
        assert!(!plan.new_base.contains_key("username"));
    }

    #[test]
    fn a_1password_change_is_reported_and_the_base_kept() {
        let op = login(&[("title", "Site"), ("username", "me"), ("password", "newer")]);
        let plan = Case::new(agreed(), agreed(), op).plan();
        assert!(plan.write_to_op.is_empty());
        assert_eq!(plan.op_only_changes, keys(&["password"]));
        // The base stays, so the change is found again until it is applied
        // in Proton.
        assert_eq!(plan.new_base, agreed().field_hashes(KEY));
    }

    #[test]
    fn the_same_change_on_both_sides_agrees() {
        let both = login(&[("title", "Site"), ("username", "me"), ("password", "new")]);
        let plan = Case::new(agreed(), both.clone(), both.clone()).plan();
        assert!(plan.write_to_op.is_empty() && plan.conflicts.is_empty());
        assert!(plan.op_only_changes.is_empty());
        assert_eq!(plan.new_base, both.field_hashes(KEY));
    }

    #[test]
    fn a_conflict_is_won_by_proton_and_reported() {
        let proton = login(&[
            ("title", "Site"),
            ("username", "me"),
            ("password", "proton"),
        ]);
        let op = login(&[
            ("title", "Site"),
            ("username", "me"),
            ("password", "onepass"),
        ]);
        let plan = Case::new(agreed(), proton.clone(), op).plan();
        assert_eq!(plan.write_to_op, keys(&["password"]));
        assert_eq!(plan.conflicts, keys(&["password"]));
        assert_eq!(plan.new_base, proton.field_hashes(KEY));
    }

    #[test]
    fn different_fields_changed_on_each_side_merge() {
        let proton = login(&[("title", "Site 2"), ("username", "me"), ("password", "old")]);
        let op = login(&[
            ("title", "Site"),
            ("username", "me"),
            ("password", "rotated"),
        ]);
        let plan = Case::new(agreed(), proton.clone(), op).plan();
        assert_eq!(plan.write_to_op, keys(&["title"]));
        assert_eq!(plan.op_only_changes, keys(&["password"]));
        assert!(plan.conflicts.is_empty());
        // The title is agreed; the 1Password password stays pending.
        assert_eq!(plan.new_base["title"], proton.field_hashes(KEY)["title"]);
        assert_eq!(
            plan.new_base["password"],
            agreed().field_hashes(KEY)["password"]
        );
    }

    #[test]
    fn a_field_proton_could_not_receive_is_not_a_proton_deletion() {
        // Created from 1Password: the note could not go into Proton.
        let base = login(&[("title", "Site"), ("note", "1P note")]);
        let proton = login(&[("title", "Site")]);
        let mut case = Case::new(base.clone(), proton, base.clone());
        case.missing = keys(&["note"]);
        let plan = case.plan();
        assert!(plan.write_to_op.is_empty(), "{plan:?}");
        assert_eq!(plan.proton_missing, keys(&["note"]));
        assert_eq!(plan.new_base, base.field_hashes(KEY));

        // Once the owner copies it into Proton, it is an ordinary field.
        let proton = login(&[("title", "Site"), ("note", "1P note")]);
        case.proton = proton;
        let plan = case.plan();
        assert!(plan.write_to_op.is_empty());
        assert!(plan.proton_missing.is_empty());
    }

    #[test]
    fn a_guarded_item_is_never_written() {
        let proton = login(&[("title", "Site"), ("username", "me"), ("password", "new")]);
        let mut case = Case::new(agreed(), proton, agreed());
        case.guarded = true;
        let plan = case.plan();
        assert!(plan.write_to_op.is_empty());
        assert_eq!(plan.blocked, keys(&["password"]));
        // Not written, so not agreed: the base stays.
        assert_eq!(plan.new_base, agreed().field_hashes(KEY));
        assert!(!plan.is_settled(&agreed().field_hashes(KEY)));
    }

    #[test]
    fn fields_new_on_one_side_follow_the_same_rules() {
        let proton = login(&[
            ("title", "Site"),
            ("username", "me"),
            ("password", "old"),
            ("email", "e@x"),
        ]);
        let op = login(&[
            ("title", "Site"),
            ("username", "me"),
            ("password", "old"),
            ("x:Mine", "1P"),
        ]);
        let plan = Case::new(agreed(), proton.clone(), op).plan();
        assert_eq!(plan.write_to_op, keys(&["email"]));
        assert_eq!(plan.op_only_changes, keys(&["x:Mine"]));
        assert!(plan.new_base.contains_key("email"));
        assert!(!plan.new_base.contains_key("x:Mine"));
    }
}
