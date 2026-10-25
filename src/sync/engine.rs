//! One sync run: pair the vaults, find what changed on either side from
//! secret-free listings, then create, update, move, pair or delete items,
//! saving the state after every write so a run cut short loses nothing.
//!
//! Proton Pass is the source of truth. What the CLIs cannot do safely is
//! reported instead of done:
//! - edits made in 1Password are reported for the owner to apply in
//!   Proton (pass-cli takes updated values only on its command line);
//! - Proton edits to a 1Password item that may hold a passkey or files are
//!   reported for the owner to apply in 1Password (a template edit would
//!   drop them);
//! - deletions are only ever reversible (Proton trash, 1Password archive),
//!   and none happen in a vault where too many items vanished at once.

use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

use super::api::{OpApi, OpSummary, ProtonApi, ProtonSummary, Vault, op_requests};
use super::merge::{self, MergeInput};
use super::onepassword::OpProblem;
use super::op_json::{self, OpItem, RawItem};
use super::proton_json::{self, ProtonItem};
use super::record::{FieldHash, Record};
use super::report::{Event, Report};
use super::state::{Equivalent, ItemPair, Origin, PendingCopy, State, VaultPair};
use crate::pass_cli::SessionProblem;

#[derive(Debug, Clone)]
pub struct Config {
    /// A Proton vault `X` pairs with the 1Password vault `<prefix>X`.
    pub vault_prefix: String,
    /// Proton vault names to sync; empty: every vault pass-cli shows.
    pub include_vaults: Vec<String>,
    pub exclude_vaults: Vec<String>,
    /// Create a missing 1Password vault (the service account must be
    /// allowed to); otherwise the owner creates it.
    pub create_op_vaults: bool,
    /// 1Password requests allowed per day, counting earlier runs.
    pub op_requests_per_day: usize,
    /// 1Password writes allowed per run (a run every 30 minutes stays
    /// under a service account's 100 writes an hour).
    pub op_writes_per_run: usize,
    /// Deletions in a vault are held when more than this share of its
    /// pairs (and more than `delete_brake_min`) vanish in one run.
    pub delete_brake_ratio: f64,
    pub delete_brake_min: usize,
    pub allow_mass_delete: bool,
    pub dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            vault_prefix: "Proton · ".to_string(),
            include_vaults: Vec::new(),
            exclude_vaults: Vec::new(),
            create_op_vaults: false,
            op_requests_per_day: 900,
            op_writes_per_run: 40,
            delete_brake_ratio: 0.1,
            delete_brake_min: 3,
            allow_mass_delete: false,
            dry_run: false,
        }
    }
}

/// The Proton item a 1Password copy points back to: `share_id/item_id`.
pub fn proton_ref(share: &str, item: &str) -> String {
    format!("{share}/{item}")
}

/// Run one sync. `save` persists the state; it is called after every
/// change to it (never in a dry run). The report comes back even when the
/// run fails: what it holds is already marked reported in the state.
pub fn run(
    proton: &mut dyn ProtonApi,
    op: &mut dyn OpApi,
    state: &mut State,
    key: &[u8],
    config: &Config,
    now: u64,
    save: &mut dyn FnMut(&State) -> Result<()>,
) -> (Report, Result<()>) {
    // The adapter may have made requests before this run; those are not
    // this run's to record.
    let recorded_requests = op.requests();
    let mut engine = Engine {
        proton,
        op,
        state,
        key,
        config,
        now,
        save,
        report: Report {
            dry_run: config.dry_run,
            ..Report::default()
        },
        op_writes: 0,
        op_stopped: false,
        recorded_requests,
        proton_unread: false,
        op_unread: false,
    };
    let result = engine.sync();
    // Whatever happened, count the requests made.
    let saved = engine.persist();
    (engine.report, result.and(saved))
}

/// A vault pair being synced, with both listings.
struct VaultRun {
    proton: Vault,
    op: Vault,
    proton_items: BTreeMap<String, ProtonSummary>,
    op_items: BTreeMap<String, OpSummary>,
}

/// Where a pair stands after listing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Standing {
    Present,
    GoneFromProton,
    GoneFromOp,
    GoneFromBoth,
}

struct Engine<'a> {
    proton: &'a mut dyn ProtonApi,
    op: &'a mut dyn OpApi,
    state: &'a mut State,
    key: &'a [u8],
    config: &'a Config,
    now: u64,
    save: &'a mut dyn FnMut(&State) -> Result<()>,
    report: Report,
    op_writes: usize,
    /// No more 1Password requests this run (rate limit or budget).
    op_stopped: bool,
    /// Of `op.requests()`, how many are already in the state.
    recorded_requests: usize,
    /// Some Proton item, or a whole vault, could not be read this run: a
    /// pair gone from Proton may have moved to it, so is not deleted.
    proton_unread: bool,
    /// The same for 1Password.
    op_unread: bool,
}

/// 1Password's hashes in Proton's form, where the pair knows 1Password
/// stores a value differently.
fn translate(
    mut op: BTreeMap<String, FieldHash>,
    equivalents: &BTreeMap<String, Equivalent>,
) -> BTreeMap<String, FieldHash> {
    for (name, equivalent) in equivalents {
        let current = op.get(name).cloned().unwrap_or_default();
        if current == equivalent.op {
            if equivalent.proton.is_empty() {
                op.remove(name);
            } else {
                op.insert(name.clone(), equivalent.proton.clone());
            }
        }
    }
    op
}

/// For the fields `names`, record where 1Password now stores a value in
/// another form than Proton's (and forget where it no longer does).
fn note_equivalents<'n>(
    equivalents: &mut BTreeMap<String, Equivalent>,
    names: impl IntoIterator<Item = &'n String>,
    proton: &BTreeMap<String, FieldHash>,
    op: &BTreeMap<String, FieldHash>,
) {
    for name in names {
        let in_proton = proton.get(name).cloned().unwrap_or_default();
        let in_op = op.get(name).cloned().unwrap_or_default();
        if in_proton == in_op {
            equivalents.remove(name);
        } else {
            equivalents.insert(
                name.clone(),
                Equivalent {
                    proton: in_proton,
                    op: in_op,
                },
            );
        }
    }
}

fn version_of(raw: &RawItem) -> u64 {
    raw.0.get("version").and_then(|v| v.as_u64()).unwrap_or(0)
}

fn names(set: &BTreeSet<String>) -> Vec<String> {
    set.iter().cloned().collect()
}

impl Engine<'_> {
    fn sync(&mut self) -> Result<()> {
        let mut runs = self.pair_vaults()?;
        let standings = self.standings(&runs);
        let mut unpaired_proton = self.unpaired_proton(&runs);
        let mut unpaired_op = self.unpaired_op(&runs);

        // Contents of the unpaired items: needed to spot moves, to pair
        // items that are already on both sides, and to copy the rest.
        let mut proton_items = self.read_proton(&runs, &unpaired_proton)?;
        let mut op_items = self.read_op(&runs, &unpaired_op)?;

        let mut moved = BTreeSet::new();
        self.find_moves(
            &runs,
            &standings,
            &mut unpaired_proton,
            &mut unpaired_op,
            &mut proton_items,
            &mut op_items,
            &mut moved,
        )?;
        self.pair_existing(
            &runs,
            &mut unpaired_proton,
            &mut unpaired_op,
            &proton_items,
            &op_items,
        )?;
        self.forget_settled_copies(&runs);
        self.copy_to_op(&runs, &unpaired_proton, &proton_items)?;
        self.copy_to_proton(&runs, &unpaired_op, &op_items)?;
        self.update_pairs(&mut runs, &standings, &moved)?;
        self.delete_vanished(&runs, &standings, &moved)?;
        Ok(())
    }

    /// Record the 1Password requests made so far and save the state.
    fn persist(&mut self) -> Result<()> {
        let made = self.op.requests();
        let new = made.saturating_sub(self.recorded_requests);
        if self.config.dry_run {
            return Ok(());
        }
        self.state.record_op_requests(new, self.now);
        self.recorded_requests = made;
        (self.save)(self.state)
    }

    /// Whether `weight` more 1Password requests fit the day's budget, and,
    /// for a write, the run's write budget.
    fn op_allows(&mut self, weight: usize, write: bool) -> bool {
        if self.op_stopped {
            return false;
        }
        let used = self.state.op_requests_today(self.now)
            + self.op.requests().saturating_sub(self.recorded_requests);
        let over_day = used + weight > self.config.op_requests_per_day;
        let over_run = write && self.op_writes >= self.config.op_writes_per_run;
        if over_day || over_run {
            self.op_stopped = true;
            self.report.push(Event::OpStopped(if over_day {
                "1Password's daily request budget is used up; the rest waits for a later run"
                    .to_string()
            } else {
                "this run's 1Password write budget is used up; the rest waits for the next run"
                    .to_string()
            }));
            return false;
        }
        true
    }

    /// Turn a 1Password error into an outcome: a rate limit stops further
    /// requests, a refused token ends the run, anything else is the item's.
    fn op_failed(&mut self, error: anyhow::Error, title: &str) -> Result<()> {
        match error.downcast_ref::<OpProblem>() {
            Some(OpProblem::RateLimited) => {
                if !self.op_stopped {
                    self.report
                        .push(Event::OpStopped(OpProblem::RateLimited.to_string()));
                }
                self.op_stopped = true;
                Ok(())
            }
            Some(OpProblem::NotSignedIn) => Err(error),
            None => {
                self.report.push(Event::ItemFailed {
                    title: title.to_string(),
                    error: format!("{error:#}"),
                });
                Ok(())
            }
        }
    }

    /// A Proton error: a session problem ends the run, anything else is
    /// the item's.
    fn proton_failed(&mut self, error: anyhow::Error, title: &str) -> Result<()> {
        if error.downcast_ref::<SessionProblem>().is_some() {
            return Err(error);
        }
        self.report.push(Event::ItemFailed {
            title: title.to_string(),
            error: format!("{error:#}"),
        });
        Ok(())
    }

    // ---- vaults -----------------------------------------------------------

    fn pair_vaults(&mut self) -> Result<Vec<VaultRun>> {
        let proton_vaults: Vec<Vault> = self
            .proton
            .vaults()?
            .into_iter()
            .filter(|vault| {
                (self.config.include_vaults.is_empty()
                    || self.config.include_vaults.contains(&vault.name))
                    && !self.config.exclude_vaults.contains(&vault.name)
            })
            .collect();
        if !self.op_allows(op_requests::VAULT_LIST, false) {
            return Ok(Vec::new());
        }
        let op_vaults = match self.op.vaults() {
            Ok(vaults) => vaults,
            Err(e) => {
                self.op_failed(e, "1Password vaults")?;
                return Ok(Vec::new());
            }
        };

        let mut runs = Vec::new();
        for proton_vault in proton_vaults {
            let paired = self
                .state
                .vault_for_proton(&proton_vault.id)
                .map(|pair| pair.op_vault.clone());
            let op_vault = match paired {
                Some(id) => match op_vaults.iter().find(|vault| vault.id == id) {
                    Some(vault) => vault.clone(),
                    None => {
                        self.report.push(Event::Vault(format!(
                            "the 1Password vault paired with '{}' is gone, or the service account \
                             can no longer reach it; skipped",
                            crate::text::printable(&proton_vault.name)
                        )));
                        continue;
                    }
                },
                None => match self.pair_new_vault(&proton_vault, &op_vaults)? {
                    Some(vault) => vault,
                    None => continue,
                },
            };
            let proton_items = match self.proton.items(&proton_vault.id) {
                Ok(items) => items,
                Err(e) => {
                    self.proton_unread = true;
                    self.proton_failed(e, &proton_vault.name)?;
                    continue;
                }
            };
            if !self.op_allows(op_requests::ITEM_LIST, false) {
                self.op_unread = true;
                continue;
            }
            let op_items = match self.op.items(&op_vault.id) {
                Ok(items) => items,
                Err(e) => {
                    self.op_unread = true;
                    self.op_failed(e, &op_vault.name)?;
                    continue;
                }
            };
            runs.push(VaultRun {
                proton_items: proton_items
                    .into_iter()
                    .filter(|item| item.active && item.kind.is_some())
                    .map(|item| (item.id.clone(), item))
                    .collect(),
                op_items: op_items
                    .into_iter()
                    .filter(|item| item.kind.is_some())
                    .map(|item| (item.id.clone(), item))
                    .collect(),
                proton: proton_vault,
                op: op_vault,
            });
        }
        Ok(runs)
    }

    /// Pair a Proton vault with `<prefix><name>` in 1Password, creating it
    /// when allowed; `None` when it cannot be paired this run.
    fn pair_new_vault(&mut self, proton: &Vault, op_vaults: &[Vault]) -> Result<Option<Vault>> {
        let name = format!("{}{}", self.config.vault_prefix, proton.name);
        let taken: BTreeSet<&str> = self
            .state
            .vaults
            .iter()
            .map(|p| p.op_vault.as_str())
            .collect();
        let found = op_vaults
            .iter()
            .find(|vault| vault.name == name && !taken.contains(vault.id.as_str()))
            .cloned();
        let vault = match found {
            Some(vault) => vault,
            None if self.config.create_op_vaults && !self.config.dry_run => {
                if !self.op_allows(op_requests::VAULT_CREATE, true) {
                    return Ok(None);
                }
                match self.op.create_vault(&name) {
                    Ok(vault) => {
                        self.op_writes += 1;
                        vault
                    }
                    Err(e) => {
                        self.op_failed(e, &name)?;
                        return Ok(None);
                    }
                }
            }
            None => {
                self.report.push(Event::Vault(format!(
                    "no 1Password vault for Proton's '{}': create one named '{}' and give the \
                     service account read and write access to it",
                    crate::text::printable(&proton.name),
                    crate::text::printable(&name)
                )));
                return Ok(None);
            }
        };
        if !self.config.dry_run {
            self.state.vaults.push(VaultPair {
                proton_share: proton.id.clone(),
                op_vault: vault.id.clone(),
            });
            self.persist()?;
        }
        Ok(Some(vault))
    }

    // ---- listing ----------------------------------------------------------

    fn run_of<'r>(runs: &'r [VaultRun], pair: &ItemPair) -> Option<&'r VaultRun> {
        runs.iter()
            .find(|run| run.proton.id == pair.proton_share && run.op.id == pair.op_vault)
    }

    fn standings(&self, runs: &[VaultRun]) -> Vec<Option<Standing>> {
        self.state
            .items
            .iter()
            .map(|pair| {
                let run = Self::run_of(runs, pair)?;
                let in_proton = run.proton_items.contains_key(&pair.proton_item);
                let in_op = run.op_items.contains_key(&pair.op_item);
                Some(match (in_proton, in_op) {
                    (true, true) => Standing::Present,
                    (false, true) => Standing::GoneFromProton,
                    (true, false) => Standing::GoneFromOp,
                    (false, false) => Standing::GoneFromBoth,
                })
            })
            .collect()
    }

    /// Unpaired Proton items, as (run index, item ID).
    fn unpaired_proton(&self, runs: &[VaultRun]) -> Vec<(usize, String)> {
        let paired: BTreeSet<(&str, &str)> = self
            .state
            .items
            .iter()
            .map(|p| (p.proton_share.as_str(), p.proton_item.as_str()))
            .collect();
        runs.iter()
            .enumerate()
            .flat_map(|(index, run)| {
                run.proton_items
                    .keys()
                    .filter(|id| !paired.contains(&(run.proton.id.as_str(), id.as_str())))
                    .map(move |id| (index, id.clone()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn unpaired_op(&self, runs: &[VaultRun]) -> Vec<(usize, String)> {
        let paired: BTreeSet<(&str, &str)> = self
            .state
            .items
            .iter()
            .map(|p| (p.op_vault.as_str(), p.op_item.as_str()))
            .collect();
        runs.iter()
            .enumerate()
            .flat_map(|(index, run)| {
                run.op_items
                    .keys()
                    .filter(|id| !paired.contains(&(run.op.id.as_str(), id.as_str())))
                    .map(move |id| (index, id.clone()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    // ---- reading ----------------------------------------------------------

    fn read_proton(
        &mut self,
        runs: &[VaultRun],
        items: &[(usize, String)],
    ) -> Result<BTreeMap<(usize, String), ProtonItem>> {
        let mut read = BTreeMap::new();
        for (index, id) in items {
            let run = &runs[*index];
            match self.proton.view(&run.proton.id, id) {
                Ok(Some(item)) if item.active => {
                    read.insert((*index, id.clone()), item);
                }
                Ok(_) => {}
                Err(e) => {
                    self.proton_unread = true;
                    self.proton_failed(e, &run.proton_items[id].title)?;
                }
            }
        }
        Ok(read)
    }

    fn read_op(
        &mut self,
        runs: &[VaultRun],
        items: &[(usize, String)],
    ) -> Result<BTreeMap<(usize, String), OpItem>> {
        let mut read = BTreeMap::new();
        for (index, id) in items {
            if !self.op_allows(op_requests::ITEM_GET, false) {
                self.op_unread = true;
                break;
            }
            let run = &runs[*index];
            match self.op.get(&run.op.id, id) {
                Ok(Some(item)) => {
                    read.insert((*index, id.clone()), item);
                }
                Ok(None) => {}
                Err(e) => {
                    self.op_unread = true;
                    self.op_failed(e, &run.op_items[id].title)?;
                }
            }
        }
        Ok(read)
    }

    /// The base without the fields Proton never received: what Proton's
    /// side should hash to when it has not changed.
    fn proton_side_of(pair: &ItemPair) -> BTreeMap<String, FieldHash> {
        pair.base
            .iter()
            .filter(|(name, _)| !pair.proton_missing.contains(*name))
            .map(|(name, hash)| (name.clone(), hash.clone()))
            .collect()
    }

    /// The 1Password side when it was not read: the base, with the
    /// 1Password-only changes already reported.
    fn op_side_of(pair: &ItemPair) -> BTreeMap<String, FieldHash> {
        let mut op = pair.base.clone();
        for (name, hash) in &pair.reported {
            if name.starts_with('!') {
                continue;
            }
            if hash.is_empty() {
                op.remove(name);
            } else {
                op.insert(name.clone(), hash.clone());
            }
        }
        op
    }

    #[allow(clippy::too_many_arguments)]
    fn find_moves(
        &mut self,
        runs: &[VaultRun],
        standings: &[Option<Standing>],
        unpaired_proton: &mut Vec<(usize, String)>,
        unpaired_op: &mut Vec<(usize, String)>,
        proton_items: &mut BTreeMap<(usize, String), ProtonItem>,
        op_items: &mut BTreeMap<(usize, String), OpItem>,
        moved: &mut BTreeSet<usize>,
    ) -> Result<()> {
        for (index, standing) in standings.iter().enumerate() {
            let pair = self.state.items[index].clone();
            match standing {
                // Gone from its Proton vault: the same item new in another one?
                Some(Standing::GoneFromProton) => {
                    let expected = Self::proton_side_of(&pair);
                    let found = unpaired_proton.iter().position(|(run, id)| {
                        runs[*run].proton.id != pair.proton_share
                            && proton_items.get(&(*run, id.clone())).is_some_and(|item| {
                                item.record.kind == pair.kind
                                    && item.record.field_hashes(self.key) == expected
                            })
                    });
                    let Some(position) = found else { continue };
                    let (run, id) = unpaired_proton.remove(position);
                    proton_items.remove(&(run, id.clone()));
                    moved.insert(index);
                    let target = &runs[run];
                    let title = target.proton_items[&id].title.clone();
                    if self.config.dry_run {
                        self.report.push(Event::Moved {
                            title,
                            to: target.op.name.clone(),
                        });
                        continue;
                    }
                    if !self.op_allows(op_requests::ITEM_MOVE, true) {
                        continue;
                    }
                    // The move forgets the version: a change pq-sync did not
                    // make must be caught now (see `read_pair_op`).
                    let listed = Self::run_of(runs, &pair)
                        .and_then(|run| run.op_items.get(&pair.op_item))
                        .map(|item| item.version);
                    let foreign_change = pair.op_version != 0 && listed != Some(pair.op_version);
                    match self
                        .op
                        .move_item(&pair.op_item, &pair.op_vault, &target.op.id)
                    {
                        Ok(new_id) => {
                            self.op_writes += 1;
                            if foreign_change && !pair.op_guarded {
                                self.report.push(Event::Guarded {
                                    title: title.clone(),
                                });
                            }
                            let pair = &mut self.state.items[index];
                            pair.op_guarded |= foreign_change;
                            pair.proton_share = target.proton.id.clone();
                            pair.proton_item = id.clone();
                            pair.op_vault = target.op.id.clone();
                            pair.op_item = new_id;
                            // Read both sides again next run.
                            pair.op_version = 0;
                            pair.proton_modified = String::new();
                            self.report.push(Event::Moved {
                                title,
                                to: target.op.name.clone(),
                            });
                            self.persist()?;
                        }
                        Err(e) => self.op_failed(e, &title)?,
                    }
                }
                // Gone from its 1Password vault: moved there by the owner?
                Some(Standing::GoneFromOp) => {
                    // With the 1Password changes already reported: the item
                    // as 1Password last had it.
                    let expected = Self::op_side_of(&pair);
                    let found = unpaired_op.iter().position(|(run, id)| {
                        runs[*run].op.id != pair.op_vault
                            && op_items.get(&(*run, id.clone())).is_some_and(|item| {
                                item.record.kind == pair.kind
                                    && translate(
                                        item.record.field_hashes(self.key),
                                        &pair.equivalents,
                                    ) == expected
                            })
                    });
                    let Some(position) = found else { continue };
                    let (run, id) = unpaired_op.remove(position);
                    let item = op_items.remove(&(run, id.clone()));
                    moved.insert(index);
                    let target = &runs[run];
                    let title = target.op_items[&id].title.clone();
                    // Moved by the owner: unless it is just as pq-sync left
                    // it, it may have gained a passkey on the way.
                    let version = target.op_items[&id].version;
                    let unsafe_now = item.is_none_or(|item| item.has_files || item.ambiguous)
                        || pair.op_version == 0
                        || version != pair.op_version;
                    if self.config.dry_run {
                        self.report.push(Event::Moved {
                            title,
                            to: target.proton.name.clone(),
                        });
                        continue;
                    }
                    match self.proton.move_item(
                        &pair.proton_share,
                        &pair.proton_item,
                        &target.proton.id,
                    ) {
                        Ok(new_id) => {
                            if unsafe_now && !pair.op_guarded {
                                self.report.push(Event::Guarded {
                                    title: title.clone(),
                                });
                            }
                            let pair = &mut self.state.items[index];
                            pair.op_guarded |= unsafe_now;
                            pair.proton_share = target.proton.id.clone();
                            pair.proton_item = new_id;
                            pair.op_vault = target.op.id.clone();
                            pair.op_item = id.clone();
                            pair.op_version = version;
                            pair.proton_modified = String::new();
                            self.report.push(Event::Moved {
                                title,
                                to: target.proton.name.clone(),
                            });
                            self.persist()?;
                        }
                        Err(e) => self.proton_failed(e, &title)?,
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Pair unpaired items that are already the same item on both sides:
    /// a 1Password copy pq-sync asked for and never saw made, or one with
    /// the Proton item's content (a reference back to it picks among
    /// several). Only the first may be edited from a template later.
    fn pair_existing(
        &mut self,
        runs: &[VaultRun],
        unpaired_proton: &mut Vec<(usize, String)>,
        unpaired_op: &mut Vec<(usize, String)>,
        proton_items: &BTreeMap<(usize, String), ProtonItem>,
        op_items: &BTreeMap<(usize, String), OpItem>,
    ) -> Result<()> {
        let mut index = 0;
        while index < unpaired_op.len() {
            let (run, op_id) = unpaired_op[index].clone();
            let Some(op_item) = op_items.get(&(run, op_id.clone())) else {
                index += 1;
                continue;
            };
            let share = &runs[run].proton.id;
            let by_ref = op_item.proton_ref.as_deref().and_then(|reference| {
                unpaired_proton
                    .iter()
                    .position(|(r, id)| *r == run && proton_ref(share, id) == reference)
            });
            let op_hashes = op_item.record.field_hashes(self.key);
            // The same item: every field equal, but for those a Proton copy
            // could not have received.
            let uncopyable: BTreeSet<String> = proton_json::create_template(&op_item.record)
                .missing
                .into_iter()
                .collect();
            let content_matches = |id: &String| {
                proton_items.get(&(run, id.clone())).is_some_and(|item| {
                    let proton_hashes = item.record.field_hashes(self.key);
                    let names: BTreeSet<&String> =
                        proton_hashes.keys().chain(op_hashes.keys()).collect();
                    item.record.kind == op_item.record.kind
                        && names.into_iter().all(|name| {
                            match (proton_hashes.get(name), op_hashes.get(name)) {
                                (Some(p), Some(o)) => p == o,
                                (None, Some(_)) => uncopyable.contains(name),
                                _ => false,
                            }
                        })
                })
            };
            // A copy pq-sync asked for and never saw made: its reference
            // is enough, as 1Password may have changed what it was given.
            let asked_for = |id: &String| {
                self.state.pending.contains(&PendingCopy {
                    proton_share: share.clone(),
                    proton_item: id.clone(),
                    op_vault: runs[run].op.id.clone(),
                })
            };
            // Otherwise the reference is item content anyone with access to
            // the item could set: it only picks among items whose content
            // matches.
            let by_ref = by_ref.filter(|&position| {
                let id = &unpaired_proton[position].1;
                asked_for(id) || content_matches(id)
            });
            let by_content = || {
                unpaired_proton
                    .iter()
                    .position(|(r, id)| *r == run && content_matches(id))
            };
            let Some(position) = by_ref.or_else(by_content) else {
                index += 1;
                continue;
            };
            let ours_lost = by_ref == Some(position) && asked_for(&unpaired_proton[position].1);
            let (_, proton_id) = unpaired_proton.remove(position);
            unpaired_op.remove(index);
            let title = runs[run].op_items[&op_id].title.clone();
            self.report.push(Event::Paired {
                title: title.clone(),
            });
            if self.config.dry_run {
                continue;
            }
            if ours_lost && let Some(proton) = proton_items.get(&(run, proton_id.clone())) {
                let mut pair = self.copied_pair(&runs[run], &proton_id, &proton.record, op_item);
                // Its reply was lost: a version past the first is a change
                // pq-sync did not see.
                pair.op_guarded |= version_of(&op_item.raw) > 1;
                self.state
                    .pending
                    .retain(|p| !(p.proton_share == *share && p.proton_item == proton_id));
                self.state.items.push(pair);
                self.persist()?;
                continue;
            }
            let proton_hashes = proton_items
                .get(&(run, proton_id.clone()))
                .map(|item| item.record.field_hashes(self.key))
                .unwrap_or_default();
            let mut base = proton_hashes.clone();
            let mut proton_missing = BTreeSet::new();
            for (name, hash) in &op_hashes {
                if !proton_hashes.contains_key(name) {
                    base.insert(name.clone(), hash.clone());
                    proton_missing.insert(name.clone());
                }
            }
            let mut equivalents = BTreeMap::new();
            note_equivalents(
                &mut equivalents,
                proton_hashes.keys(),
                &proton_hashes,
                &op_hashes,
            );
            self.state.items.push(ItemPair {
                kind: op_item.record.kind,
                origin: if op_item.proton_ref.is_some() {
                    Origin::Proton
                } else {
                    Origin::OnePassword
                },
                proton_share: share.clone(),
                proton_item: proton_id.clone(),
                op_vault: runs[run].op.id.clone(),
                op_item: op_id.clone(),
                proton_modified: runs[run].proton_items[&proton_id].modified.clone(),
                op_version: runs[run].op_items[&op_id].version,
                base,
                proton_missing,
                // Nothing shows pq-sync made it as it is now (a reference is
                // item content anyone could set): it may hold a passkey the
                // CLI cannot show.
                op_guarded: true,
                reported: BTreeMap::new(),
                equivalents,
            });
            self.persist()?;
        }
        Ok(())
    }

    fn copy_to_op(
        &mut self,
        runs: &[VaultRun],
        unpaired: &[(usize, String)],
        items: &BTreeMap<(usize, String), ProtonItem>,
    ) -> Result<()> {
        for (run, id) in unpaired {
            let Some(item) = items.get(&(*run, id.clone())) else {
                continue;
            };
            let target = &runs[*run];
            let title = target.proton_items[id].title.clone();
            if self.config.dry_run {
                self.report.push(Event::CreatedInOp {
                    vault: target.op.name.clone(),
                    title,
                });
                continue;
            }
            let intent = PendingCopy {
                proton_share: target.proton.id.clone(),
                proton_item: id.clone(),
                op_vault: target.op.id.clone(),
            };
            let asked_before = self.state.pending.contains(&intent);
            // The copy asked for last time may be among the items not read.
            if asked_before && self.op_unread {
                continue;
            }
            if !self.op_allows(op_requests::ITEM_CREATE, true) {
                break;
            }
            if !asked_before {
                self.state.pending.push(intent.clone());
                self.persist()?;
            }
            let json = op_json::create_json(&item.record, &proton_ref(&target.proton.id, id));
            match self.op.create(&target.op.id, &json) {
                Ok(created) => {
                    self.op_writes += 1;
                    let pair = self.copied_pair(target, id, &item.record, &created);
                    self.state.pending.retain(|p| *p != intent);
                    self.state.items.push(pair);
                    self.report.push(Event::CreatedInOp {
                        vault: target.op.name.clone(),
                        title,
                    });
                    self.persist()?;
                }
                Err(e) => self.op_failed(e, &title)?,
            }
        }
        Ok(())
    }

    /// The pair for a Proton item and the 1Password copy pq-sync made of
    /// it, noting what 1Password stores differently from what it was given.
    fn copied_pair(
        &self,
        run: &VaultRun,
        proton_id: &str,
        proton: &Record,
        created: &OpItem,
    ) -> ItemPair {
        let proton_hashes = proton.field_hashes(self.key);
        let op_hashes = created.record.field_hashes(self.key);
        let mut equivalents = BTreeMap::new();
        let all: BTreeSet<&String> = proton_hashes.keys().chain(op_hashes.keys()).collect();
        note_equivalents(&mut equivalents, all, &proton_hashes, &op_hashes);
        ItemPair {
            kind: proton.kind,
            origin: Origin::Proton,
            proton_share: run.proton.id.clone(),
            proton_item: proton_id.to_string(),
            op_vault: run.op.id.clone(),
            op_item: created.raw.0["id"].as_str().unwrap_or_default().to_string(),
            proton_modified: run.proton_items[proton_id].modified.clone(),
            op_version: version_of(&created.raw),
            base: proton_hashes,
            proton_missing: BTreeSet::new(),
            op_guarded: created.has_files || created.ambiguous,
            reported: BTreeMap::new(),
            equivalents,
        }
    }

    /// Forget the copies asked for whose Proton item is paired or gone.
    fn forget_settled_copies(&mut self, runs: &[VaultRun]) {
        let State { items, pending, .. } = &mut *self.state;
        pending.retain(|p| {
            let Some(run) = runs
                .iter()
                .find(|run| run.proton.id == p.proton_share && run.op.id == p.op_vault)
            else {
                return true;
            };
            run.proton_items.contains_key(&p.proton_item)
                && !items
                    .iter()
                    .any(|i| i.proton_share == p.proton_share && i.proton_item == p.proton_item)
        });
    }

    fn copy_to_proton(
        &mut self,
        runs: &[VaultRun],
        unpaired: &[(usize, String)],
        items: &BTreeMap<(usize, String), OpItem>,
    ) -> Result<()> {
        for (run, id) in unpaired {
            let Some(item) = items.get(&(*run, id.clone())) else {
                continue;
            };
            let target = &runs[*run];
            let title = target.op_items[id].title.clone();
            let template = proton_json::create_template(&item.record);
            if self.config.dry_run {
                self.report.push(Event::CreatedInProton {
                    vault: target.proton.name.clone(),
                    title,
                    missing: template.missing.clone(),
                });
                continue;
            }
            let proton_id = match self.proton.create(&target.proton.id, &template) {
                Ok(proton_id) => proton_id,
                Err(e) => {
                    self.proton_failed(e, &title)?;
                    continue;
                }
            };
            let op_hashes = item.record.field_hashes(self.key);
            let missing: BTreeSet<String> = template.missing.iter().cloned().collect();
            // How Proton stored it; failing that, what was sent.
            let proton_hashes = match self.proton.view(&target.proton.id, &proton_id) {
                Ok(Some(created)) => created.record.field_hashes(self.key),
                _ => op_hashes
                    .iter()
                    .filter(|(name, _)| !missing.contains(*name))
                    .map(|(name, hash)| (name.clone(), hash.clone()))
                    .collect(),
            };
            let mut base = proton_hashes.clone();
            for name in &missing {
                if let Some(hash) = op_hashes.get(name) {
                    base.insert(name.clone(), hash.clone());
                }
            }
            let mut equivalents = BTreeMap::new();
            let carried: BTreeSet<&String> = proton_hashes
                .keys()
                .chain(op_hashes.keys().filter(|name| !missing.contains(*name)))
                .collect();
            note_equivalents(&mut equivalents, carried, &proton_hashes, &op_hashes);
            self.state.items.push(ItemPair {
                kind: item.record.kind,
                origin: Origin::OnePassword,
                proton_share: target.proton.id.clone(),
                proton_item: proton_id,
                op_vault: target.op.id.clone(),
                op_item: id.clone(),
                proton_modified: String::new(),
                op_version: target.op_items[id].version,
                base,
                proton_missing: missing,
                // Made in 1Password: it may hold a passkey the CLI cannot show.
                op_guarded: true,
                reported: BTreeMap::new(),
                equivalents,
            });
            self.report.push(Event::CreatedInProton {
                vault: target.proton.name.clone(),
                title,
                missing: template.missing,
            });
            self.persist()?;
        }
        Ok(())
    }

    fn update_pairs(
        &mut self,
        runs: &mut [VaultRun],
        standings: &[Option<Standing>],
        moved: &BTreeSet<usize>,
    ) -> Result<()> {
        for (index, standing) in standings.iter().enumerate() {
            if *standing != Some(Standing::Present) || moved.contains(&index) {
                continue;
            }
            let mut pair = self.state.items[index].clone();
            let Some(run) = Self::run_of(runs, &pair) else {
                continue;
            };
            let proton_summary = run.proton_items[&pair.proton_item].clone();
            let op_summary = run.op_items[&pair.op_item].clone();
            let proton_changed = proton_summary.modified != pair.proton_modified;
            let op_changed = op_summary.version != pair.op_version;
            if !proton_changed && !op_changed {
                continue;
            }
            let title = proton_summary.title.clone();

            let mut proton_record = None;
            let proton_hashes = if proton_changed {
                match self.proton.view(&pair.proton_share, &pair.proton_item) {
                    Ok(Some(item)) if item.active => {
                        let hashes = item.record.field_hashes(self.key);
                        proton_record = Some(item.record);
                        hashes
                    }
                    // Gone since the listing: the next run sees it.
                    Ok(_) => continue,
                    Err(e) => {
                        self.proton_failed(e, &title)?;
                        continue;
                    }
                }
            } else {
                Self::proton_side_of(&pair)
            };

            let mut op_item = None;
            let mut newly_guarded = false;
            let mut op_hashes = Self::op_side_of(&pair);
            if op_changed {
                match self.read_pair_op(&mut pair, &title, &mut newly_guarded)? {
                    Some((item, hashes)) => {
                        op_hashes = hashes;
                        op_item = Some(item);
                    }
                    None => continue,
                }
            }
            let mut plan = merge::plan(MergeInput {
                base: &pair.base,
                proton: &proton_hashes,
                op: &op_hashes,
                proton_missing: &pair.proton_missing,
                op_guarded: pair.op_guarded,
            });
            // A write needs the item as 1Password has it now.
            if !plan.write_to_op.is_empty() && op_item.is_none() {
                match self.read_pair_op(&mut pair, &title, &mut newly_guarded)? {
                    Some((item, hashes)) => {
                        op_hashes = hashes;
                        op_item = Some(item);
                    }
                    None => continue,
                }
                plan = merge::plan(MergeInput {
                    base: &pair.base,
                    proton: &proton_hashes,
                    op: &op_hashes,
                    proton_missing: &pair.proton_missing,
                    op_guarded: pair.op_guarded,
                });
            }
            if newly_guarded {
                self.report.push(Event::Guarded {
                    title: title.clone(),
                });
            }

            let mut wrote = false;
            if !plan.write_to_op.is_empty() {
                let (Some(record), Some(item)) = (&proton_record, &op_item) else {
                    continue;
                };
                if self.config.dry_run {
                    self.report.push(Event::UpdatedOp {
                        title: title.clone(),
                        fields: names(&plan.write_to_op),
                    });
                    continue;
                }
                if !self.op_allows(op_requests::ITEM_EDIT, true) {
                    continue;
                }
                let mut raw = item.raw.clone();
                if let Err(e) = op_json::apply_edit(&mut raw, record, &plan.write_to_op) {
                    self.report.push(Event::ItemFailed {
                        title: title.clone(),
                        error: format!("{e:#}"),
                    });
                    continue;
                }
                match self.op.edit(&pair.op_vault, &pair.op_item, &raw) {
                    Ok(edited) => {
                        self.op_writes += 1;
                        wrote = true;
                        let after = edited.record.field_hashes(self.key);
                        note_equivalents(
                            &mut pair.equivalents,
                            &plan.write_to_op,
                            &proton_hashes,
                            &after,
                        );
                        pair.op_version = version_of(&edited.raw);
                        self.report.push(Event::UpdatedOp {
                            title: title.clone(),
                            fields: names(&plan.write_to_op),
                        });
                    }
                    Err(e) => {
                        self.op_failed(e, &title)?;
                        continue;
                    }
                }
            }

            pair.base = plan.new_base.clone();
            pair.proton_missing = plan.proton_missing.clone();
            if !plan.conflicts.is_empty() {
                self.report.push(Event::Conflict {
                    title: title.clone(),
                    fields: names(&plan.conflicts),
                });
            }
            // Every field where 1Password is left differing from the base
            // (its own change, or one that lost a conflict it could not be
            // told of), so `op_side_of` stands for it when it is not read.
            let mut reported = BTreeMap::new();
            let fields: BTreeSet<&String> = op_hashes.keys().chain(plan.new_base.keys()).collect();
            for name in fields {
                let in_op = op_hashes.get(name);
                if !plan.write_to_op.contains(name) && in_op != plan.new_base.get(name) {
                    reported.insert(name.clone(), in_op.cloned().unwrap_or_default());
                }
            }
            let new_op_changes: Vec<String> = plan
                .op_only_changes
                .iter()
                .filter(|name| pair.reported.get(*name) != reported.get(*name))
                .cloned()
                .collect();
            let mut new_blocked = Vec::new();
            for name in &plan.blocked {
                let marker = format!("!{name}");
                let hash = proton_hashes.get(name).cloned().unwrap_or_default();
                if pair.reported.get(&marker) != Some(&hash) {
                    new_blocked.push(name.clone());
                }
                reported.insert(marker, hash);
            }
            pair.reported = reported;
            if !new_op_changes.is_empty() {
                self.report.push(Event::OpOnlyChange {
                    title: title.clone(),
                    fields: new_op_changes,
                });
            }
            if !new_blocked.is_empty() {
                self.report.push(Event::Blocked {
                    title: title.clone(),
                    fields: new_blocked,
                });
            }
            // A Proton change not yet written is read again next run.
            if plan.blocked.is_empty() {
                pair.proton_modified = proton_summary.modified.clone();
            }
            if !wrote {
                pair.op_version = op_summary.version;
            }
            if !self.config.dry_run {
                self.state.items[index] = pair;
                self.persist()?;
            }
        }
        Ok(())
    }

    /// Read a pair's 1Password item: its hashes in Proton's form, and
    /// whether it must be guarded from now on. `None` when it cannot be
    /// read this run.
    fn read_pair_op(
        &mut self,
        pair: &mut ItemPair,
        title: &str,
        newly_guarded: &mut bool,
    ) -> Result<Option<(OpItem, BTreeMap<String, FieldHash>)>> {
        if !self.op_allows(op_requests::ITEM_GET, false) {
            return Ok(None);
        }
        let item = match self.op.get(&pair.op_vault, &pair.op_item) {
            Ok(Some(item)) => item,
            Ok(None) => return Ok(None),
            Err(e) => {
                self.op_failed(e, title)?;
                return Ok(None);
            }
        };
        // A change pq-sync did not make may have added a passkey, which
        // `op item get` does not show and a template edit would drop: fail
        // closed and edit the item no more. (pq-sync's own edits record the
        // version they produced; 0 means not known yet.)
        let foreign_change = pair.op_version != 0 && version_of(&item.raw) != pair.op_version;
        if (foreign_change || item.has_files || item.ambiguous) && !pair.op_guarded {
            pair.op_guarded = true;
            *newly_guarded = true;
        }
        let hashes = translate(item.record.field_hashes(self.key), &pair.equivalents);
        Ok(Some((item, hashes)))
    }

    fn delete_vanished(
        &mut self,
        runs: &[VaultRun],
        standings: &[Option<Standing>],
        moved: &BTreeSet<usize>,
    ) -> Result<()> {
        let mut remove = BTreeSet::new();
        let result = self.delete_from_runs(runs, standings, moved, &mut remove);
        // A deletion done stays done, even when a later one ends the run.
        if !self.config.dry_run && !remove.is_empty() {
            for i in remove.into_iter().rev() {
                self.state.items.remove(i);
            }
            self.persist()?;
        }
        result
    }

    /// Delete what vanished, noting in `remove` the pairs that are done.
    fn delete_from_runs(
        &mut self,
        runs: &[VaultRun],
        standings: &[Option<Standing>],
        moved: &BTreeSet<usize>,
        remove: &mut BTreeSet<usize>,
    ) -> Result<()> {
        for (run_index, run) in runs.iter().enumerate() {
            let in_run: Vec<usize> = (0..standings.len())
                .filter(|&i| {
                    standings[i].is_some()
                        && Self::run_of(runs, &self.state.items[i])
                            .is_some_and(|r| std::ptr::eq(r, &runs[run_index]))
                })
                .collect();
            let vanished: Vec<usize> = in_run
                .iter()
                .copied()
                .filter(|i| {
                    !moved.contains(i)
                        && matches!(
                            standings[*i],
                            Some(Standing::GoneFromProton | Standing::GoneFromOp)
                        )
                })
                .collect();
            for &i in &in_run {
                if standings[i] == Some(Standing::GoneFromBoth) && !moved.contains(&i) {
                    remove.insert(i);
                }
            }
            if vanished.is_empty() {
                continue;
            }
            let count = vanished.len();
            let too_many = count > self.config.delete_brake_min
                && count as f64 > self.config.delete_brake_ratio * in_run.len() as f64;
            if too_many && !self.config.allow_mass_delete {
                self.report.push(Event::BrakeHeld {
                    vault: run.proton.name.clone(),
                    vanished: vanished.len(),
                });
                continue;
            }
            for i in vanished {
                let pair = self.state.items[i].clone();
                match standings[i] {
                    // It may have moved to an item that could not be read:
                    // a later run tells.
                    Some(Standing::GoneFromProton) if self.proton_unread => {}
                    Some(Standing::GoneFromOp) if self.op_unread => {}
                    Some(Standing::GoneFromProton) => {
                        let title = run.op_items[&pair.op_item].title.clone();
                        if self.config.dry_run {
                            self.report.push(Event::ArchivedInOp { title });
                            continue;
                        }
                        if !self.op_allows(op_requests::ITEM_ARCHIVE, true) {
                            continue;
                        }
                        match self.op.archive(&pair.op_vault, &pair.op_item) {
                            Ok(()) => {
                                self.op_writes += 1;
                                remove.insert(i);
                                self.report.push(Event::ArchivedInOp { title });
                            }
                            Err(e) => self.op_failed(e, &title)?,
                        }
                    }
                    Some(Standing::GoneFromOp) => {
                        let title = run.proton_items[&pair.proton_item].title.clone();
                        if self.config.dry_run {
                            self.report.push(Event::TrashedInProton { title });
                            continue;
                        }
                        match self.proton.trash(&pair.proton_share, &pair.proton_item) {
                            Ok(()) => {
                                remove.insert(i);
                                self.report.push(Event::TrashedInProton { title });
                            }
                            Err(e) => self.proton_failed(e, &title)?,
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}
