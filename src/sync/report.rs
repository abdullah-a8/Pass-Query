//! What a sync run did and what it needs from the owner. Events name items
//! by title (escaped: titles come from shared vaults) and fields by name,
//! never by value.

use std::fmt;

use crate::text::printable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A Proton item now has a 1Password copy.
    CreatedInOp {
        vault: String,
        title: String,
    },
    /// A 1Password item now has a Proton copy; `missing` fields could not
    /// be copied (pass-cli's templates have no slot for them).
    CreatedInProton {
        vault: String,
        title: String,
        missing: Vec<String>,
    },
    /// Proton changes written to 1Password.
    UpdatedOp {
        title: String,
        fields: Vec<String>,
    },
    /// Changed in 1Password only: to apply in Proton by hand.
    OpOnlyChange {
        title: String,
        fields: Vec<String>,
    },
    /// Changed differently on both sides; Proton's value was kept.
    Conflict {
        title: String,
        fields: Vec<String>,
    },
    /// Proton changes not written, because the 1Password item may hold data
    /// the CLI cannot keep: to apply in 1Password by hand.
    Blocked {
        title: String,
        fields: Vec<String>,
    },
    /// The 1Password item changed in a way the CLI cannot show (likely a
    /// passkey was added); pq-sync no longer edits it.
    Guarded {
        title: String,
    },
    ArchivedInOp {
        title: String,
    },
    TrashedInProton {
        title: String,
    },
    Moved {
        title: String,
        to: String,
    },
    /// An unpaired item on each side turned out to be the same item.
    Paired {
        title: String,
    },
    /// Too many items vanished from a vault at once; none was deleted.
    BrakeHeld {
        vault: String,
        vanished: usize,
    },
    /// A vault pq-sync could not pair or reach.
    Vault(String),
    /// One item failed; the run went on.
    ItemFailed {
        title: String,
        error: String,
    },
    /// 1Password's budget or rate limit stopped further requests.
    OpStopped(String),
}

#[derive(Debug, Default)]
pub struct Report {
    pub events: Vec<Event>,
    pub dry_run: bool,
}

impl Report {
    pub fn push(&mut self, event: Event) {
        self.events.push(event);
    }

    /// Whether the owner has something to do.
    pub fn needs_attention(&self) -> bool {
        self.events.iter().any(|event| {
            matches!(
                event,
                Event::OpOnlyChange { .. }
                    | Event::Blocked { .. }
                    | Event::Conflict { .. }
                    | Event::BrakeHeld { .. }
                    | Event::Vault(_)
                    | Event::ItemFailed { .. }
                    | Event::CreatedInProton { .. }
                    | Event::Guarded { .. }
            )
        })
    }
}

fn fields(fields: &[String]) -> String {
    fields
        .iter()
        .map(|field| printable(field.strip_prefix("x:").unwrap_or(field)))
        .collect::<Vec<_>>()
        .join(", ")
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = |title: &str| format!("'{}'", printable(title));
        match self {
            Event::CreatedInOp { vault, title } => {
                write!(f, "+ 1Password: copied {} into {}", t(title), t(vault))
            }
            Event::CreatedInProton {
                vault,
                title,
                missing,
            } => {
                write!(f, "+ Proton: copied {} into {}", t(title), t(vault))?;
                if !missing.is_empty() {
                    write!(
                        f,
                        "; copy by hand (pass-cli cannot set them): {}",
                        fields(missing)
                    )?;
                }
                Ok(())
            }
            Event::UpdatedOp {
                title,
                fields: changed,
            } => {
                write!(f, "~ 1Password: updated {} ({})", t(title), fields(changed))
            }
            Event::OpOnlyChange {
                title,
                fields: changed,
            } => write!(
                f,
                "! {} was changed in 1Password ({}); apply it in Proton Pass, which stays the source",
                t(title),
                fields(changed)
            ),
            Event::Conflict {
                title,
                fields: changed,
            } => write!(
                f,
                "! {} changed on both sides ({}); kept Proton's value (1Password's is in its item history)",
                t(title),
                fields(changed)
            ),
            Event::Blocked {
                title,
                fields: changed,
            } => write!(
                f,
                "! {} changed in Proton ({}) but its 1Password item may hold a passkey or files \
                 the CLI would drop; apply it in 1Password by hand",
                t(title),
                fields(changed)
            ),
            Event::Guarded { title } => write!(
                f,
                "! {} changed in 1Password in a way the CLI cannot show (likely a passkey); \
                 pq-sync will report Proton changes to it instead of writing them",
                t(title)
            ),
            Event::ArchivedInOp { title } => {
                write!(f, "- 1Password: archived {} (gone from Proton)", t(title))
            }
            Event::TrashedInProton { title } => write!(
                f,
                "- Proton: moved {} to the trash (gone from 1Password)",
                t(title)
            ),
            Event::Moved { title, to } => write!(f, "> moved {} to {}", t(title), t(to)),
            Event::Paired { title } => write!(f, "= paired {} (already on both sides)", t(title)),
            Event::BrakeHeld { vault, vanished } => write!(
                f,
                "! {vanished} items vanished from {} at once; nothing was deleted. \
                 If that was intended, run pq-sync with --allow-mass-delete",
                t(vault)
            ),
            Event::Vault(message) => write!(f, "! {message}"),
            Event::ItemFailed { title, error } => {
                write!(f, "! {}: {}", t(title), printable(error))
            }
            Event::OpStopped(reason) => write!(f, "! {reason}"),
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.dry_run {
            writeln!(f, "Dry run: nothing was written.")?;
        }
        if self.events.is_empty() {
            return writeln!(f, "In step: nothing to do.");
        }
        for event in &self.events {
            writeln!(f, "{event}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_escape_titles_and_name_fields_not_values() {
        let event = Event::OpOnlyChange {
            title: "bank\u{1b}]0;x\u{7}".into(),
            fields: vec!["password".into(), "x:API key".into()],
        };
        let shown = event.to_string();
        assert!(!shown.contains('\u{1b}'), "{shown}");
        assert!(shown.contains("password, API key"), "{shown}");
    }

    #[test]
    fn an_empty_report_says_in_step() {
        let report = Report::default();
        assert_eq!(report.to_string(), "In step: nothing to do.\n");
        assert!(!report.needs_attention());
    }
}
