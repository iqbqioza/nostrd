//! NIP-70: Protected Events.
//!
//! Events carrying a `["-"]` tag must come from authenticated clients and are
//! only delivered to authenticated subscribers.

use crate::event::Event;

pub const PROTECTED_TAG: &str = "-";

/// NIP-70: "When the `"-"` tag is present, that means the event is
/// 'protected'." The canonical marker is the one-element `["-"]`, but the
/// rule keys off the tag *name*, so any tag named `-` marks the event.
///
/// Requiring exactly one element failed open. `["-", "reason"]` — a client
/// adding a note, a version stamping itself, a stray value — read as
/// unprotected, so `validate_base` accepted it from an unauthenticated
/// client and `ws/handler`'s delivery check served it to every subscriber,
/// permanently, retrievable by id. The author's intent was explicit and the
/// relay published it anyway.
///
/// The two ways to be wrong are not symmetric, and that decides the
/// tie-break. Requiring one element leaks: the author asked for protection
/// and got publication. Matching on the name can only withhold an event some
/// other relay would have published — an availability cost, and one the
/// author can undo by removing the tag. A relay that cannot serve the event
/// to its author is an annoyance; one that publishes it to the world is the
/// failure NIP-70 exists to prevent.
pub fn is_protected(event: &Event) -> bool {
    event
        .tags
        .iter()
        .any(|t| t.first().is_some_and(|name| name == PROTECTED_TAG))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: 1,
            tags,
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn protected_detection() {
        assert!(is_protected(&event(vec![vec!["-".into()]])));
        assert!(!is_protected(&event(vec![vec!["p".into(), "x".into()]])));
        assert!(!is_protected(&event(vec![])));
        // A tag *named* `-` marks the event however many values it carries:
        // `["-", "reason"]` used to read as unprotected, so the event was
        // accepted unauthenticated and served to every subscriber.
        assert!(is_protected(&event(vec![vec!["-".into(), "x".into()]])));
        assert!(is_protected(&event(vec![
            vec!["e".into(), "a".repeat(64)],
            vec!["-".into(), "why".into(), "more".into()],
        ])));
        // An empty tag carries no name and marks nothing; `-` must be the
        // whole first element, not a prefix of it.
        assert!(!is_protected(&event(vec![vec![String::new(), "x".into()]])));
        assert!(!is_protected(&event(vec![vec!["--".into()]])));
        assert!(!is_protected(&event(vec![vec!["-x".into()]])));
    }

    /// The leak this rule closes, seen from the predicate both gates
    /// consult. `relay::validate` pins the write path end to end
    /// (`a_multi_value_dash_tag_needs_authentication`).
    #[test]
    fn a_multi_value_dash_tag_is_classified_as_protected() {
        // The exact leak: a `-` tag carrying a value read as unprotected, so
        // the write path accepted it unauthenticated and the delivery path
        // served it to every subscriber.
        assert!(
            is_protected(&event(vec![vec!["-".into(), "reason".into()]])),
            "`[-, reason]` is a NIP-70 marker by tag name"
        );
        // The canonical one-element form still works.
        assert!(is_protected(&event(vec![vec!["-".into()]])));
    }
}
