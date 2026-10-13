//! Holds DATA field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use crate::decode::{Decoded, Field};

/// Closed set of DATA fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    DataSize,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        Kind::DataSize => (
            "Data size",
            "Shows how many captured bytes netmon leaves uninterpreted because it does not decode their format.",
            "",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, _field: &Field, _packet: &Decoded) -> String {
    match key {
        Kind::DataSize => String::new(),
    }
}
