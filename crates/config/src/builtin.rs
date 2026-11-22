//! The policies a profile names without defining them.

/// Surge's and Loon's REJECT variants, built in as `REJECT` is. They reject a connection as it
/// does; the MITM engine answers a request one rejects with the body the name asks for.
pub const REJECT_REPLIES: [&str; 7] = [
    "REJECT-NO-DROP",
    "REJECT-TINYGIF",
    "REJECT-IMG",
    "REJECT-DICT",
    "REJECT-ARRAY",
    "REJECT-200",
    "REJECT-VIDEO",
];

const BASE: [&str; 7] = [
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "PASS-RULE",
    "COMPATIBLE",
    "GLOBAL",
];

pub fn is_builtin(name: &str) -> bool {
    BASE.contains(&name) || REJECT_REPLIES.contains(&name)
}

pub fn names() -> impl Iterator<Item = &'static str> {
    BASE.into_iter().chain(REJECT_REPLIES)
}

/// A REJECT policy by what it does, whichever of its names a profile or module used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Reject,
    Drop,
    NoDrop,
    TinyGif,
    Dict,
    Array,
    Ok200,
}

impl Reject {
    /// `REJECT-IMG` is Loon's `REJECT-TINYGIF` and `REJECT-VIDEO` its `REJECT-200`.
    pub fn named(name: &str) -> Option<Reject> {
        Some(match name {
            "REJECT" => Reject::Reject,
            "REJECT-DROP" => Reject::Drop,
            "REJECT-NO-DROP" => Reject::NoDrop,
            "REJECT-TINYGIF" | "REJECT-IMG" => Reject::TinyGif,
            "REJECT-DICT" => Reject::Dict,
            "REJECT-ARRAY" => Reject::Array,
            "REJECT-200" | "REJECT-VIDEO" => Reject::Ok200,
            _ => return None,
        })
    }

    /// Surge's name for it.
    pub fn name(self) -> &'static str {
        match self {
            Reject::Reject => "REJECT",
            Reject::Drop => "REJECT-DROP",
            Reject::NoDrop => "REJECT-NO-DROP",
            Reject::TinyGif => "REJECT-TINYGIF",
            Reject::Dict => "REJECT-DICT",
            Reject::Array => "REJECT-ARRAY",
            Reject::Ok200 => "REJECT-200",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reject_name_reads_as_a_reject_that_keeps_its_surge_name() {
        for name in REJECT_REPLIES.into_iter().chain(["REJECT", "REJECT-DROP"]) {
            let reject = Reject::named(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(Reject::named(reject.name()), Some(reject), "{name}");
        }
        assert_eq!(Reject::named("DIRECT"), None);
    }
}
