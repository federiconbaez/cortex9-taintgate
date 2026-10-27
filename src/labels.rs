//! Information-flow labels attached to tool outputs and to the content that
//! later reappears in tool-call arguments.

use std::fmt;

/// A small set of labels. Only two exist: `private` (confidential data the
/// user owns) and `untrusted` (content a third party may control).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Labels(u8);

impl Labels {
    pub const NONE: Labels = Labels(0);
    pub const PRIVATE: Labels = Labels(1);
    pub const UNTRUSTED: Labels = Labels(2);

    pub fn union(self, other: Labels) -> Labels {
        Labels(self.0 | other.0)
    }

    pub fn contains(self, other: Labels) -> bool {
        other.0 != 0 && self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn parse(name: &str) -> Result<Labels, String> {
        match name {
            "private" => Ok(Labels::PRIVATE),
            "untrusted" => Ok(Labels::UNTRUSTED),
            other => Err(format!(
                "unknown label {other:?} (expected \"private\" or \"untrusted\")"
            )),
        }
    }

    pub fn parse_all<S: AsRef<str>>(names: &[S]) -> Result<Labels, String> {
        let mut l = Labels::NONE;
        for n in names {
            l = l.union(Labels::parse(n.as_ref())?);
        }
        Ok(l)
    }

    pub fn names(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.contains(Labels::PRIVATE) {
            v.push("private");
        }
        if self.contains(Labels::UNTRUSTED) {
            v.push("untrusted");
        }
        v
    }
}

impl fmt::Debug for Labels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{}}}", self.names().join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_and_contains() {
        let both = Labels::PRIVATE.union(Labels::UNTRUSTED);
        assert!(both.contains(Labels::PRIVATE));
        assert!(both.contains(Labels::UNTRUSTED));
        assert!(!Labels::PRIVATE.contains(Labels::UNTRUSTED));
        assert!(!both.contains(Labels::NONE));
        assert_eq!(Labels::parse_all(&["untrusted", "private"]).unwrap(), both);
        assert!(Labels::parse("secret").is_err());
        assert_eq!(both.names(), vec!["private", "untrusted"]);
    }
}
