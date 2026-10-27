//! Policy file: which downstream servers to start, which tools are sources of
//! `private` / `untrusted` content, which tools are exfiltration-capable
//! sinks, and which destinations of those sinks are trusted.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::labels::Labels;
use crate::normalize::Decoders;

/// What to do when a flow violates the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Refuse the call; the client gets a tool error.
    Block,
    /// Run the approver command; exit status 0 lets the call through.
    Ask,
    /// Let the call through and only record the decision.
    Monitor,
}

/// How tools that match no `[[tool]]` rule are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unknown {
    /// Exfiltration-capable sink with no trusted destination (fail closed).
    Sink,
    /// Neither source nor sink.
    Ignore,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gateway {
    pub mode: Mode,
    /// Lethal trifecta: only fire when untrusted content has been seen in the
    /// session. With `false`, any private data to an untrusted sink fires.
    pub require_untrusted: bool,
    /// Also fire when the destination of a sink (recipient, URL host) was
    /// itself copied from untrusted content while private data was read in
    /// the session, even if no private content is found in the payload.
    pub untrusted_destination: bool,
    pub unknown_tool: Unknown,
    /// Character n-gram length over the alphanumeric skeleton.
    pub ngram: usize,
    /// Minimum distinct matching n-grams in one argument for a hit.
    pub min_ngram_hits: usize,
    /// Minimum skeleton length of an atom (short distinctive token).
    pub min_atom: usize,
    /// Treat capitalised / mixed-case words that are not sentence-initial
    /// and not common words as atoms ("Spotify", "iPhone").
    pub proper_nouns: bool,
    /// Concatenate everything already sent to the same sink destination with
    /// the current payload, so data split across calls still matches.
    pub accumulate: bool,
    pub decoders: Decoders,
    /// Approver command for `mode = "ask"`; receives the decision as JSON on
    /// stdin. Missing approver means deny.
    pub approver: Option<Vec<String>>,
}

impl Default for Gateway {
    fn default() -> Self {
        Self {
            mode: Mode::Block,
            require_untrusted: true,
            untrusted_destination: false,
            unknown_tool: Unknown::Sink,
            ngram: 16,
            min_ngram_hits: 1,
            min_atom: 6,
            proper_nouns: true,
            accumulate: true,
            decoders: Decoders::all(),
            approver: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub name: String,
    /// Spawn this command and speak MCP over its stdin/stdout.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Or connect to this Streamable HTTP endpoint.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    /// Glob over `server/tool`; `*` matches any run of characters.
    #[serde(rename = "match")]
    pub pattern: String,
    /// Labels attached to this tool's output.
    #[serde(default)]
    pub source: Vec<String>,
    /// Exfiltration-capable: its arguments can leave the user's control.
    #[serde(default)]
    pub sink: bool,
    /// Argument names holding a recipient (email, IBAN, user, channel).
    /// Their values are compared with `trusted` and are not scanned as
    /// payload.
    #[serde(default)]
    pub destination: Vec<String>,
    /// Argument names holding a URL: the host is the destination, and the
    /// whole URL is still scanned as payload (query strings leak).
    #[serde(default)]
    pub url_destination: Vec<String>,
    /// Destination globs that are trusted (e.g. `*@example.com`).
    #[serde(default)]
    pub trusted: Vec<String>,
    /// The output inherits the labels found in this call's arguments
    /// (summarisers, formatters, file writes that echo content).
    #[serde(default)]
    pub propagate: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub gateway: Gateway,
    pub server: Vec<Server>,
    pub tool: Vec<ToolRule>,
}

/// The resolved view of one tool.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolClass {
    pub source: Labels,
    pub sink: bool,
    pub destination: Vec<String>,
    pub url_destination: Vec<String>,
    pub trusted: Vec<String>,
    pub propagate: bool,
    /// Index of the matching rule, `None` when the default applied.
    pub rule: Option<usize>,
}

impl Policy {
    pub fn from_toml(text: &str) -> Result<Policy, String> {
        let p: Policy = toml::from_str(text).map_err(|e| e.to_string())?;
        p.validate()?;
        Ok(p)
    }

    pub fn load(path: &Path) -> Result<Policy, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Policy::from_toml(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.gateway.ngram < 4 {
            return Err("gateway.ngram must be >= 4".into());
        }
        if self.gateway.min_ngram_hits == 0 {
            return Err("gateway.min_ngram_hits must be >= 1".into());
        }
        for s in &self.server {
            if s.command.is_some() == s.url.is_some() {
                return Err(format!(
                    "server {:?}: set exactly one of `command` or `url`",
                    s.name
                ));
            }
            if s.name.is_empty() || s.name.contains('/') || s.name.contains("__") {
                return Err(format!(
                    "server name {:?} must be non-empty, without '/' or '__'",
                    s.name
                ));
            }
        }
        for t in &self.tool {
            Labels::parse_all(&t.source)?;
            if !t.sink
                && (!t.destination.is_empty()
                    || !t.url_destination.is_empty()
                    || !t.trusted.is_empty())
            {
                return Err(format!(
                    "tool rule {:?}: destination/trusted only make sense with sink = true",
                    t.pattern
                ));
            }
        }
        Ok(())
    }

    /// First matching rule wins.
    pub fn classify(&self, server: &str, tool: &str) -> ToolClass {
        let key = format!("{server}/{tool}");
        for (i, r) in self.tool.iter().enumerate() {
            if glob(&r.pattern, &key) {
                return ToolClass {
                    source: Labels::parse_all(&r.source).unwrap_or_default(),
                    sink: r.sink,
                    destination: r.destination.clone(),
                    url_destination: r.url_destination.clone(),
                    trusted: r.trusted.clone(),
                    propagate: r.propagate,
                    rule: Some(i),
                };
            }
        }
        ToolClass {
            source: Labels::NONE,
            sink: self.gateway.unknown_tool == Unknown::Sink,
            destination: Vec::new(),
            url_destination: Vec::new(),
            trusted: Vec::new(),
            propagate: false,
            rule: None,
        }
    }
}

/// `*` matches any (possibly empty) run of characters; everything else is
/// literal and case-sensitive.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] != '*' && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching() {
        assert!(glob("*@acme.example", "ana@acme.example"));
        assert!(!glob("*@acme.example", "ana@acme.example.evil"));
        assert!(glob("world/get_*", "world/get_balance"));
        assert!(glob("*", ""));
        assert!(glob("a*b*c", "aXXbYYc"));
        assert!(!glob("a*b*c", "aXXbYY"));
    }

    #[test]
    fn parse_and_classify() {
        let p = Policy::from_toml(
            r#"
            [gateway]
            mode = "ask"
            [[server]]
            name = "w"
            command = ["x"]
            [[tool]]
            match = "w/read_*"
            source = ["private", "untrusted"]
            [[tool]]
            match = "*/send_email"
            sink = true
            destination = ["recipients"]
            trusted = ["*@acme.example"]
            "#,
        )
        .unwrap();
        assert_eq!(p.gateway.mode, Mode::Ask);
        let r = p.classify("w", "read_inbox");
        assert!(r.source.contains(Labels::PRIVATE) && r.source.contains(Labels::UNTRUSTED));
        assert!(!r.sink);
        let s = p.classify("w", "send_email");
        assert!(s.sink && s.rule == Some(1));
        let u = p.classify("w", "mystery");
        assert!(u.sink && u.rule.is_none());
    }

    #[test]
    fn rejects_bad_policies() {
        assert!(Policy::from_toml("[gateway]\nmode = \"maybe\"").is_err());
        assert!(Policy::from_toml("[[server]]\nname = \"a\"").is_err());
        assert!(Policy::from_toml("[[tool]]\nmatch = \"*\"\ndestination = [\"to\"]").is_err());
        assert!(Policy::from_toml("[[tool]]\nmatch = \"*\"\nsource = [\"secret\"]").is_err());
        assert!(Policy::from_toml("[gateway]\ntypo = 1").is_err());
    }
}
