//! Taint store: fingerprints of labelled tool outputs, and the scanner that
//! looks for them in later tool-call arguments.
//!
//! Two kinds of fingerprint are kept for every labelled output:
//!
//! * **n-grams**: every window of `ngram` characters of the alphanumeric
//!   skeleton, hashed. A payload hits when at least `min_ngram_hits`
//!   distinct windows of its skeleton are in the store.
//! * **atoms**: short distinctive strings that are shorter than one n-gram
//!   and would otherwise be missed: tokens with digits (codes, account
//!   numbers), digit groups separated by spaces or dashes (phone numbers),
//!   short JSON leaf values ("Spotify Premium") and, optionally, capitalised
//!   or mixed-case words that are not sentence-initial and not common words
//!   ("Spotify", "iPhone"). A payload hits when its skeleton contains one.

use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde_json::Value;

use crate::labels::Labels;
use crate::normalize::{skeleton, variants, Decoders};

#[derive(Debug, Clone)]
pub struct Params {
    pub ngram: usize,
    pub min_ngram_hits: usize,
    pub min_atom: usize,
    pub proper_nouns: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            ngram: 16,
            min_ngram_hits: 1,
            min_atom: 6,
            proper_nouns: true,
        }
    }
}

#[derive(Debug, Clone)]
struct Atom {
    skel: String,
    labels: Labels,
    fragment: usize,
}

/// One match of tainted content inside an argument.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// `"ngram"` or `"atom"`.
    pub kind: &'static str,
    pub labels: Labels,
    /// `server/tool` that produced the matching content.
    pub source: String,
    /// Decoder chain that exposed it (`""` = as sent).
    pub chain: String,
    /// Argument path (`subject`, `recipients[0]`, `*` for the concatenation).
    pub arg: String,
    /// Redacted evidence: first characters of the matched skeleton + length.
    pub evidence: String,
}

#[derive(Default)]
pub struct TaintStore {
    pub params: Params,
    grams: HashMap<u64, (Labels, usize)>,
    atoms: Vec<Atom>,
    atom_index: HashSet<String>,
    sources: Vec<String>,
    seen: Labels,
}

fn fnv(chars: &[char]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for c in chars {
        let mut buf = [0u8; 4];
        for b in c.encode_utf8(&mut buf).bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

pub fn redact(skel: &str) -> String {
    let head: String = skel.chars().take(4).collect();
    format!("{head}…({} chars)", skel.chars().count())
}

const COMMON_WORDS: &[&str] = &[
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "hello",
    "dear",
    "thanks",
    "thank",
    "please",
    "regards",
    "best",
    "about",
    "after",
    "again",
    "before",
    "could",
    "would",
    "should",
    "there",
    "their",
    "these",
    "those",
    "which",
    "while",
    "where",
    "today",
    "tomorrow",
    "subject",
    "meeting",
    "update",
    "project",
    "team",
    "information",
    "important",
    "message",
    "email",
    "account",
    "payment",
    "transaction",
    "total",
    "amount",
    "balance",
    "date",
    "note",
    "notes",
    "file",
    "document",
    "channel",
    "general",
    "random",
    "summary",
    "report",
    "invoice",
    "order",
    "the",
    "this",
    "that",
    "your",
    "from",
    "with",
    "user",
    "users",
    "admin",
    "street",
    "avenue",
    "city",
    "country",
];

impl TaintStore {
    pub fn new(params: Params) -> Self {
        Self {
            params,
            ..Default::default()
        }
    }

    /// Union of every label ingested so far in this session.
    pub fn seen(&self) -> Labels {
        self.seen
    }

    pub fn gram_count(&self) -> usize {
        self.grams.len()
    }

    pub fn atom_count(&self) -> usize {
        self.atoms.len()
    }

    /// Record a labelled tool result. Returns the number of texts ingested.
    pub fn ingest_result(&mut self, source: &str, labels: Labels, result: &Value) -> usize {
        let texts = result_texts(result);
        for t in &texts {
            self.ingest_text(source, labels, t);
        }
        texts.len()
    }

    pub fn ingest_text(&mut self, source: &str, labels: Labels, text: &str) {
        if labels.is_empty() {
            return;
        }
        self.seen = self.seen.union(labels);
        let frag = self.sources.len();
        self.sources.push(source.to_string());

        let sk: Vec<char> = skeleton(text).chars().collect();
        let n = self.params.ngram;
        if sk.len() >= n {
            for w in sk.windows(n) {
                let e = self.grams.entry(fnv(w)).or_insert((Labels::NONE, frag));
                e.0 = e.0.union(labels);
            }
        }

        let mut atoms = Vec::new();
        atoms.extend(digit_tokens(text, self.params.min_atom));
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            if v.is_object() || v.is_array() {
                let mut leaves = Vec::new();
                json_leaves(&v, "", &mut leaves);
                atoms.extend(leaves.into_iter().map(|(_, s)| skeleton(&s)));
            }
        }
        if self.params.proper_nouns {
            atoms.extend(proper_nouns(text));
        }
        // Long digit-bearing tokens also contribute their short prefixes and
        // suffixes so a split across later calls can still match.
        let mut expanded = atoms;
        let mut extras = Vec::new();
        for a in &expanded {
            let len = a.chars().count();
            if len >= n && a.chars().any(|c| c.is_numeric()) {
                let chars: Vec<char> = a.chars().collect();
                for len_a in self.params.min_atom.max(5)..n {
                    extras.push(chars[..len_a].iter().collect());
                    extras.push(chars[len - len_a..].iter().collect());
                }
            }
        }
        expanded.extend(extras);
        for a in expanded {
            let len = a.chars().count();
            // shorter than 5 is too common to be distinctive; n or longer is
            // already covered by the n-grams of the same text
            if len < 5 || len >= n {
                continue;
            }
            if self.atom_index.insert(a.clone()) {
                self.atoms.push(Atom {
                    skel: a,
                    labels,
                    fragment: frag,
                });
            } else if let Some(at) = self.atoms.iter_mut().find(|x| x.skel == a) {
                at.labels = at.labels.union(labels);
            }
        }
    }

    /// Scan one argument text (and its decoded variants).
    pub fn scan(&self, arg: &str, text: &str, decoders: &Decoders) -> Vec<Hit> {
        let mut hits = Vec::new();
        for (chain, t) in variants(text, decoders) {
            self.scan_skeleton(arg, &chain, &skeleton(&t), &mut hits);
        }
        hits
    }

    /// Scan an already-normalised skeleton (used for accumulated payloads).
    pub fn scan_skeleton(&self, arg: &str, chain: &str, sk: &str, hits: &mut Vec<Hit>) {
        self.scan_skeleton_from(arg, chain, sk, 0, hits)
    }

    /// Like [`scan_skeleton`](Self::scan_skeleton) but only reports matches
    /// that end after character `from`, i.e. that involve the part of `sk`
    /// after an already-delivered prefix.
    pub fn scan_skeleton_from(
        &self,
        arg: &str,
        chain: &str,
        sk: &str,
        from: usize,
        hits: &mut Vec<Hit>,
    ) {
        let chars: Vec<char> = sk.chars().collect();
        let n = self.params.ngram;
        if chars.len() >= n {
            let mut seen_h = HashSet::new();
            let mut labels = Labels::NONE;
            let mut first: Option<(usize, usize)> = None;
            for (i, w) in chars.windows(n).enumerate() {
                if i + n <= from {
                    continue;
                }
                let h = fnv(w);
                if let Some((l, frag)) = self.grams.get(&h) {
                    if seen_h.insert(h) {
                        labels = labels.union(*l);
                        if first.is_none() {
                            first = Some((i, *frag));
                        }
                    }
                }
            }
            if seen_h.len() >= self.params.min_ngram_hits {
                if let Some((i, frag)) = first {
                    let ev: String = chars[i..i + n].iter().collect();
                    hits.push(Hit {
                        kind: "ngram",
                        labels,
                        source: self.sources[frag].clone(),
                        chain: chain.to_string(),
                        arg: arg.to_string(),
                        evidence: redact(&ev),
                    });
                }
            }
        }
        for a in &self.atoms {
            let involved = sk
                .match_indices(a.skel.as_str())
                .any(|(b, m)| sk[..b + m.len()].chars().count() > from);
            if involved {
                hits.push(Hit {
                    kind: "atom",
                    labels: a.labels,
                    source: self.sources[a.fragment].clone(),
                    chain: chain.to_string(),
                    arg: arg.to_string(),
                    evidence: redact(&a.skel),
                });
            }
        }
    }
}

/// Texts of an MCP `tools/call` result: `content[].text`, embedded
/// resource text, and `structuredContent` serialised as JSON.
pub fn result_texts(result: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(items) = result.get("content").and_then(Value::as_array) {
        for it in items {
            if let Some(t) = it.get("text").and_then(Value::as_str) {
                out.push(t.to_string());
            }
            if let Some(t) = it
                .get("resource")
                .and_then(|r| r.get("text"))
                .and_then(Value::as_str)
            {
                out.push(t.to_string());
            }
        }
    }
    if let Some(sc) = result.get("structuredContent") {
        out.push(sc.to_string());
    }
    out
}

/// All string (and integer) leaves with their JSON path.
pub fn json_leaves(v: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => out.push((path.to_string(), s.clone())),
        Value::Number(n) if n.is_i64() || n.is_u64() => out.push((path.to_string(), n.to_string())),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                json_leaves(x, &format!("{path}[{i}]"), out);
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                json_leaves(x, &p, out);
            }
        }
        _ => {}
    }
}

fn digit_tokens(text: &str, min: usize) -> Vec<String> {
    use std::sync::OnceLock;
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    static GROUPS: OnceLock<Regex> = OnceLock::new();
    static DATE: OnceLock<Regex> = OnceLock::new();
    // identifiers joined by - _ . / (codes, IBANs, order ids)
    let token =
        TOKEN.get_or_init(|| Regex::new(r"[\p{L}\p{N}]+(?:[\-_./][\p{L}\p{N}]+)*").unwrap());
    // digit groups separated by spaces, dashes, dots or parentheses (phones)
    let groups = GROUPS.get_or_init(|| Regex::new(r"\p{N}+(?:[ \-.()/]+\p{N}+)+").unwrap());
    // dates and times are shared by unrelated texts all the time
    let date = DATE.get_or_init(|| {
        Regex::new(r"^(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|\d{1,2}:\d{2}(?::\d{2})?)$")
            .unwrap()
    });
    token
        .find_iter(text)
        .chain(groups.find_iter(text))
        .map(|m| m.as_str())
        .filter(|t| t.chars().any(|c| c.is_numeric()) && !date.is_match(t.trim()))
        .map(skeleton)
        .filter(|s| s.chars().count() >= min)
        .collect()
}

fn proper_nouns(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut sentence_start = true;
    let mut word = String::new();
    let flush = |word: &mut String, sentence_start: bool, out: &mut Vec<String>| {
        if word.chars().count() >= 5
            && word.chars().any(|c| c.is_uppercase())
            && !(sentence_start && word.chars().skip(1).all(|c| !c.is_uppercase()))
        {
            let lower = word.to_lowercase();
            if !COMMON_WORDS.contains(&lower.as_str()) {
                out.push(lower);
            }
        }
        word.clear();
    };
    for c in text.chars() {
        if c.is_alphabetic() {
            word.push(c);
            continue;
        }
        if !word.is_empty() {
            flush(&mut word, sentence_start, &mut out);
            sentence_start = false;
        }
        if ".!?:\n\"".contains(c) {
            sentence_start = true;
        } else if c.is_ascii_digit() {
            sentence_start = false;
        }
    }
    if !word.is_empty() {
        flush(&mut word, sentence_start, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store() -> TaintStore {
        let mut s = TaintStore::new(Params::default());
        s.ingest_text(
            "bank/get_transactions",
            Labels::PRIVATE,
            "2022-03-04 Spotify Premium 50.00 to SE3550000000054910000003. \
             Call me at +1 555 0100. Your security code is 463820.",
        );
        s
    }

    #[test]
    fn ngram_and_atoms_hit() {
        let s = store();
        let d = Decoders::none();
        let h = s.scan("subject", "iban se3550000000054910000003", &d);
        assert!(h
            .iter()
            .any(|h| h.kind == "ngram" && h.labels == Labels::PRIVATE));
        let h = s.scan("subject", "The user is subscribed to spotify", &d);
        assert!(h.iter().any(|h| h.kind == "atom"), "{h:?}");
        let h = s.scan("body", "code: 463820", &d);
        assert!(h.iter().any(|h| h.kind == "atom"));
        let h = s.scan("body", "phone 15550100", &d);
        assert!(h.iter().any(|h| h.kind == "atom"), "{h:?}");
        assert!(s.scan("body", "lunch at noon on friday", &d).is_empty());
        assert_eq!(s.seen(), Labels::PRIVATE);
    }

    #[test]
    fn decoders_expose_encoded_payloads() {
        use base64::Engine;
        let s = store();
        let enc = base64::engine::general_purpose::STANDARD.encode("SE3550000000054910000003");
        assert!(s.scan("x", &enc, &Decoders::none()).is_empty());
        let h = s.scan("x", &enc, &Decoders::all());
        assert!(h.iter().any(|h| h.chain == "base64"));
    }

    #[test]
    fn evidence_is_redacted() {
        let s = store();
        let h = s.scan("x", "SE3550000000054910000003", &Decoders::none());
        assert!(h.iter().all(|h| !h.evidence.contains("54910000003")));
    }

    #[test]
    fn proper_noun_rules() {
        let p = proper_nouns("Please call Spotify. Meeting with iPhone team at Acme on Monday");
        assert!(p.contains(&"spotify".to_string()));
        assert!(p.contains(&"iphone".to_string()));
        assert!(!p.contains(&"please".to_string()));
        assert!(!p.contains(&"meeting".to_string()));
        assert!(!p.contains(&"monday".to_string()));
    }

    #[test]
    fn extracts_result_texts() {
        let r = json!({"content":[{"type":"text","text":"a"},
            {"type":"resource","resource":{"uri":"x","text":"b"}}],
            "structuredContent":{"k":"v"}});
        assert_eq!(result_texts(&r), vec!["a", "b", "{\"k\":\"v\"}"]);
    }
}
