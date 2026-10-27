//! Text normalisation and the decoders applied to tool-call arguments before
//! they are compared with tainted content.
//!
//! Matching works on a *skeleton*: the lower-cased alphanumeric characters of
//! a string, with everything else removed. That makes case changes,
//! whitespace, punctuation and separators irrelevant. Decoders add extra
//! candidate strings (base64, hex, percent-encoding, rot13, reversal,
//! leetspeak, spelled-out digits) so that a payload that was mechanically
//! re-encoded can still be compared with the original.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;

/// Lower-cased alphanumeric characters only.
pub fn skeleton(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_alphanumeric() {
            for l in c.to_lowercase() {
                out.push(l);
            }
        }
    }
    out
}

/// Which decoders run on arguments. All on by default.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Decoders {
    pub base64: bool,
    pub hex: bool,
    pub percent: bool,
    pub rot13: bool,
    pub reverse: bool,
    pub leet: bool,
    pub number_words: bool,
}

impl Default for Decoders {
    fn default() -> Self {
        Self::all()
    }
}

impl Decoders {
    pub fn all() -> Self {
        Self {
            base64: true,
            hex: true,
            percent: true,
            rot13: true,
            reverse: true,
            leet: true,
            number_words: true,
        }
    }

    pub fn none() -> Self {
        Self {
            base64: false,
            hex: false,
            percent: false,
            rot13: false,
            reverse: false,
            leet: false,
            number_words: false,
        }
    }
}

const MAX_VARIANTS: usize = 48;
const MIN_ENCODED_RUN: usize = 12;

/// The input plus every decoded variant, each tagged with the chain of
/// decoders that produced it (`""` for the input itself). Two levels deep, so
/// e.g. base64 of hex is covered; deduplicated and capped.
pub fn variants(s: &str, d: &Decoders) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![(String::new(), s.to_string())];
    let mut frontier = vec![(String::new(), s.to_string())];
    for _depth in 0..2 {
        let mut next = Vec::new();
        for (chain, text) in &frontier {
            for (name, decoded) in decode_once(text, d) {
                if out.len() >= MAX_VARIANTS {
                    break;
                }
                if out.iter().any(|(_, t)| *t == decoded) {
                    continue;
                }
                let c = if chain.is_empty() {
                    name.to_string()
                } else {
                    format!("{chain}+{name}")
                };
                out.push((c.clone(), decoded.clone()));
                next.push((c, decoded));
            }
        }
        frontier = next;
    }
    out
}

fn decode_once(s: &str, d: &Decoders) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    if d.base64 {
        if let Some(t) = decode_base64_runs(s) {
            v.push(("base64", t));
        }
    }
    if d.hex {
        if let Some(t) = decode_hex_runs(s) {
            v.push(("hex", t));
        }
    }
    if d.percent {
        if let Some(t) = percent_decode(s) {
            v.push(("percent", t));
        }
    }
    if d.rot13 {
        v.push(("rot13", rot13(s)));
    }
    if d.reverse {
        v.push(("reverse", s.chars().rev().collect()));
    }
    if d.leet && s.chars().any(|c| "013457@$".contains(c)) {
        v.push(("leet", unleet(s)));
    }
    if d.number_words {
        if let Some(t) = number_words(s) {
            v.push(("number_words", t));
        }
    }
    v
}

fn printable(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.is_empty() {
        return None;
    }
    let total = s.chars().count();
    let ok = s
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .count();
    if ok * 100 >= total * 90 {
        Some(s.to_string())
    } else {
        None
    }
}

fn runs<F: Fn(char) -> bool>(s: &str, accept: F, min: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in s.char_indices() {
        if accept(c) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(st) = start.take() {
            if i - st >= min {
                out.push(&s[st..i]);
            }
        }
    }
    if let Some(st) = start {
        if s.len() - st >= min {
            out.push(&s[st..]);
        }
    }
    out
}

/// Decode every base64-looking run (standard or URL-safe alphabet, padding
/// optional) and join the decodings that are printable UTF-8.
pub fn decode_base64_runs(s: &str) -> Option<String> {
    // '=' is only padding, so it ends a run (and `key=value` splits cleanly)
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || "+/-_".contains(c);
    let mut parts = Vec::new();
    for run in runs(s, is_b64, MIN_ENCODED_RUN) {
        let trimmed = run;
        let engine = if trimmed.contains('-') || trimmed.contains('_') {
            &URL_SAFE_NO_PAD
        } else {
            &STANDARD_NO_PAD
        };
        if let Ok(bytes) = engine.decode(trimmed) {
            if let Some(t) = printable(&bytes) {
                parts.push(t);
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

pub fn decode_hex_runs(s: &str) -> Option<String> {
    let mut parts = Vec::new();
    for run in runs(s, |c| c.is_ascii_hexdigit(), MIN_ENCODED_RUN) {
        let run = if run.len() % 2 == 1 {
            &run[..run.len() - 1]
        } else {
            run
        };
        let bytes: Option<Vec<u8>> = (0..run.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&run[i..i + 2], 16).ok())
            .collect();
        if let Some(t) = bytes.as_deref().and_then(printable) {
            parts.push(t);
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

pub fn percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut changed = false;
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    if !changed {
        return None;
    }
    String::from_utf8(out).ok()
}

pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

pub fn unleet(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '@' => 'a',
            '$' => 's',
            _ => c,
        })
        .collect()
}

const NUMBER_WORDS: [&str; 10] = [
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
];

/// Replace spelled-out digits ("four-six-three") with the digits themselves.
pub fn number_words(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String, changed: &mut bool| {
        if let Some(d) = NUMBER_WORDS
            .iter()
            .position(|w| w.eq_ignore_ascii_case(word))
        {
            out.push(char::from(b'0' + d as u8));
            *changed = true;
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    for c in s.chars() {
        if c.is_alphabetic() {
            word.push(c);
        } else {
            flush(&mut word, &mut out, &mut changed);
            out.push(c);
        }
    }
    flush(&mut word, &mut out, &mut changed);
    if changed {
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn skeleton_drops_case_space_and_punctuation() {
        assert_eq!(skeleton("  Security-Code: 46 38 20!"), "securitycode463820");
        assert_eq!(skeleton("ÀÉ ü"), "àéü");
    }

    #[test]
    fn base64_runs_inside_text() {
        let enc = STANDARD.encode("the code is 463820");
        let s = format!("payload={enc} thanks");
        assert_eq!(decode_base64_runs(&s).unwrap(), "the code is 463820");
        let url = URL_SAFE_NO_PAD.encode("??>>secret value<<??");
        assert_eq!(decode_base64_runs(&url).unwrap(), "??>>secret value<<??");
        assert!(decode_base64_runs("short").is_none());
    }

    #[test]
    fn hex_percent_rot13_leet_words() {
        assert_eq!(
            decode_hex_runs("x=73656372657420636f6465").unwrap(),
            "secret code"
        );
        assert_eq!(percent_decode("a%20b%2Fc+d").unwrap(), "a b/c d");
        assert!(percent_decode("100%").is_none());
        assert_eq!(rot13(&rot13("Hello")), "Hello");
        assert_eq!(unleet("p4ssw0rd"), "password");
        assert_eq!(
            number_words("four-six-Three 8").unwrap(),
            "4-6-3 8".to_string()
        );
        assert!(number_words("nothing here").is_none());
    }

    #[test]
    fn variants_are_two_levels_deep() {
        let inner = "73656372657420636f6465"; // hex("secret code")
        let outer = STANDARD.encode(inner);
        let v = variants(&outer, &Decoders::all());
        assert!(v
            .iter()
            .any(|(c, t)| c == "base64+hex" && t == "secret code"));
        let none = variants(&outer, &Decoders::none());
        assert_eq!(none.len(), 1);
    }
}
