//! One message, refusing what a lenient parser would take (T4).
//!
//! serde_json refuses NaN, a leading zero, a byte order mark and a lone
//! surrogate, and refuses a repeated key only where a struct declares it —
//! `content` twice is an error and `a` twice is not, so how strict it is
//! depends on what this adapter happens to read. A repeat does not survive
//! into a `Value` either, whose map keeps one of them. So that one is read
//! from the bytes, as the other six adapters read it.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::Error;

/// The largest a JavaScript number carries exactly.
const SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Parses one message, or says which leniency it relied on.
pub fn from_str<T: DeserializeOwned>(raw: &str) -> Result<T, Error> {
    no_repeated_keys(raw.as_bytes())?;
    within_range(&serde_json::from_str::<Value>(raw)?)?;
    Ok(serde_json::from_str(raw)?)
}

/// One pass over the bytes, refusing a key an object already carries.
///
/// The delimiters are ASCII and no UTF-8 sequence contains one, so nothing
/// needs decoding to be found. Keys are unescaped before comparison, because
/// `\u0063ontent` and `content` are one key to every parser.
fn no_repeated_keys(raw: &[u8]) -> Result<(), Error> {
    let mut open: Vec<Vec<String>> = Vec::new();
    let mut at = 0;

    while at < raw.len() {
        match raw[at] {
            b'"' => {
                let (literal, next) = string_at(raw, at);
                let mut after = next;
                while after < raw.len() && raw[after].is_ascii_whitespace() {
                    after += 1;
                }
                // A key is a string with a colon after it.
                if after < raw.len() && raw[after] == b':' {
                    if let Some(names) = open.last_mut() {
                        let name = unescape(&literal);
                        if names.contains(&name) {
                            return Err(format!("repeated key {name:?}").into());
                        }
                        names.push(name);
                    }
                }
                at = next;
            }
            b'{' => {
                open.push(Vec::new());
                at += 1;
            }
            b'}' => {
                open.pop();
                at += 1;
            }
            _ => at += 1,
        }
    }
    Ok(())
}

/// Where a string literal ends, skipping what a backslash protects.
fn string_at(raw: &[u8], start: usize) -> (String, usize) {
    let mut at = start + 1;
    while at < raw.len() && raw[at] != b'"' {
        at += if raw[at] == b'\\' { 2 } else { 1 };
    }
    let literal = String::from_utf8_lossy(&raw[start + 1..at.min(raw.len())]).into_owned();
    (literal, (at + 1).min(raw.len()))
}

fn unescape(literal: &str) -> String {
    serde_json::from_str::<String>(&format!("\"{literal}\"")).unwrap_or_else(|_| literal.to_owned())
}

fn within_range(value: &Value) -> Result<(), Error> {
    match value {
        // unsigned_abs, not abs: i64::MIN has no positive counterpart, and
        // abs panics on it in debug and wraps to a negative in release. An
        // integer literal serde could hold in neither i64 nor u64 arrives as
        // a float, which is also outside the range T4 allows.
        Value::Number(number) => {
            let outside = match (number.as_i64(), number.as_u64()) {
                (Some(whole), _) => whole.unsigned_abs() > SAFE_INTEGER as u64,
                (None, Some(whole)) => whole > SAFE_INTEGER as u64,
                (None, None) => {
                    !number.is_f64() || number.as_f64().is_some_and(|n| n.fract() == 0.0)
                }
            };
            if outside {
                return Err(format!("{number} is outside ±(2^53 - 1)").into());
            }
            Ok(())
        }
        Value::Object(members) => members.values().try_for_each(within_range),
        Value::Array(items) => items.iter().try_for_each(within_range),
        _ => Ok(()),
    }
}
