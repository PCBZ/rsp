//! One message, refusing what a lenient parser would take (T4).
//!
//! serde_json already refuses a repeated field, NaN, a leading zero, a byte
//! order mark and a lone surrogate. What it takes and T4 does not is an
//! integer JavaScript would round, which arrives here as a perfectly good
//! i64 and leaves the two sides disagreeing about its value.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::Error;

/// The largest a JavaScript number carries exactly.
const SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Parses one message, or says which leniency it relied on.
pub fn from_str<T: DeserializeOwned>(raw: &str) -> Result<T, Error> {
    within_range(&serde_json::from_str::<Value>(raw)?)?;
    Ok(serde_json::from_str(raw)?)
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
