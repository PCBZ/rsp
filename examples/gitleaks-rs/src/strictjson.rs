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
        Value::Number(number) => match number.as_i64() {
            Some(whole) if whole.abs() > SAFE_INTEGER => {
                Err(format!("{number} is outside ±(2^53 - 1)").into())
            }
            None if number.as_u64().is_some() => {
                Err(format!("{number} is outside ±(2^53 - 1)").into())
            }
            _ => Ok(()),
        },
        Value::Object(members) => members.values().try_for_each(within_range),
        Value::Array(items) => items.iter().try_for_each(within_range),
        _ => Ok(()),
    }
}
