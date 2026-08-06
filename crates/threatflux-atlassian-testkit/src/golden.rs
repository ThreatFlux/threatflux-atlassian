//! Semantic JSON comparison.
//!
//! Comparison is semantic rather than byte-wise on purpose: `reqwest`
//! serializes a request body in struct field order, which is not stable across
//! refactors, while [`serde_json::Map`] is sorted. Two payloads that differ only
//! in key order are the same request.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde_json::Value;

/// Returns one line per semantic difference, each anchored to a JSON pointer.
///
/// An empty result means the two documents are equal.
pub fn json_diff(actual: &Value, expected: &Value) -> Vec<String> {
    let mut differences = Vec::new();
    walk("", actual, expected, &mut differences);
    differences
}

/// Asserts that two JSON documents are semantically equal.
///
/// # Panics
///
/// Panics with a pointer-anchored diff if they are not.
pub fn assert_json_eq(actual: &Value, expected: &Value) {
    let differences = json_diff(actual, expected);
    assert!(
        differences.is_empty(),
        "JSON documents differ:\n{}",
        differences.join("\n")
    );
}

/// Asserts that two serialized JSON documents are semantically equal.
///
/// # Panics
///
/// Panics if either side fails to parse, or with a pointer-anchored diff if the
/// two documents are not equal.
pub fn assert_json_str_eq(actual: &str, expected: &str) {
    let actual: Value = serde_json::from_str(actual).expect("actual side should be valid JSON");
    let expected: Value =
        serde_json::from_str(expected).expect("expected side should be valid JSON");
    assert_json_eq(&actual, &expected);
}

fn walk(path: &str, actual: &Value, expected: &Value, out: &mut Vec<String>) {
    match (actual, expected) {
        (Value::Object(left), Value::Object(right)) => {
            let keys: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
            for key in keys {
                let mut child = String::with_capacity(path.len() + key.len() + 1);
                let _ = write!(&mut child, "{path}/{key}");
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => walk(&child, left, right, out),
                    (Some(left), None) => out.push(format!("{child}: unexpected key ({left})")),
                    (None, Some(right)) => out.push(format!("{child}: missing key ({right})")),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            if left.len() == right.len() {
                for (index, (left, right)) in left.iter().zip(right.iter()).enumerate() {
                    walk(&format!("{path}/{index}"), left, right, out);
                }
            } else {
                out.push(format!(
                    "{path}: array length {} != {}",
                    left.len(),
                    right.len()
                ));
            }
        }
        _ => {
            if actual != expected {
                let anchor = if path.is_empty() { "" } else { path };
                out.push(format!("{anchor}: {actual} != {expected}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{assert_json_eq, assert_json_str_eq, json_diff};
    use serde_json::json;

    #[test]
    fn key_order_is_not_a_difference() {
        assert_json_str_eq(r#"{"b":1,"a":2}"#, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn scalar_mismatch_is_anchored_to_its_pointer() {
        let differences = json_diff(
            &json!({"fields": {"summary": "a"}}),
            &json!({"fields": {"summary": "b"}}),
        );
        assert_eq!(differences, vec![r#"/fields/summary: "a" != "b""#]);
    }

    #[test]
    fn extra_and_missing_keys_are_reported_separately() {
        let differences = json_diff(&json!({"a": 1}), &json!({"b": 2}));
        assert_eq!(
            differences,
            vec!["/a: unexpected key (1)", "/b: missing key (2)"]
        );
    }

    #[test]
    fn array_length_mismatch_stops_at_the_array() {
        let differences = json_diff(&json!({"labels": ["a"]}), &json!({"labels": ["a", "b"]}));
        assert_eq!(differences, vec!["/labels: array length 1 != 2"]);
    }

    #[test]
    fn array_elements_are_compared_positionally() {
        let differences = json_diff(&json!(["a", "b"]), &json!(["a", "c"]));
        assert_eq!(differences, vec![r#"/1: "b" != "c""#]);
    }

    #[test]
    fn equal_documents_produce_no_diff() {
        assert_json_eq(
            &json!({"a": [1, {"b": null}]}),
            &json!({"a": [1, {"b": null}]}),
        );
    }

    #[test]
    #[should_panic(expected = "JSON documents differ")]
    fn assert_reports_the_diff() {
        assert_json_eq(&json!(1), &json!(2));
    }
}
