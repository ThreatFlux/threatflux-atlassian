//! GitHub Actions `GITHUB_OUTPUT` re-parser.
//!
//! `output.contains("severity=high")` cannot tell a correct file from one that
//! also carries a forged extra key, so tests assert on the parsed map instead.
//! The grammar here is the runner's, not a convenient approximation of it: the
//! runner reads the file with .NET line splitting, which terminates a line on
//! `\r\n`, `\n` **and a lone `\r`**. A value carrying a bare carriage return
//! therefore escapes its own entry, which is the injection this parser exists to
//! make visible.

use std::collections::BTreeMap;
use std::fmt;

/// A malformed `GITHUB_OUTPUT` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhaOutputError {
    /// A line was neither `name=value` nor a heredoc opener.
    MissingSeparator {
        /// The offending line.
        line: String,
    },
    /// An entry had an empty name.
    EmptyName {
        /// The offending line.
        line: String,
    },
    /// A heredoc opener used an empty delimiter.
    EmptyDelimiter {
        /// The name the heredoc was opened for.
        name: String,
    },
    /// A heredoc opener was never closed by its delimiter.
    UnterminatedHeredoc {
        /// The name the heredoc was opened for.
        name: String,
        /// The delimiter the closing line should have carried.
        delimiter: String,
    },
}

impl fmt::Display for GhaOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator { line } => {
                write!(
                    formatter,
                    "line is neither `name=value` nor `name<<DELIM`: {line:?}"
                )
            }
            Self::EmptyName { line } => write!(formatter, "entry has an empty name: {line:?}"),
            Self::EmptyDelimiter { name } => {
                write!(formatter, "heredoc for {name:?} has an empty delimiter")
            }
            Self::UnterminatedHeredoc { name, delimiter } => write!(
                formatter,
                "heredoc for {name:?} is never closed by {delimiter:?}"
            ),
        }
    }
}

impl std::error::Error for GhaOutputError {}

/// Parses `GITHUB_OUTPUT` contents into entries, in file order.
///
/// Duplicate names are preserved: a forged second value for a name the workflow
/// already set is exactly what a caller needs to see.
pub fn parse_github_output(raw: &str) -> Result<Vec<(String, String)>, GhaOutputError> {
    let lines = split_lines(raw);
    let mut entries = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        index += 1;
        if line.is_empty() {
            continue;
        }

        // Whichever separator appears first wins, as the runner's own file
        // command parser decides it: `q=a<<b` is a key/value pair, not a
        // heredoc opener for the name `q=a`.
        let equals = line.find('=');
        let heredoc = line.find("<<");
        let opens_heredoc = match (equals, heredoc) {
            (Some(equals), Some(heredoc)) => heredoc < equals,
            (None, Some(_)) => true,
            (Some(_), None) => false,
            (None, None) => {
                return Err(GhaOutputError::MissingSeparator {
                    line: line.to_string(),
                })
            }
        };

        if opens_heredoc {
            let at = heredoc.expect("heredoc separator was located");
            let (name, delimiter) = (&line[..at], &line[at + 2..]);
            if name.is_empty() {
                return Err(GhaOutputError::EmptyName {
                    line: line.to_string(),
                });
            }
            if delimiter.is_empty() {
                return Err(GhaOutputError::EmptyDelimiter {
                    name: name.to_string(),
                });
            }

            let mut value = Vec::new();
            loop {
                let Some(current) = lines.get(index) else {
                    return Err(GhaOutputError::UnterminatedHeredoc {
                        name: name.to_string(),
                        delimiter: delimiter.to_string(),
                    });
                };
                index += 1;
                if *current == delimiter {
                    break;
                }
                value.push(*current);
            }
            entries.push((name.to_string(), value.join("\n")));
        } else {
            let at = equals.expect("key/value separator was located");
            let (name, value) = (&line[..at], &line[at + 1..]);
            if name.is_empty() {
                return Err(GhaOutputError::EmptyName {
                    line: line.to_string(),
                });
            }
            entries.push((name.to_string(), value.to_string()));
        }
    }

    Ok(entries)
}

/// Parses `GITHUB_OUTPUT` contents into the map the runner ends up with.
///
/// A repeated name overwrites the earlier value, as the runner's own
/// set-output does.
pub fn github_output_map(raw: &str) -> Result<BTreeMap<String, String>, GhaOutputError> {
    Ok(parse_github_output(raw)?.into_iter().collect())
}

/// Splits on every terminator the runner treats as one, including a lone `\r`.
fn split_lines(raw: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = raw.as_bytes();
    let mut start = 0;
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'\n' => {
                lines.push(&raw[start..index]);
                index += 1;
                start = index;
            }
            b'\r' => {
                lines.push(&raw[start..index]);
                index += if bytes.get(index + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = index;
            }
            _ => index += 1,
        }
    }

    if start < bytes.len() {
        lines.push(&raw[start..]);
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::{github_output_map, parse_github_output, GhaOutputError};

    #[test]
    fn key_value_lines_parse() {
        let map = github_output_map("created=true\nseverity=high\n").expect("should parse");

        assert_eq!(map.len(), 2);
        assert_eq!(map["created"], "true");
        assert_eq!(map["severity"], "high");
    }

    #[test]
    fn empty_values_are_preserved() {
        let map = github_output_map("matched-rule-id=\n").expect("should parse");
        assert_eq!(map["matched-rule-id"], "");
    }

    #[test]
    fn value_containing_an_equals_sign_keeps_it() {
        let map = github_output_map("q=project = \"KAN\"\n").expect("should parse");
        assert_eq!(map["q"], r#"project = "KAN""#);
    }

    #[test]
    fn the_first_separator_on_the_line_decides_the_form() {
        let map = github_output_map("q=a<<b\n").expect("should parse");
        assert_eq!(map["q"], "a<<b");
    }

    #[test]
    fn heredoc_values_join_their_lines() {
        let raw = "body<<EOF\nline one\nline two\nEOF\ncreated=true\n";
        let map = github_output_map(raw).expect("should parse");

        assert_eq!(map["body"], "line one\nline two");
        assert_eq!(map["created"], "true");
    }

    #[test]
    fn heredoc_body_may_contain_an_equals_sign_or_a_partial_delimiter() {
        let raw = "body<<EOF\na=b\nEOFX\nEOF\n";
        let map = github_output_map(raw).expect("should parse");
        assert_eq!(map["body"], "a=b\nEOFX");
    }

    #[test]
    fn crlf_terminators_are_not_part_of_the_value() {
        let map = github_output_map("created=true\r\nseverity=high\r\n").expect("should parse");
        assert_eq!(map["created"], "true");
        assert_eq!(map["severity"], "high");
    }

    #[test]
    fn a_lone_carriage_return_inside_a_value_forges_a_second_entry() {
        let entries = parse_github_output("severity=high\rcreated=true\n").expect("should parse");

        assert_eq!(
            entries,
            vec![
                ("severity".to_string(), "high".to_string()),
                ("created".to_string(), "true".to_string()),
            ],
            "a bare CR terminates the line for the runner, so it must here too"
        );
    }

    #[test]
    fn duplicate_names_are_visible_in_entries_and_last_wins_in_the_map() {
        let raw = "created=false\ncreated=true\n";

        assert_eq!(parse_github_output(raw).expect("should parse").len(), 2);
        assert_eq!(
            github_output_map(raw).expect("should parse")["created"],
            "true"
        );
    }

    #[test]
    fn unterminated_heredoc_is_an_error() {
        let error = parse_github_output("body<<EOF\nline one\n").expect_err("should fail");
        assert_eq!(
            error,
            GhaOutputError::UnterminatedHeredoc {
                name: "body".to_string(),
                delimiter: "EOF".to_string(),
            }
        );
    }

    #[test]
    fn line_without_a_separator_is_an_error() {
        let error = parse_github_output("severity high\n").expect_err("should fail");
        assert_eq!(
            error,
            GhaOutputError::MissingSeparator {
                line: "severity high".to_string()
            }
        );
    }

    #[test]
    fn empty_name_is_an_error() {
        assert_eq!(
            parse_github_output("=high\n").expect_err("should fail"),
            GhaOutputError::EmptyName {
                line: "=high".to_string()
            }
        );
        assert_eq!(
            parse_github_output("<<EOF\nEOF\n").expect_err("should fail"),
            GhaOutputError::EmptyName {
                line: "<<EOF".to_string()
            }
        );
    }

    #[test]
    fn empty_delimiter_is_an_error() {
        assert_eq!(
            parse_github_output("body<<\n\n").expect_err("should fail"),
            GhaOutputError::EmptyDelimiter {
                name: "body".to_string()
            }
        );
    }

    #[test]
    fn blank_lines_between_entries_are_ignored() {
        let map = github_output_map("\ncreated=true\n\nseverity=high\n\n").expect("should parse");
        assert_eq!(map.len(), 2);
    }
}
