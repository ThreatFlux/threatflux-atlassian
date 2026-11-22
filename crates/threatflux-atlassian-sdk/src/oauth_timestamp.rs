use jiff::{civil::DateTime, tz::Offset, Timestamp};
use regex::Regex;
use serde::{de, Deserialize, Deserializer};
use std::{str::FromStr, sync::LazyLock};

const NANOS_PER_SECOND: u32 = 1_000_000_000;
const SECONDS_PER_GREGORIAN_CYCLE: i64 = 146_097 * 86_400;

// Accept the relaxed RFC 3339 forms supported by previously published SDKs.
static TIMESTAMP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\A\s*(?<year>[+-][0-9]+|[0-9]{1,4})\s*-\s*",
        r"(?<month>[0-9]{1,2})\s*-\s*(?<day>[0-9]{1,2})[Tt ]\s*",
        r"(?<hour>[0-9]{1,2})\s*:\s*(?<minute>[0-9]{1,2})\s*:\s*(?<second>[0-9]{1,2})",
        r"(?:\.(?<fraction>[0-9]+))?\s*",
        r"(?:(?i:z|utc)|(?<sign>[+\-−])(?<offset_hour>[01][0-9]|2[0-3])",
        r"[:\s]*(?<offset_minute>[0-5][0-9]))\s*\z"
    ))
    .expect("OAuth timestamp pattern is valid")
});

/// A UTC instant for OAuth token expiration, ordered by time.
///
/// Parses RFC 3339 strings, including the extended signed years from -262143
/// to +262142 that previous SDK versions accepted. UTC offsets are normalized.
/// Fractions retain nanosecond precision, including during a leap second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OAuthTimestamp {
    seconds: i64,
    nanoseconds: u32,
}

/// An invalid or out-of-range OAuth timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or out-of-range OAuth timestamp")]
pub struct ParseOAuthTimestampError;

impl OAuthTimestamp {
    /// Earliest supported instant at the start of UTC year -262143.
    pub const MIN: Self = Self {
        seconds: -8_334_601_228_800,
        nanoseconds: 0,
    };

    /// Latest supported instant, including a leap second at the end of UTC year +262142.
    pub const MAX: Self = Self {
        seconds: 8_210_266_876_799,
        nanoseconds: 1_999_999_999,
    };

    /// Constructs an instant from Unix seconds and fractional nanoseconds.
    ///
    /// For a leap second, use the preceding Unix second ending in `:59` and
    /// pass 1,000,000,000 plus the fractional nanoseconds.
    pub const fn from_unix_parts(seconds: i64, nanoseconds: u32) -> Option<Self> {
        if seconds < Self::MIN.seconds
            || seconds > Self::MAX.seconds
            || nanoseconds > Self::MAX.nanoseconds
            || (nanoseconds >= NANOS_PER_SECOND && seconds.rem_euclid(60) != 59)
        {
            return None;
        }
        Some(Self {
            seconds,
            nanoseconds,
        })
    }

    /// Returns Unix seconds and fractional nanoseconds in the constructor's representation.
    pub const fn to_unix_parts(self) -> (i64, u32) {
        (self.seconds, self.nanoseconds)
    }

    pub(crate) fn now() -> Self {
        let nanoseconds = Timestamp::now().as_nanosecond();
        let divisor = i128::from(NANOS_PER_SECOND);
        Self {
            seconds: i64::try_from(nanoseconds.div_euclid(divisor))
                .expect("Jiff whole seconds fit in i64"),
            nanoseconds: u32::try_from(nanoseconds.rem_euclid(divisor))
                .expect("the remainder is less than one second"),
        }
    }

    pub(crate) fn checked_add_seconds(self, seconds: i64) -> Option<Self> {
        Self::from_unix_parts(self.seconds.checked_add(seconds)?, self.nanoseconds)
    }
}

impl FromStr for OAuthTimestamp {
    type Err = ParseOAuthTimestampError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let fields = TIMESTAMP_PATTERN
            .captures(value)
            .ok_or(ParseOAuthTimestampError)?;
        let year: i32 = fields["year"]
            .parse()
            .map_err(|_| ParseOAuthTimestampError)?;
        if !(-262_143..=262_142).contains(&year) {
            return Err(ParseOAuthTimestampError);
        }
        let number = |field: &str| {
            fields[field]
                .parse::<i8>()
                .map_err(|_| ParseOAuthTimestampError)
        };
        let second = number("second")?;
        let leap_second = second == 60;

        // The Gregorian calendar repeats every 400 years. Validate the civil
        // fields within Jiff's range, then restore the full year in Unix seconds.
        let cycle = (year - 2000).div_euclid(400);
        let civil_year = i16::try_from(year - cycle * 400).map_err(|_| ParseOAuthTimestampError)?;
        let local = DateTime::new(
            civil_year,
            number("month")?,
            number("day")?,
            number("hour")?,
            number("minute")?,
            second - i8::from(leap_second),
            0,
        )
        .map_err(|_| ParseOAuthTimestampError)?;
        let local_seconds = Offset::UTC
            .to_timestamp(local)
            .map_err(|_| ParseOAuthTimestampError)?
            .as_second();
        let offset = if let Some(sign) = fields.name("sign") {
            let seconds =
                i64::from(number("offset_hour")?) * 3600 + i64::from(number("offset_minute")?) * 60;
            if sign.as_str() == "+" {
                seconds
            } else {
                -seconds
            }
        } else {
            0
        };
        let seconds = local_seconds + i64::from(cycle) * SECONDS_PER_GREGORIAN_CYCLE - offset;

        let fraction = fields.name("fraction").map_or("", |value| value.as_str());
        let nanos = fraction
            .bytes()
            .chain(std::iter::repeat(b'0'))
            .take(9)
            .fold(0, |nanos, digit| nanos * 10 + u32::from(digit - b'0'));
        Self::from_unix_parts(seconds, nanos + u32::from(leap_second) * NANOS_PER_SECOND)
            .ok_or(ParseOAuthTimestampError)
    }
}

impl<'de> Deserialize<'de> for OAuthTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TimestampVisitor;

        impl de::Visitor<'_> for TimestampVisitor {
            type Value = OAuthTimestamp;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an OAuth timestamp string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}
