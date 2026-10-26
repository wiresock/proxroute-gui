//! Parsing and evaluation for `when` time-window predicates.
//!
//! Shared by config validation (which rejects malformed specs) and the routing
//! matcher (which evaluates them against the local clock), so both agree on the
//! accepted syntax — mirroring how [`crate::validate::parse_port_spec`] is shared.
//!
//! - **days** — a weekday `"Mon".."Sun"` (case-insensitive, 3-letter) or an
//!   inclusive range `"Mon-Fri"`. A reversed range wraps the week (`"Fri-Mon"` =
//!   Fri, Sat, Sun, Mon).
//! - **hours** — a window `"HH:MM-HH:MM"` (24-hour). `start > end` wraps past
//!   midnight (`"22:00-06:00"`); the end is exclusive. A zero-length `start == end`
//!   window never matches and is rejected by validation.

use crate::schema::TimeMatch;

/// Map a 3-letter weekday token to a Monday=0..Sunday=6 index.
fn weekday_index(s: &str) -> Option<u8> {
    match s.trim().to_ascii_lowercase().as_str() {
        "mon" => Some(0),
        "tue" => Some(1),
        "wed" => Some(2),
        "thu" => Some(3),
        "fri" => Some(4),
        "sat" => Some(5),
        "sun" => Some(6),
        _ => None,
    }
}

/// Parse a day spec (`"Mon"` or `"Mon-Fri"`) into an inclusive `(lo, hi)` weekday
/// range (Monday=0). `lo > hi` denotes a week-wrapping range.
pub fn parse_day_spec(spec: &str) -> Option<(u8, u8)> {
    match spec.split_once('-') {
        Some((lo, hi)) => Some((weekday_index(lo)?, weekday_index(hi)?)),
        None => {
            let d = weekday_index(spec)?;
            Some((d, d))
        }
    }
}

/// Parse `"HH:MM"` into a minute-of-day (`0..=1439`).
fn minute_of_day(s: &str) -> Option<u16> {
    let (h, m) = s.trim().split_once(':')?;
    let h: u16 = h.trim().parse().ok()?;
    let m: u16 = m.trim().parse().ok()?;
    // Guard BEFORE the arithmetic: `then_some` takes its argument by value and evaluates it
    // unconditionally, so `h * 60 + m` would run even for an out-of-range hour — any `h >= 1093`
    // overflows u16 (debug panic; release wraps to a wrong value that the false guard then
    // discards). An explicit `if` gates the multiply so only in-range input (h <= 23 => max 1439)
    // is ever computed.
    if h <= 23 && m <= 59 {
        Some(h * 60 + m)
    } else {
        None
    }
}

/// Parse an hour window `"HH:MM-HH:MM"` into `(start, end)` minutes-of-day.
/// `start > end` denotes a window that wraps past midnight; `start == end` is a
/// zero-length window that never matches (rejected by validation).
pub fn parse_hour_window(spec: &str) -> Option<(u16, u16)> {
    let (lo, hi) = spec.split_once('-')?;
    Some((minute_of_day(lo)?, minute_of_day(hi)?))
}

/// Whether weekday `day` (Monday=0) falls in inclusive `(lo, hi)`, wrapping the
/// week when `lo > hi`.
fn weekday_in_range(day: u8, lo: u8, hi: u8) -> bool {
    if lo <= hi {
        lo <= day && day <= hi
    } else {
        day >= lo || day <= hi
    }
}

/// Evaluate a `when` spec against the local `weekday` (Monday=0) and
/// `minute`-of-day. Empty `days`/`hours` are unconstrained; malformed entries are
/// ignored (validation rejects them up front, so this only bites a hand-built
/// config).
///
/// A wrapping hour window (e.g. `22:00-06:00`) on a day spec belongs to the
/// *listed* day in the evening and to the **next** day in the morning — so
/// `Mon` + `22:00-06:00` covers Monday 22:00 through Tuesday 06:00, and does
/// *not* match Monday 01:00 (which is Sunday night's window).
pub fn time_window_matches(spec: &TimeMatch, weekday: u8, minute: u16) -> bool {
    let day_allowed = |d: u8| {
        spec.days.is_empty()
            || spec
                .days
                .iter()
                .any(|s| parse_day_spec(s).is_some_and(|(lo, hi)| weekday_in_range(d, lo, hi)))
    };

    // Day-only constraint: no hours to place against a day boundary.
    if spec.hours.is_empty() {
        return day_allowed(weekday);
    }

    let prev_day = (weekday + 6) % 7; // yesterday, Monday=0
    spec.hours.iter().any(|h| match parse_hour_window(h) {
        // Non-wrapping [start, end): today must be allowed.
        Some((start, end)) if start < end => {
            minute >= start && minute < end && day_allowed(weekday)
        }
        // Wrapping (start > end): the evening [start, 24:00) is on the listed day;
        // the morning [00:00, end) belongs to the previous day's window.
        Some((start, end)) if start > end => {
            (minute >= start && day_allowed(weekday)) || (minute < end && day_allowed(prev_day))
        }
        // start == end (zero-length) or unparseable → no match.
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_day_specs() {
        assert_eq!(parse_day_spec("Mon"), Some((0, 0)));
        assert_eq!(parse_day_spec("mon-fri"), Some((0, 4)));
        assert_eq!(parse_day_spec("Fri-Mon"), Some((4, 0))); // wraps
        assert_eq!(parse_day_spec("Sun"), Some((6, 6)));
        assert!(parse_day_spec("Funday").is_none());
        assert!(parse_day_spec("Mon-Funday").is_none());
    }

    #[test]
    fn parses_hour_windows() {
        assert_eq!(parse_hour_window("09:00-18:00"), Some((540, 1080)));
        assert_eq!(parse_hour_window("22:00-06:00"), Some((1320, 360))); // wraps
        assert!(parse_hour_window("9-18").is_none()); // no minutes
        assert!(parse_hour_window("24:00-01:00").is_none()); // hour out of range
        assert!(parse_hour_window("9999:00-10:00").is_none()); // huge hour: reject, don't overflow u16
        assert!(parse_hour_window("09:60-10:00").is_none()); // minute out of range
        assert!(parse_hour_window("09:00").is_none()); // not a window
    }

    #[test]
    fn matches_weekday_ranges_with_wrap() {
        let mon_fri = TimeMatch {
            days: vec!["Mon-Fri".into()],
            hours: vec![],
        };
        assert!(time_window_matches(&mon_fri, 0, 600)); // Mon
        assert!(time_window_matches(&mon_fri, 4, 600)); // Fri
        assert!(!time_window_matches(&mon_fri, 5, 600)); // Sat excluded

        let weekend = TimeMatch {
            days: vec!["Sat-Sun".into()],
            hours: vec![],
        };
        assert!(time_window_matches(&weekend, 5, 0)); // Sat
        assert!(!time_window_matches(&weekend, 0, 0)); // Mon excluded

        let fri_mon = TimeMatch {
            days: vec!["Fri-Mon".into()],
            hours: vec![],
        };
        assert!(time_window_matches(&fri_mon, 6, 0)); // Sun (within wrap)
        assert!(!time_window_matches(&fri_mon, 2, 0)); // Wed excluded
    }

    #[test]
    fn matches_hour_windows_with_wrap_and_exclusive_end() {
        let work = TimeMatch {
            days: vec![],
            hours: vec!["09:00-18:00".into()],
        };
        assert!(time_window_matches(&work, 0, 540)); // 09:00 inclusive
        assert!(time_window_matches(&work, 0, 1079)); // 17:59
        assert!(!time_window_matches(&work, 0, 1080)); // 18:00 exclusive
        assert!(!time_window_matches(&work, 0, 539)); // 08:59

        let night = TimeMatch {
            days: vec![],
            hours: vec!["22:00-06:00".into()],
        };
        assert!(time_window_matches(&night, 0, 1320)); // 22:00
        assert!(time_window_matches(&night, 0, 30)); // 00:30 (wrapped)
        assert!(!time_window_matches(&night, 0, 720)); // noon excluded
    }

    #[test]
    fn days_and_hours_are_anded_and_empty_is_unconstrained() {
        let spec = TimeMatch {
            days: vec!["Mon-Fri".into()],
            hours: vec!["09:00-17:00".into()],
        };
        assert!(time_window_matches(&spec, 2, 600)); // Wed 10:00
        assert!(!time_window_matches(&spec, 2, 60)); // Wed 01:00 (out of hours)
        assert!(!time_window_matches(&spec, 6, 600)); // Sun 10:00 (out of days)

        // Empty → always matches.
        assert!(time_window_matches(&TimeMatch::default(), 6, 1439));
    }

    #[test]
    fn day_constrained_overnight_window_belongs_to_listed_then_next_day() {
        // "Mon 22:00-06:00" = Monday evening through Tuesday early morning.
        let spec = TimeMatch {
            days: vec!["Mon".into()],
            hours: vec!["22:00-06:00".into()],
        };
        assert!(time_window_matches(&spec, 0, 1380)); // Mon 23:00 ✓ (evening, listed day)
        assert!(time_window_matches(&spec, 1, 60)); // Tue 01:00 ✓ (morning belongs to Mon)
        assert!(!time_window_matches(&spec, 0, 60)); // Mon 01:00 ✗ (that's Sun night)
        assert!(!time_window_matches(&spec, 1, 1380)); // Tue 23:00 ✗ (Tue not listed)
        assert!(!time_window_matches(&spec, 2, 60)); // Wed 01:00 ✗

        // Week-wrap day range with an overnight window: "Fri-Sat 23:00-02:00".
        let weekend = TimeMatch {
            days: vec!["Fri-Sat".into()],
            hours: vec!["23:00-02:00".into()],
        };
        assert!(time_window_matches(&weekend, 4, 1410)); // Fri 23:30 ✓
        assert!(time_window_matches(&weekend, 5, 30)); // Sat 00:30 ✓ (Fri's morning)
        assert!(time_window_matches(&weekend, 6, 30)); // Sun 00:30 ✓ (Sat's morning)
        assert!(!time_window_matches(&weekend, 0, 30)); // Mon 00:30 ✗
    }
}
