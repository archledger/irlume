// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Calendar dates a person reads: when an attempt happened (the Overview)
//! and when scans were captured (Faces, ADR-0030 §2). Pure over unix
//! seconds and the zone's offset from UTC, which the caller supplies, so
//! the words are the same in tests and live, whatever the host's zone.

pub(super) const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// What Faces says for a scan or camera without a capture time: scans from
/// before capture dates, and every scan an older daemon reports.
pub(super) const UNDATED: &str = "date not recorded";

/// The calendar date of `at` (unix seconds) in the zone `utc_offset`
/// seconds east of UTC: (year, month 1-12, day 1-31). The proleptic
/// Gregorian conversion from days since the epoch (H. Hinnant's
/// `civil_from_days`).
pub(super) fn civil_date(at: u64, utc_offset: i64) -> (i64, usize, i64) {
    let local = i64::try_from(at)
        .unwrap_or(i64::MAX)
        .saturating_add(utc_offset);
    let days = local.div_euclid(86_400) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, usize::try_from(month).unwrap_or(1), day)
}

/// The local days from `first` to `last` (unix seconds, either order):
/// one day as "Sep 24, 2026", a span as "Mar 3 to Sep 24, 2026", with the
/// year on both ends when they differ. Each end takes the offset in force
/// at its own time, so a daylight-saving change never moves a date.
pub(super) fn capture_range(first: u64, last: u64, utc_offset: &dyn Fn(u64) -> i64) -> String {
    let (first, last) = (first.min(last), first.max(last));
    let (first_year, first_month, first_day) = civil_date(first, utc_offset(first));
    let (last_year, last_month, last_day) = civil_date(last, utc_offset(last));
    let last_text = format!("{} {last_day}, {last_year}", MONTHS[last_month - 1]);
    if (first_year, first_month, first_day) == (last_year, last_month, last_day) {
        last_text
    } else if first_year == last_year {
        format!("{} {first_day} to {last_text}", MONTHS[first_month - 1])
    } else {
        format!(
            "{} {first_day}, {first_year} to {last_text}",
            MONTHS[first_month - 1]
        )
    }
}

/// The capture times of a profile's primary scans, index for index with
/// its scan names, or none when the list does not line up with them (an
/// older daemon, or one that predates capture dates for every scan).
pub(super) fn aligned(captured: &[Option<u64>], scans: usize) -> Option<&[Option<u64>]> {
    (captured.len() == scans).then_some(captured)
}

/// The dates of a set of scans (`captured`, one entry per scan): their
/// range, and how many carry no date when only some do; "date not
/// recorded" when none does.
pub(super) fn scan_dates(captured: &[Option<u64>], utc_offset: &dyn Fn(u64) -> i64) -> String {
    let dated = captured.iter().flatten().copied();
    let (Some(first), Some(last)) = (dated.clone().min(), dated.max()) else {
        return UNDATED.into();
    };
    let range = capture_range(first, last, utc_offset);
    match captured.iter().filter(|at| at.is_none()).count() {
        0 => range,
        undated => format!("{range} · {undated} undated"),
    }
}

/// An added camera's dates from the first/last pair the daemon reports for
/// a profile's scans on it; "date not recorded" when it reports neither.
pub(super) fn group_dates(
    first: Option<u64>,
    last: Option<u64>,
    utc_offset: &dyn Fn(u64) -> i64,
) -> String {
    match (first.or(last), last.or(first)) {
        (Some(first), Some(last)) => capture_range(first, last, utc_offset),
        _ => UNDATED.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-24 12:00:00 UTC.
    const SEP_24: u64 = 1_790_251_200;
    const DAY: u64 = 86_400;

    #[test]
    fn civil_dates_follow_the_gregorian_calendar_in_the_given_zone() {
        assert_eq!(civil_date(0, 0), (1970, 1, 1));
        assert_eq!(civil_date(951_782_400, 0), (2000, 2, 29));
        assert_eq!(civil_date(SEP_24, 0), (2026, 9, 24));
        // Twelve hours later it is the 25th in UTC, still the 24th one
        // second west of it.
        assert_eq!(civil_date(SEP_24 + 12 * 3600, 0), (2026, 9, 25));
        assert_eq!(civil_date(SEP_24 + 12 * 3600, -1), (2026, 9, 24));
        // Before the epoch in a zone west of UTC.
        assert_eq!(civil_date(0, -3600), (1969, 12, 31));
    }

    #[test]
    fn a_capture_range_reads_as_one_day_or_a_span_with_years_where_they_differ() {
        let utc = |_| 0;
        assert_eq!(capture_range(SEP_24, SEP_24, &utc), "Sep 24, 2026");
        // The same local day at two times is one day.
        assert_eq!(
            capture_range(SEP_24 - 11 * 3600, SEP_24 + 11 * 3600, &utc),
            "Sep 24, 2026"
        );
        // 2026-03-03 12:00 UTC to Sep 24, in either order.
        let march_3 = SEP_24 - 205 * DAY;
        assert_eq!(
            capture_range(march_3, SEP_24, &utc),
            "Mar 3 to Sep 24, 2026"
        );
        assert_eq!(
            capture_range(SEP_24, march_3, &utc),
            "Mar 3 to Sep 24, 2026"
        );
        // Across a new year both ends carry their year.
        let dec_30_2025 = SEP_24 - 268 * DAY;
        assert_eq!(
            capture_range(dec_30_2025, SEP_24, &utc),
            "Dec 30, 2025 to Sep 24, 2026"
        );
        // The zone decides the day: 23:30 UTC on Sep 24 is Sep 25 an hour
        // east, and one day with the first end there.
        let late = SEP_24 + 11 * 3600 + 1800;
        assert_eq!(capture_range(late, late, &|_| 3600), "Sep 25, 2026");
        assert_eq!(
            capture_range(SEP_24, late, &|_| 3600),
            "Sep 24 to Sep 25, 2026"
        );
        // Each end takes its own offset: a zone that moved an hour east
        // between the two captures.
        let moved = |at: u64| if at < SEP_24 { -3600 } else { 0 };
        assert_eq!(
            capture_range(SEP_24 - 12 * 3600, SEP_24, &moved),
            "Sep 23 to Sep 24, 2026"
        );
    }

    #[test]
    fn scans_without_a_capture_time_read_date_not_recorded() {
        let utc = |_| 0;
        assert_eq!(scan_dates(&[], &utc), "date not recorded");
        assert_eq!(scan_dates(&[None, None], &utc), "date not recorded");
        assert_eq!(scan_dates(&[Some(SEP_24)], &utc), "Sep 24, 2026");
        assert_eq!(
            scan_dates(&[Some(SEP_24 - 205 * DAY), None, Some(SEP_24), None], &utc),
            "Mar 3 to Sep 24, 2026 · 2 undated"
        );
        // A list that does not line up with the scans dates none of them.
        assert_eq!(aligned(&[Some(SEP_24)], 2), None);
        assert_eq!(
            aligned(&[Some(SEP_24), None], 2),
            Some(&[Some(SEP_24), None][..])
        );
        assert_eq!(aligned(&[], 0), Some(&[][..]));
        assert_eq!(group_dates(None, None, &utc), "date not recorded");
        assert_eq!(group_dates(Some(SEP_24), None, &utc), "Sep 24, 2026");
        assert_eq!(
            group_dates(Some(SEP_24 - 205 * DAY), Some(SEP_24), &utc),
            "Mar 3 to Sep 24, 2026"
        );
    }
}
