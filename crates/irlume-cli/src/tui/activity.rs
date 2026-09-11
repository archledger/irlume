// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded, process-local TUI messages. This is not a system audit collector.

use ratatui::buffer::{Buffer, Cell};
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Widget, Wrap};
use std::cell::RefCell;
use std::ops::Deref;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 200;
const MAX_ENTRY_BYTES: usize = 4096;
// Also bounds the wrapped paragraph below u16::MAX rows, even at width 1.
const MAX_TEXT_BYTES: usize = 32 * 1024;
const TRUNCATED: &str = " [detail truncated]";

#[derive(Clone, Copy)]
struct Anchor {
    id: u64,
    byte: usize,
    row: usize,
    width: u16,
}

#[derive(Default)]
struct View {
    // Stable entry id and source byte; None follows the newest message.
    anchor: Option<Anchor>,
    rows: Vec<(u64, usize)>,
    scroll: usize,
    max_scroll: usize,
    height: usize,
    width: u16,
}

pub(super) struct Activity {
    entries: Vec<(char, String)>,
    elapsed: Vec<Duration>,
    started: Instant,
    bytes: usize,
    discarded: u64,
    view: RefCell<View>,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            elapsed: Vec::new(),
            started: Instant::now(),
            bytes: 0,
            discarded: 0,
            view: RefCell::new(View::default()),
        }
    }
}

// Existing consumers can inspect tuples, but cannot mutate entries separately
// from timestamps, retention accounting or the stable history anchor.
impl Deref for Activity {
    type Target = [(char, String)];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl Activity {
    pub(super) fn push(&mut self, icon: char, message: String) {
        self.push_at(icon, message, self.started.elapsed());
    }

    fn push_at(&mut self, icon: char, message: String, elapsed: Duration) {
        let message = bounded_text(&message);
        self.bytes += message.len();
        self.entries.push((icon, message));
        self.elapsed.push(elapsed);
        while self.entries.len() > MAX_ENTRIES || self.bytes > MAX_TEXT_BYTES {
            self.bytes -= self.entries.remove(0).1.len();
            self.elapsed.remove(0);
            self.discarded = self.discarded.saturating_add(1);
        }
    }

    fn prefix(&self, index: usize) -> String {
        let seconds = self.elapsed[index].as_secs();
        format!(
            "[{:02}:{:02}] {} ",
            seconds / 60,
            seconds % 60,
            status(self.entries[index].0)
        )
    }

    pub(super) fn summary(&self, index: usize, width: u16) -> String {
        let message = &self.entries[index].1;
        let first = message.split('\n').next().unwrap_or_default();
        let mut text = format!("{}{first}", self.prefix(index));
        if message.contains('\n') {
            text.push('…');
        }
        clip(&text, width)
    }

    fn entry_lines(&self, index: usize) -> Vec<Line<'static>> {
        self.entries[index]
            .1
            .split('\n')
            .enumerate()
            .map(|(line, text)| {
                Line::raw(if line == 0 {
                    format!("{}{text}", self.prefix(index))
                } else {
                    text.to_string()
                })
            })
            .collect()
    }

    /// Use the renderer's emitted graphemes to locate each row in its source.
    /// This runs only for navigation/resizing, not on each ordinary draw. Each
    /// temporary buffer holds one bounded logical line, never the whole history.
    fn row_offsets(&self, index: usize, width: u16) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut base = 0;
        for line in self.entry_lines(index) {
            let text = line.to_string();
            offsets.extend(
                wrapped_source_offsets(&text, width)
                    .into_iter()
                    .map(|n| base + n),
            );
            base += text.len() + 1;
        }
        offsets
    }

    pub(super) fn retention(&self) -> String {
        format!(
            "{} retained · {} older discarded · session memory only",
            self.entries.len(),
            self.discarded
        )
    }

    pub(super) fn follow(&self) {
        self.view.borrow_mut().anchor = None;
    }

    pub(super) fn following(&self) -> bool {
        self.view.borrow().anchor.is_none()
    }

    /// All detail uses the same ratatui wrapping for counting and rendering.
    /// A stable entry anchor survives append/eviction and viewport resizing.
    pub(super) fn paragraph(&self, width: u16, height: u16) -> Paragraph<'static> {
        let mut rows = Vec::with_capacity(self.entries.len());
        let mut lines = Vec::new();
        for index in 0..self.entries.len() {
            let entry = self.entry_lines(index);
            let count = Paragraph::new(entry.clone())
                .wrap(Wrap { trim: false })
                .line_count(width);
            rows.push((self.discarded + index as u64, count));
            lines.extend(entry);
        }
        let mut view = self.view.borrow_mut();
        let max_scroll = rows
            .iter()
            .map(|(_, count)| count)
            .sum::<usize>()
            .saturating_sub(usize::from(height));
        let scroll = match view.anchor {
            None => max_scroll,
            Some(mut anchor) => {
                if anchor.width != width {
                    if let Some(index) = anchor
                        .id
                        .checked_sub(self.discarded)
                        .and_then(|n| usize::try_from(n).ok())
                        .filter(|index| *index < self.entries.len())
                    {
                        anchor.row = self
                            .row_offsets(index, width)
                            .partition_point(|byte| *byte <= anchor.byte)
                            .saturating_sub(1);
                    }
                    anchor.width = width;
                    view.anchor = Some(anchor);
                }
                let before = rows
                    .iter()
                    .take_while(|(row_id, _)| *row_id < anchor.id)
                    .map(|(_, count)| count)
                    .sum::<usize>();
                let offset = rows
                    .iter()
                    .find(|(row_id, _)| *row_id == anchor.id)
                    .map_or(0, |(_, count)| anchor.row.min(count.saturating_sub(1)));
                (before + offset).min(max_scroll)
            }
        };
        view.rows = rows;
        view.scroll = scroll;
        view.max_scroll = max_scroll;
        view.height = usize::from(height);
        view.width = width;
        // The total byte/entry bounds above make this conversion lossless.
        let scroll = u16::try_from(scroll).unwrap_or(u16::MAX);
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
    }

    pub(super) fn scroll(&self, key: KeyCode) {
        let mut view = self.view.borrow_mut();
        let next = match key {
            KeyCode::Home => 0,
            KeyCode::End => {
                view.anchor = None;
                return;
            }
            KeyCode::Up => view.scroll.saturating_sub(1),
            KeyCode::PageUp => view.scroll.saturating_sub(view.height.max(1)),
            KeyCode::Down => view.scroll.saturating_add(1).min(view.max_scroll),
            KeyCode::PageDown => view
                .scroll
                .saturating_add(view.height.max(1))
                .min(view.max_scroll),
            _ => return,
        };
        if next == view.max_scroll && !matches!(key, KeyCode::Home | KeyCode::Up | KeyCode::PageUp)
        {
            view.anchor = None;
        } else {
            let mut remaining = next;
            view.anchor = view.rows.iter().find_map(|(id, count)| {
                if remaining < *count {
                    let byte = id
                        .checked_sub(self.discarded)
                        .and_then(|n| usize::try_from(n).ok())
                        .filter(|index| *index < self.entries.len())
                        .and_then(|index| {
                            self.row_offsets(index, view.width).get(remaining).copied()
                        })
                        .unwrap_or(0);
                    Some(Anchor {
                        id: *id,
                        byte,
                        row: remaining,
                        width: view.width,
                    })
                } else {
                    remaining = remaining.saturating_sub(*count);
                    None
                }
            });
        }
        view.scroll = next;
    }
}

/// Ratatui's word wrapper can consume boundary spaces and omit graphemes
/// wider than the viewport. Match emitted symbols to whole source graphemes
/// monotonically, so repeated words, combining characters and those omissions
/// retain their source positions. NUL marks untouched padding/continuation
/// cells only in this offscreen buffer; bounded_text excludes it from input.
fn wrapped_source_offsets(text: &str, width: u16) -> Vec<usize> {
    if width == 0 {
        return Vec::new();
    }
    let width = width.min(
        u16::try_from(Line::raw(text).width())
            .unwrap_or(u16::MAX)
            .max(1),
    );
    let paragraph = Paragraph::new(text).wrap(Wrap { trim: false });
    let height = u16::try_from(paragraph.line_count(width)).unwrap_or(u16::MAX);
    let area = Rect::new(0, 0, width, height);
    let mut buffer = Buffer::filled(area, Cell::new("\0"));
    paragraph.render(area, &mut buffer);
    let source_line = Line::raw(text);
    let mut source = source_line
        .styled_graphemes(Style::default())
        .scan(0, |byte, grapheme| {
            let position = *byte;
            *byte += grapheme.symbol.len();
            Some((position, grapheme.symbol))
        });
    let mut next = 0;
    buffer
        .content
        .chunks(usize::from(width))
        .map(|row| {
            let mut start = None;
            let mut first_text = None;
            for cell in row {
                let symbol = cell.symbol();
                if symbol == "\0" {
                    continue;
                }
                if let Some((byte, _)) = source.find(|(_, original)| *original == symbol) {
                    start.get_or_insert(byte);
                    if !symbol.chars().all(char::is_whitespace) {
                        first_text.get_or_insert(byte);
                    }
                    next = byte + symbol.len();
                }
            }
            // Prefer actual text over leading spaces consumed differently by reflow.
            first_text.or(start).unwrap_or(next)
        })
        .collect()
}

fn status(icon: char) -> &'static str {
    match icon {
        '→' => "Requested",
        '✓' => "Completed",
        '✗' => "Failed",
        '!' => "Warning",
        _ => "Info",
    }
}

fn bounded_text(message: &str) -> String {
    let mut text = String::new();
    for ch in message.chars() {
        let ch = if ch.is_control() && ch != '\n' {
            ' '
        } else {
            ch
        };
        if text.len() + ch.len_utf8() > MAX_ENTRY_BYTES - TRUNCATED.len() {
            text.push_str(TRUNCATED);
            return text;
        }
        text.push(ch);
    }
    text
}

fn clip(text: &str, width: u16) -> String {
    if Line::raw(text).width() <= usize::from(width) {
        return text.to_string();
    }
    let mut result = String::new();
    let mut columns = 0;
    for ch in text.chars() {
        let next = columns + Line::raw(ch.to_string()).width();
        if next + 1 > usize::from(width) {
            break;
        }
        result.push(ch);
        columns = next;
    }
    if width > 0 {
        result.push('…');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render(activity: &Activity, width: u16, height: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
        term.draw(|frame| {
            frame.render_widget(activity.paragraph(width, height), frame.area());
        })
        .unwrap();
        term.backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn history_has_exact_elapsed_times_and_non_color_statuses() {
        let mut activity = Activity::default();
        for (icon, seconds, message) in [
            ('→', 0, "request"),
            ('✓', 65, "reply"),
            ('✗', 125, "error"),
            ('!', 126, "warning"),
            ('·', 127, "observation"),
        ] {
            activity.push_at(icon, message.into(), Duration::from_secs(seconds));
        }
        let text = render(&activity, 80, 8);
        for expected in [
            "[00:00] Requested request",
            "[01:05] Completed reply",
            "[02:05] Failed error",
            "Warning warning",
            "Info observation",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
    }

    #[test]
    fn long_unicode_detail_is_bounded_and_truncation_is_visible() {
        let mut activity = Activity::default();
        activity.push('·', "界".repeat(5000));
        assert!(activity[0].1.len() <= 4096);
        assert!(activity[0].1.ends_with("[detail truncated]"));
        let text = render(&activity, 60, 5);
        assert!(
            text.contains("[detail truncated]"),
            "omission must be reachable: {text}"
        );
    }

    #[test]
    fn aggregate_detail_retention_reports_discarded_entries() {
        let mut activity = Activity::default();
        for _ in 0..200 {
            activity.push('·', "x".repeat(3000));
        }
        assert!(activity.iter().map(|(_, text)| text.len()).sum::<usize>() <= 32 * 1024);
        assert!(activity.len() < 200);
        assert!(activity.discarded > 0);
        assert!(activity
            .retention()
            .contains(&format!("{} older discarded", activity.discarded)));
    }

    #[test]
    fn display_normalizes_terminal_controls_but_keeps_detail_lines() {
        let mut activity = Activity::default();
        activity.push('·', "before\u{1b}[31m\r\t\u{7}\nafter".into());
        assert!(activity[0].1.contains("\nafter"));
        assert!(!activity[0]
            .1
            .chars()
            .any(|ch| ch.is_control() && ch != '\n'));
    }

    #[test]
    fn reading_anchor_survives_new_entries_and_oldest_eviction() {
        let mut activity = Activity::default();
        for i in 0..200 {
            activity.push('·', format!("entry-{i:03}"));
        }
        render(&activity, 60, 5);
        activity.scroll(KeyCode::PageUp);
        let before = render(&activity, 60, 5);
        activity.push('✓', "latest".into());
        assert_eq!(before, render(&activity, 60, 5));
        activity.scroll(KeyCode::Home);
        let before = render(&activity, 60, 5);
        assert!(before.contains("entry-001"));
        activity.push('✓', "another latest".into());
        let after = render(&activity, 60, 5);
        assert!(after.contains("entry-002"));
        assert!(!after.contains("entry-001"));
        assert!(activity.retention().contains("2 older discarded"));
    }

    #[test]
    fn resizing_and_single_row_scrolling_reach_all_wrapped_detail() {
        let mut activity = Activity::default();
        activity.push('·', "START\n界 detail ".repeat(10) + "FINAL_SENTINEL");
        render(&activity, 20, 3);
        activity.scroll(KeyCode::Home);
        let mut seen = String::new();
        for _ in 0..120 {
            seen.push_str(&render(&activity, 20, 3));
            activity.scroll(KeyCode::Down);
        }
        assert!(seen.contains("START"));
        assert!(seen.contains("FINAL_SENTINEL"));
        assert!(activity.following());
        assert!(render(&activity, 40, 4).contains("FINAL_SENTINEL"));
    }

    #[test]
    fn reading_mid_entry_keeps_the_same_text_across_width_changes() {
        let mut activity = Activity::default();
        let message = (0..150).map(|n| format!("word{n:03} ")).collect::<String>();
        activity.push('·', message);
        render(&activity, 60, 4);
        activity.scroll(KeyCode::Home);
        render(&activity, 60, 4);
        for _ in 0..7 {
            activity.scroll(KeyCode::Down);
            render(&activity, 60, 4);
        }
        let before = render(&activity, 60, 4);
        let first_word = before.split_whitespace().next().unwrap();
        let narrow = render(&activity, 24, 4);
        assert!(
            narrow[..24].contains(first_word),
            "resizing must retain the first reading word {first_word}: {narrow}"
        );
        assert_eq!(
            render(&activity, 60, 4),
            before,
            "resizing back must retain the original source position"
        );
        assert!(!activity.following());
    }

    #[test]
    fn source_offsets_distinguish_repeats_combining_text_and_consumed_spaces() {
        for (text, width, expected) in [
            ("echo echo echo echo", 9, vec![0, 10]),
            ("e\u{301}界 e\u{301}界 e\u{301}界", 7, vec![0, 14]),
            ("word0     word1 word2", 10, vec![0, 10, 16]),
            ("界a界b", 1, vec![3, 7]),
        ] {
            assert_eq!(wrapped_source_offsets(text, width), expected, "{text:?}");
        }
    }

    #[test]
    fn skipped_wide_grapheme_cannot_supply_a_later_ascii_anchor() {
        assert_eq!(
            wrapped_source_offsets("1\u{fe0f}\u{20e3}1x", 1),
            vec![7, 8],
            "the displayed ASCII 1 must not anchor inside the skipped keycap"
        );
    }

    #[test]
    fn newline_heavy_history_fits_the_scroll_type_at_one_column() {
        let mut activity = Activity::default();
        for _ in 0..200 {
            activity.push('·', "\n".repeat(1000));
        }
        render(&activity, 1, 1);
        assert!(activity.view.borrow().max_scroll < usize::from(u16::MAX));
        activity.scroll(KeyCode::Home);
        assert_eq!(activity.view.borrow().scroll, 0);
        activity.scroll(KeyCode::End);
        render(&activity, 1, 1);
        assert_eq!(
            activity.view.borrow().scroll,
            activity.view.borrow().max_scroll
        );
    }

    #[test]
    fn summary_discloses_multiline_and_width_truncation() {
        let mut activity = Activity::default();
        activity.push('·', "first\nsecond".into());
        assert!(activity.summary(0, 80).ends_with('…'));
        let summary = activity.summary(0, 10);
        assert!(Line::raw(&summary).width() <= 10);
        assert!(summary.ends_with('…'));
    }
}
