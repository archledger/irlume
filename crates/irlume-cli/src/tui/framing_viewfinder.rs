// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use irlume_common::FramingPosition;
use ratatui::{
    layout::{Alignment, Rect},
    style::Style,
    text::Line,
    widgets::{Block, Paragraph, Wrap},
    Frame,
};

const WIDTH: u16 = 33;
const HEIGHT: u16 = 9;
const GUIDE_GAP_ROWS: u16 = 3;

pub(super) enum Guide {
    TextOnly,
    Frame(Option<FramingPosition>),
}

pub(super) fn horizontal_offset(position: FramingPosition) -> i16 {
    5 - i16::from(position.x)
}

pub(super) fn draw_stack(
    frame: &mut Frame<'_>,
    area: Rect,
    cue: Line<'_>,
    progress: Vec<Line<'_>>,
    details: Vec<Line<'_>>,
    guide: Guide,
) -> bool {
    let detail_slots = u16::try_from(details.len()).unwrap_or(u16::MAX);
    let panels = [
        Paragraph::new(cue),
        Paragraph::new(progress),
        Paragraph::new(details),
    ]
    .map(|panel| {
        panel
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false })
    });
    let [Ok(cue_rows), Ok(progress_rows), Ok(detail_rows)] = panels
        .each_ref()
        .map(|panel| u16::try_from(panel.line_count(area.width)))
    else {
        return false;
    };
    let row_area = |y, height| Rect::new(area.x, y, area.width, height);
    if let Guide::Frame(marker) = guide {
        // Center the normal stack, then spend surrounding space on wrapped
        // text without changing the guide or progress rows.
        let normal_rows = (1 + HEIGHT + GUIDE_GAP_ROWS)
            .saturating_add(progress_rows)
            .saturating_add(detail_slots);
        if area.width >= WIDTH {
            if let Some(slack) = area.height.checked_sub(normal_rows) {
                let guide_y = area.y + slack / 2 + 2;
                let progress_y = guide_y + HEIGHT + 1;
                let detail_y = progress_y + progress_rows + 1;
                if let Some(cue_y) = guide_y
                    .checked_sub(cue_rows.saturating_add(1))
                    .filter(|&y| y >= area.y)
                    .filter(|_| detail_rows <= area.bottom().saturating_sub(detail_y))
                {
                    let [cue, progress, details] = panels;
                    frame.render_widget(cue, row_area(cue_y, cue_rows));
                    draw(
                        frame,
                        Rect::new(area.x + area.width / 2 - WIDTH / 2, guide_y, WIDTH, HEIGHT),
                        marker,
                    );
                    frame.render_widget(progress, row_area(progress_y, progress_rows));
                    frame.render_widget(details, row_area(detail_y, detail_rows));
                    return true;
                }
            }
        }
    }
    let Some(text_slack) = [cue_rows, progress_rows, detail_rows]
        .into_iter()
        .try_fold(area.height, u16::checked_sub)
    else {
        return false;
    };
    let gap = u16::from(text_slack >= 2);
    let top = area.y + (text_slack - gap * 2) / 2;
    let [cue, progress, details] = panels;
    frame.render_widget(cue, row_area(top, cue_rows));
    let y = top + cue_rows + gap;
    frame.render_widget(progress, row_area(y, progress_rows));
    frame.render_widget(details, row_area(y + progress_rows + gap, detail_rows));
    true
}

pub(super) fn draw(frame: &mut Frame<'_>, area: Rect, position: Option<FramingPosition>) {
    let area = area.intersection(frame.area());
    if area.width != WIDTH || area.height != HEIGHT {
        return;
    }

    let border = Block::bordered()
        .title(" Framing guide ")
        .title_alignment(Alignment::Center);
    let inside = border.inner(area);
    frame.render_widget(border, area);
    let buffer = frame.buffer_mut();
    let style = Style::default();
    for (x, y, tick) in [(11, 1, "┌"), (21, 1, "┐"), (11, 7, "└"), (21, 7, "┘")] {
        buffer.set_string(area.x + x, area.y + y, tick, style);
    }
    if let Some(p) = position.filter(|p| p.in_bounds()) {
        let marker = ["o", "(o)", "((o))"][usize::from(p.size)];
        // Leave room for the largest mark at either edge and mirror like a selfie.
        let mirrored = u16::try_from(5 + horizontal_offset(p)).unwrap_or_default();
        let x = inside.x + 2 + (mirrored * (inside.width - 5) + 5) / 10;
        // Keep the first and last interior rows free for the four corner marks.
        let y = inside.y + 1 + (u16::from(p.y) * (inside.height - 3) + 5) / 10;
        buffer.set_string(x - u16::from(p.size), y, marker, style);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn wrapped_detail_falls_back_only_when_it_cannot_fit_below_the_guide() {
        for (height, framed) in [(16, false), (17, true)] {
            let mut terminal = Terminal::new(TestBackend::new(68, height)).unwrap();
            let detail = format!("{} detail-end", "Waiting ".repeat(10));
            terminal
                .draw(|frame| {
                    assert!(draw_stack(
                        frame,
                        frame.area(),
                        Line::raw("Camera guide not answering"),
                        vec![Line::raw("0 of 4 captured")],
                        vec![Line::raw("Profile 'demo'"), Line::raw(detail)],
                        Guide::Frame(None),
                    ));
                })
                .unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(
                text.contains("detail-end"),
                "wrapped detail was cut at height {height}"
            );
            assert_eq!(text.contains("Framing guide"), framed, "at height {height}");
        }
    }
}
