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
    let Some(text_slack) = [cue_rows, progress_rows, detail_rows]
        .into_iter()
        .try_fold(area.height, u16::checked_sub)
    else {
        return false;
    };
    let (guide, guide_rows, intervals) = match guide {
        Guide::Frame(marker) if area.width >= WIDTH && text_slack >= HEIGHT + GUIDE_GAP_ROWS => {
            (Guide::Frame(marker), HEIGHT, GUIDE_GAP_ROWS)
        }
        _ => (Guide::TextOnly, 0, 2),
    };
    let slack = text_slack - guide_rows;
    let gap = u16::from(slack >= intervals);
    let top = area.y + (slack - gap * intervals) / 2;
    let [cue, progress, details] = panels;
    let row_area = |y, height| Rect::new(area.x, y, area.width, height);
    frame.render_widget(cue, row_area(top, cue_rows));
    let mut y = top + cue_rows + gap;
    if let Guide::Frame(marker) = guide {
        draw(
            frame,
            Rect::new(area.x + area.width / 2 - WIDTH / 2, y, WIDTH, HEIGHT),
            marker,
        );
        y += guide_rows + gap;
    }
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
