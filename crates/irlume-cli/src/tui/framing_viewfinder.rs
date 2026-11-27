// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use irlume_common::FramingPosition;
use ratatui::{layout::Rect, style::Style, widgets::Block, Frame};

pub(super) const WIDTH: u16 = 23;
pub(super) const HEIGHT: u16 = 7;

pub(super) fn draw(frame: &mut Frame<'_>, area: Rect, position: Option<FramingPosition>) {
    let area = area.intersection(frame.area());
    if area.width != WIDTH || area.height != HEIGHT {
        return;
    }

    let border = Block::bordered().title(" Framing guide ");
    let inside = border.inner(area);
    frame.render_widget(border, area);
    let center = inside.x + inside.width / 2;
    let middle = inside.y + inside.height / 2;
    let buffer = frame.buffer_mut();
    let style = Style::default();
    buffer.set_string(center - 4, middle, "[", style);
    buffer.set_string(center + 4, middle, "]", style);

    if let Some(p) = position.filter(|p| p.in_bounds()) {
        let marker = ["o", "(o)", "((o))"][usize::from(p.size)];
        // Leave room for the largest mark at either edge and mirror like a selfie.
        let x = inside.x + 2 + ((10 - u16::from(p.x)) * (inside.width - 5) + 5) / 10;
        let y = inside.y + (u16::from(p.y) * (inside.height - 1) + 5) / 10;
        buffer.set_string(x - u16::from(p.size), y, marker, style);
    }
}
