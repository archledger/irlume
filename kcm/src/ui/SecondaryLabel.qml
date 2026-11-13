// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Secondary text (hints, check ids, evidence, busy text) in the colour
// Kirigami gives its own subtitles: the text colour blended a quarter of
// the way toward the background, which stays readable on light and dark
// schemes alike. The theme's disabled colour is too faint on light
// schemes, and `enabled: false` would make screen readers announce the
// text as disabled.
import QtQuick
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami

Controls.Label {
    // Inside a highlighted list row: the highlighted text colour.
    property bool selected: false

    // Most of these lines carry text from irlume's reports (a check's
    // detail, a device's evidence). Plain text shows it as written, as Qt
    // advises for text that comes from outside the application.
    textFormat: Text.PlainText

    color: selected ? Kirigami.Theme.highlightedTextColor
                    : Kirigami.ColorUtils.linearInterpolation(Kirigami.Theme.textColor,
                                                              Kirigami.Theme.backgroundColor, 0.25)
}
