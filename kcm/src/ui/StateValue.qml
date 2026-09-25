// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A value with its state: a decorative state icon, the value in words, and
// an optional hint below it. The state word is part of the accessible name,
// so colour is never the only signal, and the hint is always on screen
// (nothing hides behind a hover). Wrapping text is capped in width, so a
// long value cannot widen the form past the window.
import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami

import "labels.js" as L

RowLayout {
    id: line

    // What the value is about, for the accessible name ("Daemon").
    property string label: ""
    property string level: L.UNKNOWN
    property string value: ""
    property string hint: ""

    // The widest the row may be. A page lowers it on a narrow window: the
    // form is never narrower than its widest row.
    property real widthCap: Kirigami.Units.gridUnit * 22

    spacing: Kirigami.Units.smallSpacing
    Layout.fillWidth: true
    Layout.maximumWidth: line.widthCap

    Accessible.role: Accessible.StaticText
    Accessible.name: line.label + ": " + line.value + " (" + L.levelWord(line.level) + ")"
    Accessible.description: line.hint

    FontMetrics {
        id: metrics
        font: valueLabel.font
    }

    Kirigami.Icon {
        Layout.alignment: Qt.AlignTop
        Layout.topMargin: Math.max(0, Math.round((metrics.height - height) / 2))
        implicitWidth: Kirigami.Units.iconSizes.small
        implicitHeight: Kirigami.Units.iconSizes.small
        source: L.levelIcon(line.level)
        Accessible.ignored: true
    }

    ColumnLayout {
        Layout.fillWidth: true
        spacing: 0

        Controls.Label {
            id: valueLabel
            Layout.fillWidth: true
            text: line.value
            wrapMode: Text.Wrap
            Accessible.ignored: true
        }
        SecondaryLabel {
            Layout.fillWidth: true
            visible: line.hint.length > 0
            text: line.hint
            wrapMode: Text.Wrap
            Accessible.ignored: true
        }
    }
}
