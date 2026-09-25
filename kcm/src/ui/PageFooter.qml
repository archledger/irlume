// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The footer every page shares: what is running, an optional page action
// (which opens the irlume terminal interface), and Refresh with the
// platform's Refresh shortcut.
import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami

Item {
    id: footer

    property bool busy: false
    // Shown while busy; a page leaves it empty while its loading
    // placeholder already says the same.
    property string busyText: ""
    // Only the page on screen reacts to the shortcut: the Overview stays on
    // the page stack while a detail page is open.
    property bool active: true
    property string actionText: ""
    property string actionIcon: "utilities-terminal"

    signal actionTriggered()
    signal refreshRequested()

    // Whether the busy text and the buttons fit on one line; otherwise the
    // buttons stack on the right (narrow windows, large fonts). Measured
    // from the buttons' own sizes and the footer's width, which the page
    // sets, so stacking never feeds back into the check.
    readonly property bool oneLine: (actionButton.visible ? actionButton.implicitWidth + Kirigami.Units.smallSpacing : 0)
        + refreshButton.implicitWidth + Kirigami.Units.gridUnit * 4
        + 2 * Kirigami.Units.largeSpacing <= footer.width

    implicitHeight: row.implicitHeight + 2 * Kirigami.Units.smallSpacing
    implicitWidth: row.implicitWidth + 2 * Kirigami.Units.largeSpacing

    GridLayout {
        id: row
        anchors.fill: parent
        anchors.leftMargin: Kirigami.Units.largeSpacing
        anchors.rightMargin: Kirigami.Units.largeSpacing
        anchors.topMargin: Kirigami.Units.smallSpacing
        anchors.bottomMargin: Kirigami.Units.smallSpacing
        columns: footer.oneLine ? 3 : 1
        columnSpacing: Kirigami.Units.smallSpacing
        rowSpacing: Kirigami.Units.smallSpacing

        SecondaryLabel {
            Layout.fillWidth: true
            visible: footer.oneLine || text.length > 0
            text: footer.busy ? footer.busyText : ""
            elide: Text.ElideRight
        }
        Controls.Button {
            id: actionButton
            objectName: "footerAction"
            Layout.alignment: Qt.AlignRight
            visible: footer.actionText.length > 0
            text: footer.actionText
            icon.name: footer.actionIcon
            onClicked: footer.actionTriggered()
        }
        Controls.Button {
            id: refreshButton
            objectName: "footerRefresh"
            Layout.alignment: Qt.AlignRight
            text: "Refresh"
            icon.name: "view-refresh"
            enabled: !footer.busy
            onClicked: footer.refreshRequested()
        }
    }

    Shortcut {
        sequences: [StandardKey.Refresh]
        enabled: footer.active && !footer.busy
        onActivated: footer.refreshRequested()
    }
}
