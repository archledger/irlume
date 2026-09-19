// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Diagnostics: the doctor document as native form sections - one section
// per severity, one row per check (identifier bold, remediation text
// below in the secondary color). Conditionally-present check ids render
// only when present, exactly as the contract says.
import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

KCMUtils.SimpleKCM {
    id: root

    property var doc: ({})
    property bool pending: false
    property string failure: ""

    readonly property var groups: {
        if (!doc || !doc.ok) {
            return [];
        }
        const bySeverity = [
            {title: "Failing", states: ["fail"], color: Kirigami.Theme.negativeTextColor},
            {title: "Warnings", states: ["warn"], color: Kirigami.Theme.neutralTextColor},
            {title: "Passing", states: ["pass"], color: Kirigami.Theme.positiveTextColor},
            // "unknown" is a contract state of its own: the check could not
            // be performed, and presenting that as an informational fact
            // would lie.
            {title: "Not determined", states: ["unknown"], color: Kirigami.Theme.disabledTextColor},
            {title: "Informational", states: ["info"], color: Kirigami.Theme.disabledTextColor},
        ];
        const checks = doc.data.checks;
        const out = [];
        for (const group of bySeverity) {
            const rows = checks.filter(c => group.states.indexOf(c.state) >= 0);
            if (rows.length > 0) {
                out.push({title: group.title, color: group.color, checks: rows});
            }
        }
        return out;
    }

    function refresh() {
        failure = "";
        pending = true;
        kcm.request("doctor");
    }

    Component.onCompleted: refresh()

    Connections {
        target: kcm

        function onDocumentReady(name, document) {
            if (name === "doctor") {
                root.doc = document;
                root.pending = false;
            }
        }
        function onRequestFailed(name, reason) {
            if (name === "doctor") {
                root.pending = false;
                root.failure = reason;
            }
        }
    }

    Kirigami.FormLayout {
        wideMode: true

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: root.failure.length > 0
            type: Kirigami.MessageType.Error
            text: root.failure
        }

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: !root.pending && root.doc.ok === false
            type: Kirigami.MessageType.Warning
            text: root.doc && root.doc.error
                  ? (root.doc.error.message || root.doc.error.code)
                  : "irlume did not answer"
        }

        Controls.Label {
            visible: root.pending
            enabled: false
            text: "Running the diagnostics…"
        }

        Repeater {
            model: root.groups

            delegate: ColumnLayout {
                spacing: Kirigami.Units.smallSpacing

                Kirigami.Separator {
                    Layout.fillWidth: true
                    Kirigami.FormData.isSection: true
                    Kirigami.FormData.label: modelData.title + " (" + modelData.checks.length + ")"
                }

                Repeater {
                    model: modelData.checks
                    delegate: ColumnLayout {
                        spacing: 0
                        Controls.Label {
                            Layout.fillWidth: true
                            text: modelData.id
                            font.weight: Font.DemiBold
                        }
                        Controls.Label {
                            visible: modelData.detail !== undefined && modelData.detail !== null
                            Layout.fillWidth: true
                            text: modelData.detail === undefined ? "" : String(modelData.detail)
                            wrapMode: Text.Wrap
                            color: Kirigami.Theme.disabledTextColor
                        }
                    }
                }
            }
        }

        RowLayout {
            Kirigami.FormData.label: "Fix:"
            Controls.Button {
                text: "Open irlume"
                icon.name: "utilities-terminal"
                visible: root.doc.ok === true
                onClicked: kcm.launchTui("diagnostics")
            }
        }
    }

    footer: Item {
        implicitHeight: footerRow.implicitHeight + 2 * Kirigami.Units.smallSpacing
        RowLayout {
            id: footerRow
            anchors.fill: parent
            anchors.leftMargin: Kirigami.Units.largeSpacing
            anchors.rightMargin: Kirigami.Units.largeSpacing
            anchors.topMargin: Kirigami.Units.smallSpacing
            anchors.bottomMargin: Kirigami.Units.smallSpacing
            Controls.Label {
                text: root.pending ? "Working…" : ""
                enabled: false
                Layout.fillWidth: true
                elide: Text.ElideRight
            }
            Controls.Button {
                text: "Refresh"
                icon.name: "view-refresh"
                enabled: !root.pending
                onClicked: root.refresh()
            }
        }
    }
}
