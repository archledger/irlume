// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Diagnostics page: the doctor document, grouped by severity, with the
// remediation text verbatim. Conditionally-present check ids render only
// when present, exactly as the contract says.
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
            {title: "Informational", states: ["info"], color: Kirigami.Theme.secondaryTextColor},
            // "unknown" is a contract state of its own: the check could not be
            // performed, and presenting that as an informational fact lies.
            {title: "Not determined", states: ["unknown"], color: Kirigami.Theme.disabledTextColor},
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

    ColumnLayout {
        // Same centered column as the Overview page.
        width: Math.min(parent.width - 2 * Kirigami.Units.largeSpacing,
                        Kirigami.Units.gridUnit * 46)
        x: Math.round((parent.width - width) / 2)
        spacing: Kirigami.Units.largeSpacing

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

        Controls.BusyIndicator {
            visible: root.pending
            running: root.pending
        }

        Repeater {
            model: root.groups

            delegate: ColumnLayout {
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing

                Controls.Label {
                    text: modelData.title + " (" + modelData.checks.length + ")"
                    font.weight: Font.Bold
                    color: modelData.color
                }

                Repeater {
                    model: modelData.checks
                    delegate: Kirigami.AbstractCard {
                        Layout.fillWidth: true
                        contentItem: ColumnLayout {
                            spacing: Kirigami.Units.smallSpacing
                            Controls.Label {
                                text: modelData.id
                                font.weight: Font.DemiBold
                            }
                            Controls.Label {
                                visible: modelData.detail !== undefined && modelData.detail !== null
                                Layout.fillWidth: true
                                text: modelData.detail === undefined ? "" : String(modelData.detail)
                                wrapMode: Text.Wrap
                                color: Kirigami.Theme.secondaryTextColor
                            }
                        }
                    }
                }
            }
        }

        RowLayout {
            Controls.Button {
                text: "Fix in irlume"
                icon.name: "utilities-terminal"
                visible: root.doc.ok === true
                onClicked: kcm.launchTui("diagnostics")
            }
            Item { Layout.fillWidth: true }
            Controls.Button {
                text: root.pending ? "Working…" : "Refresh"
                icon.name: "view-refresh"
                enabled: !root.pending
                onClicked: root.refresh()
            }
        }
    }
}
