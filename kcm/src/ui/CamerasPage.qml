// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Cameras page: the census document (read-only capability: node opens for
// classification, no streaming, no daemon). The CONFIGURED pair is not
// shown: contract 1 publishes camera capability without identity; picking
// the pair happens in the TUI.
import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

KCMUtils.ScrollViewKCM {
    id: root

    property var doc: ({})
    property bool pending: false
    property string failure: ""

    readonly property var entries: doc && doc.ok ? doc.data.entries : []

    function refresh() {
        failure = "";
        pending = true;
        kcm.request("census");
    }

    Component.onCompleted: refresh()

    Connections {
        target: kcm

        function onDocumentReady(name, document) {
            if (name === "census") {
                root.doc = document;
                root.pending = false;
            }
        }
        function onRequestFailed(name, reason) {
            if (name === "census") {
                root.pending = false;
                root.failure = reason;
            }
        }
    }

    ColumnLayout {
        spacing: Kirigami.Units.largeSpacing

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: root.failure.length > 0
            type: Kirigami.MessageType.Error
            text: root.failure
        }

        Controls.BusyIndicator {
            visible: root.pending
            running: root.pending
        }

        Repeater {
            model: root.entries

            delegate: Kirigami.AbstractCard {
                Layout.fillWidth: true
                contentItem: ColumnLayout {
                    spacing: Kirigami.Units.smallSpacing
                    RowLayout {
                        spacing: Kirigami.Units.largeSpacing
                        Controls.Label {
                            text: modelData.node
                            font.family: "monospace"
                            font.weight: Font.DemiBold
                        }
                        Controls.Label {
                            text: modelData.class
                            font.family: "monospace"
                            color: Kirigami.Theme.secondaryTextColor
                        }
                        Item { Layout.fillWidth: true }
                        Controls.Label {
                            visible: modelData.privacy_engaged === true
                            text: "privacy shutter"
                            color: Kirigami.Theme.neutralTextColor
                        }
                    }
                    Repeater {
                        model: modelData.evidence
                        delegate: Controls.Label {
                            Layout.fillWidth: true
                            text: "· " + modelData
                            wrapMode: Text.Wrap
                            color: Kirigami.Theme.secondaryTextColor
                        }
                    }
                    Controls.Label {
                        visible: modelData.note !== undefined && modelData.note !== null && modelData.note !== ""
                        Layout.fillWidth: true
                        text: modelData.note === undefined ? "" : String(modelData.note)
                        wrapMode: Text.Wrap
                    }
                }
            }
        }

        RowLayout {
            Controls.Button {
                text: "Pick the camera pair in irlume"
                icon.name: "utilities-terminal"
                visible: root.doc.ok === true
                onClicked: kcm.launchTui("cameras")
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
