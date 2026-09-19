// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Cameras: the census document as native form rows. Read-only capability
// (node opens for classification, no streaming, no daemon). The CONFIGURED
// pair is not shown: contract 1 publishes camera capability without
// identity; picking the pair happens in the TUI.
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

    readonly property var entries: doc && doc.ok ? doc.data.entries : []
    readonly property string listingError: doc && doc.ok && doc.data.listing_error
        ? String(doc.data.listing_error) : ""

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

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: root.listingError.length > 0
            type: Kirigami.MessageType.Warning
            text: "The census may be incomplete: " + root.listingError
        }

        Controls.Label {
            visible: root.doc.ok === true && root.entries.length === 0 && root.listingError.length === 0
            enabled: false
            text: root.pending ? "Classifying camera devices…" : "No camera-like devices were classified."
        }

        Repeater {
            model: root.entries

            delegate: ColumnLayout {
                spacing: Kirigami.Units.smallSpacing

                RowLayout {
                    spacing: Kirigami.Units.largeSpacing
                    Controls.Label {
                        Kirigami.FormData.label: "Device:"
                        text: modelData.node
                        font.weight: Font.DemiBold
                    }
                    Controls.Label {
                        text: modelData.verdict
                        color: modelData.verdict === "supported"
                              ? Kirigami.Theme.positiveTextColor
                              : Kirigami.Theme.disabledTextColor
                    }
                }
                Controls.Label {
                    Kirigami.FormData.label: "Class:"
                    text: modelData.class
                    color: Kirigami.Theme.disabledTextColor
                }
                Repeater {
                    model: modelData.evidence
                    delegate: Controls.Label {
                        Layout.fillWidth: true
                        text: modelData
                        wrapMode: Text.Wrap
                        color: Kirigami.Theme.disabledTextColor
                    }
                }
                Controls.Label {
                    visible: modelData.note !== undefined && modelData.note !== null && modelData.note !== ""
                    Layout.fillWidth: true
                    text: modelData.note === undefined ? "" : String(modelData.note)
                    wrapMode: Text.Wrap
                }
                Kirigami.Separator {
                    Layout.fillWidth: true
                }
            }
        }

        RowLayout {
            Kirigami.FormData.label: "Pair:"
            Controls.Button {
                text: "Pick the camera pair in irlume"
                icon.name: "utilities-terminal"
                visible: root.doc.ok === true
                onClicked: kcm.launchTui("cameras")
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
