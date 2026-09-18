// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Login wiring page: the login-status document. Changing the wiring is a
// transactional flow in the TUI (plan/apply/verify/rollback); this page
// only reports state. The pam-regeneration-guard state lives in the
// Diagnostics doctor document, not here.
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

    readonly property var surfaces: doc && doc.ok ? doc.data.surfaces : []

    function refresh() {
        failure = "";
        pending = true;
        kcm.request("login");
    }

    Component.onCompleted: refresh()

    Connections {
        target: kcm

        function onDocumentReady(name, document) {
            if (name === "login") {
                root.doc = document;
                root.pending = false;
            }
        }
        function onRequestFailed(name, reason) {
            if (name === "login") {
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

        Kirigami.AbstractCard {
            Layout.fillWidth: true
            visible: root.doc.ok === true
            contentItem: ColumnLayout {
                spacing: Kirigami.Units.smallSpacing
                Controls.Label {
                    text: root.doc.ok && root.doc.data.login_manager.known
                          ? ("Login manager: " + root.doc.data.login_manager.name)
                          : "Login manager: not recognized"
                    font.weight: Font.DemiBold
                }
                Controls.Label {
                    visible: root.doc.ok && root.doc.data.selinux_module !== undefined
                    enabled: false
                    text: "SELinux module: " + root.doc.data.selinux_module
                }
            }
        }

        Repeater {
            model: root.surfaces

            delegate: Kirigami.AbstractCard {
                Layout.fillWidth: true
                visible: modelData.present === true || modelData.wired === true
                contentItem: RowLayout {
                    spacing: Kirigami.Units.largeSpacing
                    Controls.Label {
                        text: modelData.id
                        font.family: "monospace"
                        font.weight: Font.DemiBold
                    }
                    Controls.Label {
                        Layout.fillWidth: true
                        text: modelData.role
                        color: Kirigami.Theme.secondaryTextColor
                    }
                    Controls.Label {
                        visible: modelData.mode !== undefined
                        text: modelData.mode
                        color: Kirigami.Theme.secondaryTextColor
                    }
                    Controls.Label {
                        text: modelData.wired ? "wired" : "not wired"
                        color: modelData.wired ? Kirigami.Theme.positiveTextColor
                                              : Kirigami.Theme.neutralTextColor
                    }
                }
            }
        }

        RowLayout {
            Controls.Button {
                text: "Change wiring in irlume"
                icon.name: "utilities-terminal"
                visible: root.doc.ok === true
                onClicked: kcm.launchTui("login")
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
