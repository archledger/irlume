// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Login wiring: the login-status document as native form rows. Changing
// the wiring is a transactional flow in the TUI
// (plan/apply/verify/rollback); this page only reports state. The
// pam-regeneration-guard state lives in the Diagnostics doctor document,
// not here.
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

    readonly property var surfaces: doc && doc.ok ? (doc.data || {}).surfaces || [] : []

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

        RowLayout {
            Kirigami.FormData.label: "Login manager:"
            Controls.Label {
                text: root.doc.ok && (root.doc.data || {}).login_manager !== undefined && root.doc.data.login_manager.known
                      ? root.doc.data.login_manager.name
                      : "not recognized"
                color: root.doc.ok && (root.doc.data || {}).login_manager !== undefined && root.doc.data.login_manager.known
                      ? Kirigami.Theme.textColor
                      : Kirigami.Theme.disabledTextColor
            }
        }

        RowLayout {
            Kirigami.FormData.label: "SELinux module:"
            Controls.Label {
                text: root.doc.ok ? String((root.doc.data || {}).selinux_module) : ""
                color: Kirigami.Theme.disabledTextColor
            }
        }

        Kirigami.Separator {
            Layout.fillWidth: true
            Kirigami.FormData.isSection: true
            Kirigami.FormData.label: "Surfaces"
        }

        Repeater {
            model: root.surfaces.filter(s => s.present === true || s.wired === true)

            delegate: RowLayout {
                Kirigami.FormData.label: modelData.id + ":"
                Controls.Label {
                    text: modelData.role
                    color: Kirigami.Theme.disabledTextColor
                }
                Controls.Label {
                    visible: modelData.mode !== undefined
                    text: modelData.mode
                    color: Kirigami.Theme.disabledTextColor
                }
                Controls.Label {
                    text: modelData.wired ? "wired" : "present, not wired"
                    color: modelData.wired ? Kirigami.Theme.positiveTextColor
                                          : Kirigami.Theme.neutralTextColor
                }
            }
        }

        RowLayout {
            Kirigami.FormData.label: "Change:"
            Controls.Button {
                text: "Change wiring in irlume"
                icon.name: "utilities-terminal"
                visible: root.doc.ok === true
                onClicked: kcm.launchTui("login")
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
