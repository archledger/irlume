// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Overview page: version/capability handshake plus the status document as
// a card list, with launch buttons into the TUI for anything interactive.
import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

KCMUtils.ScrollViewKCM {
    id: root

    property var versionDoc: ({})
    property var statusDoc: ({})
    property bool pending: false
    property string failure: ""

    readonly property bool contractOk: versionDoc && versionDoc.ok
        && versionDoc.contract_version === 1
    readonly property var caps: root.contractOk ? versionDoc.data.capabilities : []

    function refresh() {
        failure = "";
        pending = true;
        kcm.request("version");
        kcm.request("status");
    }

    Component.onCompleted: refresh()

    Connections {
        target: kcm

        function onDocumentReady(name, doc) {
            if (name === "version") {
                root.versionDoc = doc;
            } else if (name === "status") {
                root.statusDoc = doc;
            }
            root.pending = false;
        }
        function onRequestFailed(name, reason) {
            root.pending = false;
            root.failure = reason;
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

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: !root.pending && root.statusDoc.ok === false
            type: Kirigami.MessageType.Warning
            text: root.statusDoc && root.statusDoc.error
                  ? (root.statusDoc.error.message || root.statusDoc.error.code
                     + (root.statusDoc.error.retryable ? " (retryable)" : ""))
                  : "irlume did not answer"
        }

        Kirigami.AbstractCard {
            Layout.fillWidth: true
            visible: root.contractOk
            contentItem: ColumnLayout {
                spacing: Kirigami.Units.smallSpacing
                Controls.Label {
                    text: "irlume " + root.versionDoc.engine_version
                    font.weight: Font.Bold
                }
                Controls.Label {
                    enabled: false
                    text: "Machine API contract " + root.versionDoc.contract_version
                          + "  ·  " + root.caps.length + " capabilities"
                    elide: Text.ElideRight
                }
            }
        }

        Repeater {
            model: {
                const doc = root.statusDoc;
                if (!doc || !doc.ok) {
                    return [];
                }
                const d = doc.data;
                const rows = [];
                function add(label, value, good) {
                    rows.push({label: label, value: value, good: good});
                }
                add("Daemon", d.daemon, d.daemon === "running");
                add("Enrollment",
                    d.enrollment.known === false
                        ? "unknown"
                        : (d.enrollment.profiles > 0
                            ? (d.enrollment.profiles + " profile(s), " + d.enrollment.scans + " scan(s)")
                            : "none yet"),
                    d.enrollment.known === true && d.enrollment.profiles > 0);
                add("Keyring unlock",
                    d.keyring.armed === true ? "armed"
                      : d.keyring.armed === false ? "not armed"
                      : "unknown",
                    d.keyring.armed === true);
                add("Templates at rest",
                    d.templates === "encrypted" ? "encrypted"
                      : d.templates === "plaintext" ? "not encrypted yet"
                      : String(d.templates),
                    d.templates === "encrypted");
                add("Recovery passphrase",
                    d.recovery.passphrase_set === true ? "set"
                      : d.recovery.passphrase_set === false ? "not set"
                      : "unknown",
                    d.recovery.passphrase_set === true);
                add("Face sensors",
                    d.face_disabled ? "face disabled"
                      : (d.camera.known
                          ? (d.camera.rgb && d.camera.ir ? "RGB + IR (secure tier)"
                             : d.camera.ir ? "IR"
                             : d.camera.rgb ? "RGB only"
                             : "none classified")
                          : "unknown"),
                    !d.face_disabled);
                return rows;
            }

            delegate: Kirigami.AbstractCard {
                Layout.fillWidth: true
                contentItem: RowLayout {
                    spacing: Kirigami.Units.largeSpacing
                    Controls.Label {
                        text: modelData.good ? "●" : "○"
                        color: modelData.good ? Kirigami.Theme.positiveTextColor : Kirigami.Theme.neutralTextColor
                    }
                    Controls.Label {
                        text: modelData.label
                        Layout.fillWidth: true
                        font.weight: Font.DemiBold
                    }
                    Controls.Label {
                        text: modelData.value
                        color: Kirigami.Theme.secondaryTextColor
                    }
                }
            }
        }

        // Launch actions: interactive and privileged work happens in the TUI.
        Kirigami.AbstractCard {
            Layout.fillWidth: true
            visible: root.statusDoc.ok === true
            contentItem: Flow {
                spacing: Kirigami.Units.smallSpacing
                Repeater {
                    model: [
                        {label: "Enroll face / add scans", page: "faces"},
                        {label: "Choose cameras", page: "cameras"},
                        {label: "Arm wallet unlock", page: "wallet"},
                        {label: "Set recovery passphrase", page: "recovery"},
                    ]
                    delegate: Controls.Button {
                        text: modelData.label
                        icon.name: "utilities-terminal"
                        onClicked: kcm.launchTui(modelData.page)
                    }
                }
            }
        }

        RowLayout {
            spacing: Kirigami.Units.smallSpacing
            Controls.Button {
                text: "Diagnostics"
                icon.name: "tools-report-bug"
                visible: root.caps.indexOf("doctor-json") >= 0
                onClicked: kcm.push("DiagnosticsPage.qml")
            }
            Controls.Button {
                text: "Cameras"
                icon.name: "camera-video"
                visible: root.caps.indexOf("camera-census") >= 0
                onClicked: kcm.push("CamerasPage.qml")
            }
            Controls.Button {
                text: "Login wiring"
                icon.name: "preferences-system-users"
                visible: root.caps.indexOf("login-status-json") >= 0
                onClicked: kcm.push("LoginPage.qml")
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
