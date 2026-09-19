// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Overview: the machine's face-auth status as a native Kirigami form, the
// launch actions that delegate to the TUI, and the deeper pages. Mirrors
// the Quick Settings / Mouse page idiom: FormLayout rows with right-aligned
// bold labels, section separators, footer actions, no cards.
import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

KCMUtils.SimpleKCM {
    id: root

    property var versionDoc: ({})
    property var statusDoc: ({})
    property bool pending: false
    property string failure: ""

    readonly property bool contractOk: versionDoc !== undefined
        && versionDoc.ok === true && versionDoc.contract_version === 1
    readonly property var caps: root.contractOk ? versionDoc.data.capabilities : []
    readonly property var rows: {
        const doc = root.statusDoc;
        if (!doc || !doc.ok) {
            return [];
        }
        const d = doc.data;
        // Sub-objects are guaranteed by the contract, but a short or
        // malformed document must degrade to "unknown" rows, never a
        // TypeError.
        const e = d.enrollment || {};
        const k = d.keyring || {};
        const r = d.recovery || {};
        const cam = d.camera || {};
        const out = [];
        function add(label, value, good) {
            out.push({label: label, value: value, good: good});
        }
        add("Daemon", d.daemon, d.daemon === "running");
        add("Enrollment",
            e.known === false
                ? "unknown"
                : (e.profiles > 0
                    ? (e.profiles + " profile(s), " + e.scans + " scan(s)")
                    : "none yet"),
            e.known === true && e.profiles > 0);
        add("Keyring unlock",
            k.armed === true ? "armed"
              : k.armed === false ? "not armed"
              : "unknown",
            k.armed === true);
        add("Templates at rest",
            d.templates === "encrypted" ? "encrypted"
              : d.templates === "plaintext" ? "not encrypted yet"
              : String(d.templates),
            d.templates === "encrypted");
        add("Recovery passphrase",
            r.passphrase_set === true ? "set"
              : r.passphrase_set === false ? "not set"
              : "unknown",
            r.passphrase_set === true);
        add("Face sensors",
            d.face_disabled ? "face disabled"
              : (cam.known
                  ? (cam.rgb && cam.ir ? "RGB + IR (secure tier)"
                     : cam.ir ? "IR"
                     : cam.rgb ? "RGB only"
                     : "none classified")
                  : "unknown"),
            !d.face_disabled);
        return out;
    }

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
            visible: !root.pending && root.statusDoc.ok === false
            type: Kirigami.MessageType.Warning
            text: root.statusDoc && root.statusDoc.error
                  ? (root.statusDoc.error.message || root.statusDoc.error.code)
                  : "irlume did not answer"
        }

        RowLayout {
            Kirigami.FormData.label: "Version:"
            Controls.Label {
                text: root.versionDoc.ok === true
                      ? ("irlume " + root.versionDoc.engine_version
                         + "  ·  Machine API contract " + root.versionDoc.contract_version)
                      : "irlume"
                color: Kirigami.Theme.disabledTextColor
            }
        }

        Kirigami.Separator {
            Layout.fillWidth: true
            Kirigami.FormData.isSection: true
            Kirigami.FormData.label: "Status"
        }

        Repeater {
            model: root.rows

            delegate: RowLayout {
                Kirigami.FormData.label: modelData ? modelData.label + ":" : ""
                Controls.Label {
                    text: modelData && modelData.good ? "●" : "○"
                    color: modelData && modelData.good
                          ? Kirigami.Theme.positiveTextColor
                          : Kirigami.Theme.neutralTextColor
                }
                Controls.Label {
                    text: modelData ? modelData.value : ""
                    color: Kirigami.Theme.disabledTextColor
                }
            }
        }

        Controls.Label {
            visible: root.rows.length === 0 && !root.pending
            enabled: false
            text: root.pending ? "Reading status…" : "No status available."
        }

        Kirigami.Separator {
            Layout.fillWidth: true
            Kirigami.FormData.isSection: true
            Kirigami.FormData.label: "Make changes"
        }

        Controls.Label {
            enabled: false
            visible: root.statusDoc.ok === true
            text: "Every change happens in the irlume terminal interface, with its own confirmation and authorization. Nothing is changed from this panel."
            wrapMode: Text.Wrap
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
        }

        RowLayout {
            Kirigami.FormData.label: "Enrollment:"
            visible: root.statusDoc.ok === true
            Controls.Button {
                text: "Enroll face / add scans"
                icon.name: "utilities-terminal"
                onClicked: kcm.launchTui("faces")
            }
            Controls.Button {
                text: "Choose cameras"
                icon.name: "utilities-terminal"
                onClicked: kcm.launchTui("cameras")
            }
        }

        RowLayout {
            Kirigami.FormData.label: "Secrets:"
            visible: root.statusDoc.ok === true
            Controls.Button {
                text: "Arm wallet unlock"
                icon.name: "utilities-terminal"
                onClicked: kcm.launchTui("wallet")
            }
            Controls.Button {
                text: "Set recovery passphrase"
                icon.name: "utilities-terminal"
                onClicked: kcm.launchTui("recovery")
            }
        }

        Kirigami.Separator {
            Layout.fillWidth: true
            Kirigami.FormData.isSection: true
            Kirigami.FormData.label: "More details"
        }

        RowLayout {
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
