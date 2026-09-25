// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Login wiring: the login-status document. A form with the login manager
// and the SELinux module, then the PAM surfaces that exist on this machine,
// with their role and face mode in words. Changing the wiring is a
// transactional flow in the TUI (plan/apply/verify/rollback); this page
// only reports state. The pam-regeneration-guard state lives in the
// Diagnostics doctor document, not here.
pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

import "labels.js" as L

KCMUtils.SimpleKCM {
    id: root

    title: "Login wiring"

    property var doc: null
    property bool pending: false
    property string failure: ""
    property string launchFailure: ""

    readonly property bool loaded: root.doc !== null && root.doc.ok === true
    readonly property bool cliFound: kcm.irlumePath().length > 0
    // The widest a form value may be: on a narrow window the cap leaves
    // room for the margins and the scroll bar (the form is never narrower
    // than its widest row). From the page width, never from the form.
    readonly property real textCap: Math.min(Kirigami.Units.gridUnit * 22,
                                             root.width - Kirigami.Units.gridUnit * 3)
    readonly property var loginData: root.loaded && root.doc.data ? root.doc.data : ({})
    readonly property var manager: root.loginData.login_manager || null
    readonly property var services: root.manager ? L.list(root.manager.services) : []
    readonly property var allSurfaces: L.list(root.loginData.surfaces).filter(s => !!s)
    readonly property var surfaces: root.allSurfaces.filter(s => s.present === true || s.wired === true)
    // Services the login manager consults that have no surface entry: irlume
    // has no wiring recipe for them (MACHINE-API.md).
    readonly property var unmapped: root.services.filter(
        service => !root.allSurfaces.some(s => s.id === service))

    readonly property var managerRow: {
        const m = root.manager;
        if (!root.loaded) {
            return {level: L.UNKNOWN, value: ""};
        }
        if (!m) {
            return {level: L.UNKNOWN, value: "not determined"};
        }
        if (m.known !== true) {
            // Not "none installed": a headless host, or a greeter that
            // registers no display-manager.service.
            return {level: L.UNKNOWN, value: "not determined (no display-manager.service is set)"};
        }
        const name = L.text(m.name).length > 0 ? L.text(m.name) : "unnamed login manager";
        if (m.recognized === false) {
            return {level: L.ATTENTION, value: name + " (irlume cannot wire face login for it)"};
        }
        return {level: L.GOOD, value: name};
    }
    readonly property var selinuxRow: {
        switch (root.loginData.selinux_module) {
        case "loaded":
            return {level: L.GOOD, value: "loaded", hint: ""};
        case "not-loaded":
            return {level: L.ATTENTION, value: "not loaded", hint: ""};
        case "unknown":
            // Also what irlume reports where the SELinux tools are not
            // installed, so the hint does not claim more than that.
            return {level: L.UNKNOWN, value: "not determined",
                    hint: "Reading it needs administrator rights on SELinux systems."};
        default:
            return {level: L.UNKNOWN, value: L.text(root.loginData.selinux_module)};
        }
    }

    function refresh() {
        root.failure = "";
        root.pending = true;
        kcm.request("login");
    }

    function launch() {
        root.launchFailure = "";
        kcm.launchTui("login", "login");
    }

    Component.onCompleted: root.refresh()

    Connections {
        target: kcm

        function onDocumentReady(name, document) {
            if (name === "login") {
                root.doc = document;
                root.failure = "";
                root.pending = false;
            }
        }
        function onRequestFailed(name, reason) {
            if (name === "login") {
                // A failed request leaves no document: the page shows why,
                // not the previous answer as if it were current.
                root.doc = null;
                root.failure = reason;
                root.pending = false;
            }
        }
        function onLaunchFailed(origin, reason) {
            // Only this page's own clicks: a launch that fails after the
            // user moved to another page is not that page's error.
            if (origin === "login") {
                root.launchFailure = reason;
            }
        }
    }

    header: ColumnLayout {
        spacing: 0

        PageMessage {
            objectName: "requestMessage"
            action: "read the login wiring"
            failure: root.failure
            refusal: root.doc
            pending: root.pending
            failureRetryable: root.cliFound
            onRetryRequested: root.refresh()
        }
        PageMessage {
            objectName: "launchMessage"
            action: "open irlume"
            failure: root.launchFailure
            canRetry: false
        }
        Kirigami.InlineMessage {
            objectName: "unmappedMessage"
            Layout.fillWidth: true
            position: Kirigami.InlineMessage.Position.Header
            visible: root.unmapped.length > 0
            type: Kirigami.MessageType.Warning
            text: "irlume has no wiring recipe for " + root.unmapped.join(", ")
                + ", which the login manager uses."
        }
    }

    ColumnLayout {
        spacing: Kirigami.Units.largeSpacing

        Kirigami.LoadingPlaceholder {
            objectName: "loading"
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Kirigami.Units.gridUnit * 4
            visible: root.doc === null && root.pending
            text: "Reading the login wiring…"
        }

        Kirigami.PlaceholderMessage {
            objectName: "unavailable"
            Layout.fillWidth: true
            Layout.topMargin: Kirigami.Units.gridUnit * 2
            Layout.leftMargin: Kirigami.Units.largeSpacing
            Layout.rightMargin: Kirigami.Units.largeSpacing
            visible: !root.loaded && !root.pending
            icon.name: "dialog-warning"
            text: "No login wiring available"
            explanation: "The message at the top says why. Refresh to ask again."
        }

        Kirigami.FormLayout {
            id: form
            objectName: "loginForm"
            Layout.fillWidth: true
            visible: root.loaded

            StateValue {
                objectName: "managerRow"
                widthCap: root.textCap
                Kirigami.FormData.label: "Login manager:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "Login manager"
                level: root.managerRow.level
                value: root.managerRow.value
            }
            StateValue {
                objectName: "selinuxRow"
                widthCap: root.textCap
                // Absent on hosts whose engine does not report it.
                visible: root.loginData.selinux_module !== undefined && root.loginData.selinux_module !== null
                Kirigami.FormData.label: "SELinux module:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "SELinux module"
                level: root.selinuxRow.level
                value: root.selinuxRow.value
                hint: L.text(root.selinuxRow.hint)
            }
            // The last child: the surfaces below are outside this form.
            Kirigami.Separator {
                objectName: "surfacesSection"
                Layout.fillWidth: true
                Kirigami.FormData.isSection: true
                Kirigami.FormData.label: "Surfaces"
            }
        }

        SecondaryLabel {
            objectName: "noSurfaces"
            Layout.alignment: Qt.AlignHCenter
            visible: root.loaded && root.surfaces.length === 0
            text: "None of the login surfaces irlume knows is present on this machine."
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
        }

        // A layout of its own holds only the Repeater, so the delegates keep
        // their model order (nothing static follows them in this layout).
        ColumnLayout {
            objectName: "surfaceList"
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            // As wide as the form above, so the list lines up under its
            // section heading.
            Layout.maximumWidth: Math.max(form.implicitWidth, Kirigami.Units.gridUnit * 20)
            Layout.leftMargin: Kirigami.Units.largeSpacing
            Layout.rightMargin: Kirigami.Units.largeSpacing
            spacing: Kirigami.Units.largeSpacing
            visible: root.loaded && root.surfaces.length > 0

            Repeater {
                model: root.surfaces

                delegate: RowLayout {
                    id: surface

                    required property var modelData
                    readonly property string surfaceId: L.text(surface.modelData.id)
                    readonly property bool wired: surface.modelData.wired === true
                    readonly property bool ownLoginScreen: root.services.indexOf(surface.surfaceId) >= 0
                    // This machine's own login screen without face login is
                    // worth a look; any other unwired surface is a choice.
                    readonly property string level: surface.wired ? L.GOOD
                        : surface.ownLoginScreen ? L.ATTENTION : L.NEUTRAL
                    readonly property string title: surface.surfaceId
                        + (surface.ownLoginScreen ? " (this machine's login screen)" : "")
                    readonly property string details: {
                        const parts = [L.loginRole(surface.modelData.role)];
                        if (surface.wired) {
                            const mode = L.loginMode(surface.modelData.mode);
                            parts.push(mode.length > 0 ? ("wired, " + mode) : "wired");
                        } else {
                            parts.push("not wired");
                        }
                        return parts.filter(part => part.length > 0).join(" · ");
                    }

                    objectName: "surface-" + surface.surfaceId
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.largeSpacing

                    Accessible.role: Accessible.StaticText
                    Accessible.name: surface.title + ", " + surface.details

                    Kirigami.Icon {
                        Layout.alignment: Qt.AlignTop
                        implicitWidth: Kirigami.Units.iconSizes.smallMedium
                        implicitHeight: Kirigami.Units.iconSizes.smallMedium
                        source: L.levelIcon(surface.level)
                        Accessible.ignored: true
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0

                        Controls.Label {
                            Layout.fillWidth: true
                            text: surface.title
                            wrapMode: Text.Wrap
                            font.weight: Font.DemiBold
                            Accessible.ignored: true
                        }
                        SecondaryLabel {
                            Layout.fillWidth: true
                            text: surface.details
                            wrapMode: Text.Wrap
                            Accessible.ignored: true
                        }
                    }
                }
            }
        }
    }

    footer: PageFooter {
        busy: root.pending
        // While nothing is on screen the loading placeholder says it.
        busyText: root.doc === null ? "" : "Reading the login wiring…"
        active: root.isCurrentPage
        actionText: root.loaded ? "Change wiring in irlume" : ""
        onActionTriggered: root.launch()
        onRefreshRequested: root.refresh()
    }
}
