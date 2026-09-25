// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Overview: the machine's face-auth status as a native Kirigami form, the
// launch actions that delegate to the TUI, and the deeper pages. Mirrors
// the Quick Settings / Mouse page idiom: FormLayout rows with right-aligned
// labels, section separators, footer actions, no cards.
//
// Every FormLayout child here is static. Kirigami's FormLayout reads
// FormData only from its direct children and orders rows by child order,
// which a Repeater does not keep; so the forms have no Repeater. The form
// is split in two twinned halves only so that the "no status" message can
// sit between the version and the navigation buttons.
pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

import "labels.js" as L

KCMUtils.SimpleKCM {
    id: root

    property var versionDoc: null
    property var statusDoc: null
    property bool versionPending: false
    property bool statusPending: false
    property string versionFailure: ""
    property string statusFailure: ""
    property string launchFailure: ""

    readonly property bool pending: root.versionPending || root.statusPending
    // The module looks for the irlume command once; without it, asking
    // again cannot help.
    readonly property bool cliFound: kcm.irlumePath().length > 0
    // Room for a row of buttons beside the form labels. Taken from the page
    // width, which the page stack sets, and never from the form's own size
    // (the rows' column count feeds that size, so it would loop).
    readonly property real buttonRoom: root.width - Kirigami.Units.gridUnit * 12
    // The widest a wrapping text may be. The form is never narrower than
    // its widest row, so on a narrow window the cap leaves room for the
    // margins and the scroll bar. From the page width, as above.
    readonly property real textCap: Math.min(Kirigami.Units.gridUnit * 22,
                                             root.width - Kirigami.Units.gridUnit * 3)
    readonly property bool contractOk: root.versionDoc !== null && root.versionDoc.ok === true
        && root.versionDoc.contract_version === 1
    readonly property var caps: root.contractOk && root.versionDoc.data
        ? L.list(root.versionDoc.data.capabilities) : []
    // The status data when the document is a usable answer, else null.
    readonly property var status: root.statusDoc !== null && root.statusDoc.ok === true
        && root.statusDoc.data ? root.statusDoc.data : null

    // Sub-objects are guaranteed by the contract, but a short or malformed
    // document must degrade to "not determined" rows, never a TypeError.
    readonly property var daemonRow: {
        const d = root.status ? root.status.daemon : undefined;
        switch (d) {
        case "running":
            return {level: L.GOOD, value: "running", hint: ""};
        case "starting":
            return {level: L.ATTENTION, value: "starting",
                    hint: "Loading its models; refresh in a few seconds."};
        case "access-denied":
            return {level: L.PROBLEM, value: "this account cannot reach irlumed", hint: ""};
        case "unreachable":
            return {level: L.PROBLEM, value: "not reachable",
                    hint: "Face login is unavailable; the password still works."};
        default:
            return {level: L.UNKNOWN, value: d === undefined ? "not determined" : String(d), hint: ""};
        }
    }
    readonly property var enrollmentRow: {
        const e = (root.status && root.status.enrollment) || {};
        if (e.known !== true || typeof e.profiles !== "number") {
            return {level: L.UNKNOWN, value: "not determined"};
        }
        if (e.profiles > 0) {
            const scans = typeof e.scans === "number" ? (", " + L.plural(e.scans, "scan", "scans")) : "";
            return {level: L.GOOD, value: L.plural(e.profiles, "profile", "profiles") + scans};
        }
        // Nothing to do when the sign-in method does not use face at all.
        if (root.status.face_disabled === true) {
            return {level: L.NEUTRAL, value: "no face enrolled"};
        }
        return {level: L.ATTENTION, value: "no face enrolled yet"};
    }
    readonly property bool keyringArmed: !!root.status && !!root.status.keyring
        && root.status.keyring.armed === true
    readonly property var keyringRow: {
        const k = (root.status && root.status.keyring) || {};
        // The tier in words, as the TUI shows it; the policy text also
        // carries identifiers (the pcrlock NV index) that stay off the page.
        const policy = k.policy ? ("Sealing: " + L.sealTier(k.policy)) : "";
        if (k.armed === true) {
            return {level: L.GOOD, value: "armed", hint: policy};
        }
        if (k.armed === false) {
            return {level: L.NEUTRAL, value: "not armed", hint: ""};
        }
        return {level: L.UNKNOWN, value: "not determined", hint: ""};
    }
    readonly property bool passphraseSet: !!root.status && !!root.status.recovery
        && root.status.recovery.passphrase_set === true
    readonly property var templatesRow: {
        const s = root.status || {};
        const r = s.recovery || {};
        switch (s.templates) {
        case "encrypted":
            // An absent key_present reads as true (older daemons never
            // send it); false means the templates cannot be opened.
            if (r.key_present === false) {
                return {level: L.PROBLEM, value: "encrypted, key missing",
                        hint: r.passphrase_set === true
                              ? "The templates cannot be opened. Run irlume recovery restore to recreate the key from the recovery passphrase."
                              : "The templates cannot be opened. Enroll again to use face login."};
            }
            return {level: L.GOOD, value: "encrypted", hint: ""};
        case "plaintext":
            return {level: L.ATTENTION, value: "not encrypted yet", hint: ""};
        default:
            return {level: L.UNKNOWN,
                    value: s.templates === undefined || s.templates === "unknown" ? "not determined" : String(s.templates),
                    hint: ""};
        }
    }
    readonly property var recoveryRow: {
        const r = (root.status && root.status.recovery) || {};
        if (r.passphrase_set === true) {
            return {level: L.GOOD, value: "set"};
        }
        if (r.passphrase_set === false) {
            return {level: L.ATTENTION, value: "not set"};
        }
        return {level: L.UNKNOWN, value: "not determined"};
    }
    readonly property var sensorsRow: {
        const s = root.status || {};
        const cam = s.camera || {};
        if (s.face_disabled === true) {
            return {level: L.NEUTRAL, value: "not used (the sign-in method is fingerprint only)", hint: ""};
        }
        if (cam.known === true) {
            if (cam.rgb === true && cam.ir === true) {
                return {level: L.GOOD, value: "RGB + IR (secure tier)", hint: ""};
            }
            if (cam.ir === true) {
                return {level: L.GOOD, value: "IR", hint: ""};
            }
            if (cam.rgb === true) {
                return {level: L.ATTENTION, value: "RGB only", hint: ""};
            }
            return {level: L.PROBLEM, value: "none classified", hint: ""};
        }
        // Without a daemon observation the booleans only say which
        // configured camera paths exist.
        const configured = cam.rgb === true && cam.ir === true ? "RGB + IR configured"
            : cam.ir === true ? "IR configured"
            : cam.rgb === true ? "RGB configured"
            : "none configured";
        // Why it was not checked, when the daemon state says why.
        const why = s.daemon === "starting" ? " (daemon still starting)"
            : s.daemon === "access-denied" ? " (daemon not reachable from this account)"
            : s.daemon === "unreachable" ? " (daemon not reachable)"
            : "";
        return {level: L.UNKNOWN, value: configured + ", not checked" + why, hint: ""};
    }
    readonly property var fingerprintRow: {
        const s = root.status || {};
        if (s.fingerprint_known !== true) {
            return {level: L.UNKNOWN, value: "not determined"};
        }
        if (s.fingerprint === true) {
            return {level: L.GOOD, value: "found"};
        }
        // No reader is only information while face can still sign in.
        return s.auth_method === "fingerprint" || s.face_disabled === true
            ? {level: L.ATTENTION, value: "none found (the sign-in method is fingerprint)"}
            : {level: L.NEUTRAL, value: "none found"};
    }

    function refresh() {
        root.versionFailure = "";
        root.statusFailure = "";
        root.versionPending = true;
        root.statusPending = true;
        kcm.request("version");
        kcm.request("status");
    }

    function launch(page) {
        root.launchFailure = "";
        kcm.launchTui(page, "overview");
    }

    Component.onCompleted: root.refresh()

    Connections {
        target: kcm

        function onDocumentReady(name, doc) {
            if (name === "version") {
                root.versionDoc = doc;
                root.versionFailure = "";
                root.versionPending = false;
            } else if (name === "status") {
                root.statusDoc = doc;
                root.statusFailure = "";
                root.statusPending = false;
            }
        }
        function onRequestFailed(name, reason) {
            // A failed request leaves no document: the page shows why,
            // not the previous answer as if it were current.
            if (name === "version") {
                root.versionDoc = null;
                root.versionFailure = reason;
                root.versionPending = false;
            } else if (name === "status") {
                root.statusDoc = null;
                root.statusFailure = reason;
                root.statusPending = false;
            }
        }
        function onLaunchFailed(origin, reason) {
            // Only this page's own clicks: a launch that fails after the
            // user moved to another page is not that page's error.
            if (origin === "overview") {
                root.launchFailure = reason;
            }
        }
    }

    header: ColumnLayout {
        spacing: 0

        PageMessage {
            objectName: "statusMessage"
            action: "read the status"
            failure: root.statusFailure
            refusal: root.statusDoc
            failureRetryable: root.cliFound
            onRetryRequested: root.refresh()
        }
        PageMessage {
            objectName: "versionMessage"
            action: "read the irlume version"
            failure: root.versionFailure
            refusal: root.versionDoc
            failureRetryable: root.cliFound
            onRetryRequested: root.refresh()
        }
        PageMessage {
            objectName: "launchMessage"
            action: "open irlume"
            failure: root.launchFailure
            canRetry: false
        }
    }

    ColumnLayout {
        spacing: Kirigami.Units.largeSpacing

        Kirigami.LoadingPlaceholder {
            objectName: "loading"
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Kirigami.Units.gridUnit * 4
            visible: root.statusDoc === null && root.statusPending
            text: "Reading status…"
        }

        Kirigami.FormLayout {
            id: form
            objectName: "overviewForm"
            Layout.fillWidth: true
            visible: !(root.statusDoc === null && root.statusPending)
            twinFormLayouts: [detailsForm]

            SecondaryLabel {
                objectName: "versionRow"
                Kirigami.FormData.label: "Version:"
                Layout.fillWidth: true
                Layout.maximumWidth: root.textCap
                wrapMode: Text.Wrap
                text: root.contractOk
                      ? ("irlume " + root.versionDoc.engine_version
                         + "  ·  Machine API contract " + root.versionDoc.contract_version)
                      : (root.versionPending ? "" : "not determined")
            }

            Kirigami.Separator {
                objectName: "statusSection"
                Layout.fillWidth: true
                visible: root.status !== null
                Kirigami.FormData.isSection: true
                Kirigami.FormData.label: "Status"
            }

            StateValue {
                objectName: "daemonRow"
                widthCap: root.textCap
                visible: root.status !== null
                Kirigami.FormData.label: "Daemon:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "Daemon"
                level: root.daemonRow.level
                value: root.daemonRow.value
                hint: root.daemonRow.hint
            }
            StateValue {
                objectName: "enrollmentRow"
                widthCap: root.textCap
                visible: root.status !== null
                Kirigami.FormData.label: "Enrollment:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "Enrollment"
                level: root.enrollmentRow.level
                value: root.enrollmentRow.value
            }
            StateValue {
                objectName: "keyringRow"
                widthCap: root.textCap
                visible: root.status !== null
                Kirigami.FormData.label: "Keyring unlock:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "Keyring unlock"
                level: root.keyringRow.level
                value: root.keyringRow.value
                hint: root.keyringRow.hint
            }
            StateValue {
                objectName: "templatesRow"
                widthCap: root.textCap
                visible: root.status !== null
                Kirigami.FormData.label: "Templates at rest:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "Templates at rest"
                level: root.templatesRow.level
                value: root.templatesRow.value
                hint: root.templatesRow.hint
            }
            StateValue {
                objectName: "recoveryRow"
                widthCap: root.textCap
                visible: root.status !== null
                Kirigami.FormData.label: "Recovery passphrase:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "Recovery passphrase"
                level: root.recoveryRow.level
                value: root.recoveryRow.value
            }
            StateValue {
                objectName: "sensorsRow"
                widthCap: root.textCap
                visible: root.status !== null
                Kirigami.FormData.label: "Face sensors:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "Face sensors"
                level: root.sensorsRow.level
                value: root.sensorsRow.value
            }
            StateValue {
                objectName: "fingerprintRow"
                widthCap: root.textCap
                visible: root.status !== null
                Kirigami.FormData.label: "Fingerprint reader:"
                Kirigami.FormData.labelAlignment: Qt.AlignTop
                label: "Fingerprint reader"
                level: root.fingerprintRow.level
                value: root.fingerprintRow.value
            }

            Kirigami.Separator {
                objectName: "changesSection"
                Layout.fillWidth: true
                visible: root.status !== null
                Kirigami.FormData.isSection: true
                Kirigami.FormData.label: "Make changes"
            }

            SecondaryLabel {
                objectName: "changesNote"
                visible: root.status !== null
                Layout.fillWidth: true
                Layout.maximumWidth: root.textCap
                text: "Every change happens in the irlume terminal interface, with its own confirmation and authorization. Nothing is changed from this panel."
                wrapMode: Text.Wrap
            }

            // Button rows put their buttons side by side when they fit and
            // stack them when they do not (narrow windows, large fonts).
            GridLayout {
                objectName: "enrollmentActions"
                visible: root.status !== null
                Kirigami.FormData.label: "Enrollment:"
                columns: enrollButton.implicitWidth + camerasButton.implicitWidth + columnSpacing
                         <= root.buttonRoom ? 2 : 1
                Controls.Button {
                    id: enrollButton
                    text: "Enroll face / add scans"
                    icon.name: "utilities-terminal"
                    onClicked: root.launch("faces")
                }
                Controls.Button {
                    id: camerasButton
                    text: "Choose cameras"
                    icon.name: "utilities-terminal"
                    onClicked: root.launch("cameras")
                }
            }

            GridLayout {
                objectName: "secretsActions"
                visible: root.status !== null
                Kirigami.FormData.label: "Secrets:"
                columns: walletButton.implicitWidth + recoveryButton.implicitWidth + columnSpacing
                         <= root.buttonRoom ? 2 : 1
                Controls.Button {
                    id: walletButton
                    objectName: "walletButton"
                    text: root.keyringArmed ? "Manage wallet unlock" : "Arm wallet unlock"
                    icon.name: "utilities-terminal"
                    onClicked: root.launch("wallet")
                }
                Controls.Button {
                    id: recoveryButton
                    objectName: "recoveryButton"
                    text: root.passphraseSet ? "Change recovery passphrase" : "Set recovery passphrase"
                    icon.name: "utilities-terminal"
                    onClicked: root.launch("recovery")
                }
            }
        }

        Kirigami.PlaceholderMessage {
            objectName: "noStatus"
            Layout.fillWidth: true
            Layout.leftMargin: Kirigami.Units.largeSpacing
            Layout.rightMargin: Kirigami.Units.largeSpacing
            visible: root.status === null && !root.statusPending
            icon.name: "dialog-warning"
            text: "No status available"
            explanation: "The message at the top says why. Refresh to ask again."
        }

        Kirigami.FormLayout {
            id: detailsForm
            objectName: "detailsForm"
            Layout.fillWidth: true
            visible: form.visible && root.caps.length > 0

            Kirigami.Separator {
                objectName: "detailsSection"
                Layout.fillWidth: true
                Kirigami.FormData.isSection: true
                Kirigami.FormData.label: "More details"
            }

            GridLayout {
                objectName: "detailsActions"
                readonly property real oneRow: {
                    let width = 0;
                    let shown = 0;
                    for (const button of [diagnosticsButton, camerasPageButton, loginPageButton]) {
                        if (button.visible) {
                            width += button.implicitWidth;
                            shown += 1;
                        }
                    }
                    return width + Math.max(0, shown - 1) * columnSpacing;
                }
                columns: oneRow <= root.buttonRoom ? 3 : 1
                Controls.Button {
                    id: diagnosticsButton
                    text: "Diagnostics"
                    icon.name: "tools-report-bug"
                    visible: root.caps.indexOf("doctor-json") >= 0
                    onClicked: kcm.push("DiagnosticsPage.qml")
                }
                Controls.Button {
                    id: camerasPageButton
                    text: "Cameras"
                    icon.name: "camera-video"
                    visible: root.caps.indexOf("camera-census") >= 0
                    onClicked: kcm.push("CamerasPage.qml")
                }
                Controls.Button {
                    id: loginPageButton
                    text: "Login wiring"
                    icon.name: "preferences-system-users"
                    visible: root.caps.indexOf("login-status-json") >= 0
                    onClicked: kcm.push("LoginPage.qml")
                }
            }
        }
    }

    footer: PageFooter {
        busy: root.pending
        // While nothing is on screen the loading placeholder says it.
        busyText: root.statusDoc === null ? "" : "Reading status…"
        active: root.isCurrentPage
        onRefreshRequested: root.refresh()
    }
}
