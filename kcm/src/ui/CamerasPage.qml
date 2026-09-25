// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Cameras: the census document, one entry per device with its class and
// verdict in words, whether it is part of an RGB + IR pair, the tier note
// and the evidence on one line. Rows that describe something other than a
// camera (metadata interfaces, test devices) fold into one line at the end.
// Read-only capability (node opens for classification, no streaming, no
// daemon). Picking the pair happens in the TUI.
pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

import "labels.js" as L

KCMUtils.SimpleKCM {
    id: root

    title: "Cameras"

    property var doc: null
    property bool pending: false
    property string failure: ""
    property string launchFailure: ""

    readonly property bool loaded: root.doc !== null && root.doc.ok === true
    readonly property bool cliFound: kcm.irlumePath().length > 0
    readonly property var censusData: root.loaded && root.doc.data ? root.doc.data : ({})
    readonly property var entries: L.list(root.censusData.entries)
    readonly property var devices: root.entries.filter(entry => !L.censusIsAside(entry || {}))
    readonly property var asides: root.entries.filter(entry => L.censusIsAside(entry || {}))
    readonly property string listingError: L.text(root.censusData.listing_error)

    // "/dev/video1, /dev/video3 (metadata interfaces, not cameras)", one
    // group per class.
    readonly property string asideText: {
        const groups = {};
        const order = [];
        for (const entry of root.asides) {
            const key = L.text(entry["class"]);
            if (!(key in groups)) {
                groups[key] = [];
                order.push(key);
            }
            groups[key].push(L.censusTitle(entry).split(": ")[0]);
        }
        const parts = [];
        for (const key of order) {
            const nodes = groups[key];
            let what;
            if (key === "metadata_only") {
                what = nodes.length === 1 ? "metadata interface, not a camera" : "metadata interfaces, not cameras";
            } else if (key === "dummy_node") {
                what = nodes.length === 1 ? "test device, not hardware" : "test devices, not hardware";
            } else {
                what = L.censusClass({"class": key});
            }
            parts.push(nodes.join(", ") + " (" + what + ")");
        }
        return parts.join("; ");
    }

    readonly property var shutterNodes: root.entries
        .filter(entry => entry && entry.privacy_engaged === true)
        .map(entry => L.text(entry.node).length > 0 ? L.text(entry.node) : L.censusTitle(entry))

    function refresh() {
        root.failure = "";
        root.pending = true;
        kcm.request("census");
    }

    function launch() {
        root.launchFailure = "";
        kcm.launchTui("cameras", "cameras");
    }

    Component.onCompleted: root.refresh()

    Connections {
        target: kcm

        function onDocumentReady(name, document) {
            if (name === "census") {
                root.doc = document;
                root.failure = "";
                root.pending = false;
            }
        }
        function onRequestFailed(name, reason) {
            if (name === "census") {
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
            if (origin === "cameras") {
                root.launchFailure = reason;
            }
        }
    }

    header: ColumnLayout {
        spacing: 0

        PageMessage {
            objectName: "requestMessage"
            action: "list the cameras"
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
            objectName: "shutterMessage"
            Layout.fillWidth: true
            position: Kirigami.InlineMessage.Position.Header
            visible: root.shutterNodes.length > 0
            type: Kirigami.MessageType.Warning
            // The census covers every video device, not only the pair face
            // login uses, so the warning speaks for the named cameras only.
            text: root.shutterNodes.length === 1
                  ? ("The privacy shutter on " + root.shutterNodes[0] + " is closed; that camera sees nothing until it is opened.")
                  : ("The privacy shutters on " + root.shutterNodes.join(", ") + " are closed; those cameras see nothing until they are opened.")
        }
        Kirigami.InlineMessage {
            objectName: "listingMessage"
            Layout.fillWidth: true
            position: Kirigami.InlineMessage.Position.Header
            visible: root.listingError.length > 0
            type: Kirigami.MessageType.Warning
            // The error is free text: shortened, and breakable anywhere a
            // path separates, because this message wraps only between words.
            text: "The list may be incomplete: the devices could not all be listed ("
                + L.breakable(root.listingError, 160) + ")."
        }
    }

    ColumnLayout {
        spacing: Kirigami.Units.largeSpacing

        Kirigami.LoadingPlaceholder {
            objectName: "loading"
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Kirigami.Units.gridUnit * 4
            visible: root.doc === null && root.pending
            text: "Classifying camera devices…"
        }

        Kirigami.PlaceholderMessage {
            objectName: "empty"
            Layout.fillWidth: true
            Layout.topMargin: Kirigami.Units.gridUnit * 2
            Layout.leftMargin: Kirigami.Units.largeSpacing
            Layout.rightMargin: Kirigami.Units.largeSpacing
            visible: root.devices.length === 0 && !(root.doc === null && root.pending)
            icon.name: root.loaded ? "camera-video" : "dialog-warning"
            text: root.loaded ? "No cameras found" : "No camera list available"
            explanation: !root.loaded ? "The message at the top says why. Refresh to ask again."
                : root.listingError.length > 0 ? "The device list could not be read completely."
                : root.asides.length > 0 ? "Only devices that are not cameras were found."
                : "No camera-like devices were found on this machine."
        }

        // A layout of its own holds only the Repeater, so the delegates keep
        // their model order (nothing static follows them in this layout).
        ColumnLayout {
            objectName: "deviceList"
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 36
            Layout.leftMargin: Kirigami.Units.largeSpacing
            Layout.rightMargin: Kirigami.Units.largeSpacing
            Layout.topMargin: Kirigami.Units.largeSpacing
            spacing: Kirigami.Units.largeSpacing * 2
            visible: root.devices.length > 0

            Repeater {
                model: root.devices

                delegate: RowLayout {
                    id: device

                    required property var modelData
                    readonly property var entry: device.modelData || ({})
                    readonly property string level: L.censusVerdictLevel(device.entry.verdict)
                    readonly property string evidence: L.list(device.entry.evidence).join(" · ")

                    objectName: "device-" + L.text(device.entry.node)
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.largeSpacing

                    Accessible.role: Accessible.StaticText
                    Accessible.name: L.censusTitle(device.entry) + ", " + L.censusVerdictWord(device.entry.verdict)
                        + (device.entry.paired === true ? ", " + L.pairedText : "")
                    Accessible.description: [L.text(device.entry.note), device.evidence]
                        .filter(part => part.length > 0).join(". ")

                    Kirigami.Icon {
                        Layout.alignment: Qt.AlignTop
                        implicitWidth: Kirigami.Units.iconSizes.smallMedium
                        implicitHeight: Kirigami.Units.iconSizes.smallMedium
                        source: L.levelIcon(device.level)
                        Accessible.ignored: true
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Kirigami.Units.smallSpacing / 2

                        Controls.Label {
                            Layout.fillWidth: true
                            text: L.censusTitle(device.entry)
                            wrapMode: Text.Wrap
                            font.weight: Font.DemiBold
                            Accessible.ignored: true
                        }
                        Controls.Label {
                            Layout.fillWidth: true
                            text: L.censusVerdictWord(device.entry.verdict)
                                + (device.entry.paired === true ? " · " + L.pairedText : "")
                            wrapMode: Text.Wrap
                            color: device.level === L.GOOD ? Kirigami.Theme.positiveTextColor
                                 : device.level === L.ATTENTION ? Kirigami.Theme.neutralTextColor
                                 : device.level === L.PROBLEM ? Kirigami.Theme.negativeTextColor
                                 : Kirigami.Theme.textColor
                            Accessible.ignored: true
                        }
                        Controls.Label {
                            Layout.fillWidth: true
                            visible: text.length > 0
                            text: L.text(device.entry.note)
                            wrapMode: Text.Wrap
                            Accessible.ignored: true
                        }
                        SecondaryLabel {
                            Layout.fillWidth: true
                            visible: text.length > 0
                            text: device.evidence
                            wrapMode: Text.Wrap
                            Accessible.ignored: true
                        }
                    }
                }
            }
        }

        SecondaryLabel {
            objectName: "alsoFound"
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 36
            Layout.leftMargin: Kirigami.Units.largeSpacing
            Layout.rightMargin: Kirigami.Units.largeSpacing
            visible: root.asideText.length > 0
            text: "Also found: " + root.asideText + "."
            wrapMode: Text.Wrap
        }
    }

    footer: PageFooter {
        busy: root.pending
        // While nothing is on screen the loading placeholder says it.
        busyText: root.doc === null ? "" : "Classifying camera devices…"
        active: root.isCurrentPage
        actionText: root.loaded ? "Pick the camera pair in irlume" : ""
        onActionTriggered: root.launch()
        onRefreshRequested: root.refresh()
    }
}
