// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Diagnostics: the doctor document as a list grouped by state, problems
// first. Each row has a state icon, a plain title for its check id (the id
// stays visible for support), and the detail: in full for a row that needs
// attention, on one line for the rest. Conditionally present check ids
// render only when present, exactly as the contract says.
pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

import "labels.js" as L

KCMUtils.ScrollViewKCM {
    id: root

    title: "Diagnostics"

    property var doc: null
    property bool pending: false
    property string failure: ""
    property string launchFailure: ""

    readonly property bool loaded: root.doc !== null && root.doc.ok === true
    readonly property bool cliFound: kcm.irlumePath().length > 0
    // Counts per contract state, from the rows actually shown. `admin`
    // counts the root-only checks among the undetermined ones.
    property var counts: ({fail: 0, warn: 0, unknown: 0, pass: 0, info: 0, other: 0, admin: 0})
    // Whether anything calls for a look in irlume. The root-only checks
    // are left out: they are undetermined for every ordinary account, and
    // the terminal interface cannot settle them either.
    readonly property bool needsLook: root.counts.fail + root.counts.warn + root.counts.other
        + (root.counts.unknown - root.counts.admin) > 0

    readonly property string summary: {
        const c = root.counts;
        const parts = [];
        if (c.fail > 0) {
            parts.push(c.fail + " failing");
        }
        if (c.warn > 0) {
            parts.push(L.plural(c.warn, "warning", "warnings"));
        }
        if (c.unknown > 0) {
            parts.push(c.unknown + " not determined");
        }
        if (c.other > 0) {
            parts.push(c.other + " in another state");
        }
        parts.push(c.pass + " passing");
        let text = parts.join(", ") + ".";
        if (c.admin > 0) {
            text += " " + (c.admin === 1 ? "1 check needs" : (c.admin + " checks need"))
                + " administrator rights: run sudo irlume doctor in a terminal.";
        }
        return text;
    }

    // The model is built from the document alone (never from the theme),
    // so it is rebuilt only when a new document arrives.
    function rebuild() {
        checks.clear();
        const c = {fail: 0, warn: 0, unknown: 0, pass: 0, info: 0, other: 0, admin: 0};
        // Read the document directly: this runs from onDocChanged, before
        // bindings on `doc` are guaranteed to have caught up.
        const doc = root.doc;
        const data = doc !== null && doc.ok === true && doc.data ? doc.data : {};
        const rows = [];
        const all = L.list(data.checks);
        for (let i = 0; i < all.length; ++i) {
            const check = all[i] || {};
            if (L.checkHidden(check.id)) {
                continue;
            }
            const group = L.checkGroupIndex(check.state);
            const key = ["fail", "warn", "unknown", "pass", "info"][group];
            c[key === undefined ? "other" : key] += 1;
            if (L.checkNeedsAdmin(check)) {
                c.admin += 1;
            }
            rows.push({order: i, group: group, check: check});
        }
        // Problems first; the doctor order within a group.
        rows.sort((a, b) => a.group !== b.group ? a.group - b.group : a.order - b.order);
        const perGroup = {};
        for (const row of rows) {
            perGroup[row.group] = (perGroup[row.group] || 0) + 1;
        }
        for (const row of rows) {
            const check = row.check;
            const detail = L.text(check.detail);
            const state = L.text(check.state);
            let shown = detail;
            let raw = detail;
            let full = true;
            if (L.checkNeedsAdmin(check)) {
                // The permission error it replaces stays out of the tooltip
                // and the accessible description too.
                shown = "Checked only with administrator rights (run: sudo irlume doctor).";
                raw = "";
            } else if ((state === "warn" || state === "fail") && detail.length === 0) {
                shown = "Details: open irlume, or run irlume doctor in a terminal.";
            } else if (state === "unknown" && detail.length === 0) {
                shown = "This check could not be carried out.";
            } else if (state === "pass" || state === "info") {
                full = false;
            }
            checks.append({
                checkId: L.text(check.id),
                title: L.checkTitle(check.id),
                checkState: state,
                level: L.checkLevel(check.state),
                shown: shown,
                raw: raw,
                wrap: full,
                section: L.checkGroupTitle(row.group) + " (" + perGroup[row.group] + ")",
            });
        }
        root.counts = c;
    }

    function refresh() {
        root.failure = "";
        root.pending = true;
        kcm.request("doctor");
    }

    function launch() {
        root.launchFailure = "";
        kcm.launchTui("diagnostics", "diagnostics");
    }

    onDocChanged: root.rebuild()
    Component.onCompleted: root.refresh()

    ListModel {
        id: checks
    }

    Connections {
        target: kcm

        function onDocumentReady(name, document) {
            if (name === "doctor") {
                root.doc = document;
                root.failure = "";
                root.pending = false;
            }
        }
        function onRequestFailed(name, reason) {
            if (name === "doctor") {
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
            if (origin === "diagnostics") {
                root.launchFailure = reason;
            }
        }
    }

    headerPaddingEnabled: false
    header: ColumnLayout {
        spacing: 0

        PageMessage {
            objectName: "requestMessage"
            action: "run the diagnostics"
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
            objectName: "summaryMessage"
            Layout.fillWidth: true
            position: Kirigami.InlineMessage.Position.Header
            visible: root.loaded && checks.count > 0
            type: root.counts.fail > 0 ? Kirigami.MessageType.Error
                : root.counts.warn > 0 ? Kirigami.MessageType.Warning
                : root.needsLook ? Kirigami.MessageType.Information
                : Kirigami.MessageType.Positive
            text: root.summary
            actions: [
                Kirigami.Action {
                    text: "Open irlume"
                    icon.name: "utilities-terminal"
                    visible: root.needsLook
                    onTriggered: root.launch()
                }
            ]
        }
    }

    view: ListView {
        id: list
        objectName: "checkList"

        model: checks
        clip: true
        reuseItems: false
        activeFocusOnTab: true
        keyNavigationEnabled: true
        currentIndex: -1

        section.property: "section"
        section.criteria: ViewSection.FullString
        section.delegate: Kirigami.ListSectionHeader {
            required property string section
            objectName: "section"
            width: ListView.view ? ListView.view.width : implicitWidth
            text: section
        }

        delegate: Controls.ItemDelegate {
            id: row

            required property int index
            required property string checkId
            required property string title
            required property string level
            required property string shown
            required property string raw
            required property bool wrap

            objectName: "check-" + row.checkId
            width: ListView.view ? ListView.view.width : implicitWidth
            hoverEnabled: false
            down: false
            highlighted: ListView.isCurrentItem && list.activeFocus

            Accessible.name: row.title + ", " + L.levelWord(row.level)
            // The id leads the description: support and bug reports key on it.
            Accessible.description: (row.title !== row.checkId ? ("Check " + row.checkId + ". ") : "")
                + row.shown + (row.raw.length > 0 && row.raw !== row.shown ? " " + row.raw : "")

            onClicked: list.currentIndex = row.index

            contentItem: RowLayout {
                spacing: Kirigami.Units.largeSpacing

                Kirigami.Icon {
                    Layout.alignment: Qt.AlignTop
                    Layout.topMargin: Math.max(0, Math.round((titleLabel.implicitHeight - height) / 2))
                    implicitWidth: Kirigami.Units.iconSizes.smallMedium
                    implicitHeight: Kirigami.Units.iconSizes.smallMedium
                    source: L.levelIcon(row.level)
                    Accessible.ignored: true
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0

                    // The title, then the raw id right beside it (support
                    // and bug reports key on the id), then free space. The
                    // widths come from the row's own width, which the view
                    // sets, so the layout never feeds its own result back.
                    // A long id takes at most two fifths and wraps.
                    RowLayout {
                        id: titleRow
                        readonly property real room: Math.max(0, row.availableWidth
                            - Kirigami.Units.iconSizes.smallMedium - Kirigami.Units.largeSpacing)
                        readonly property real idWidth: idLabel.visible
                            ? Math.min(idLabel.implicitWidth, Math.floor(titleRow.room * 0.4)) : 0
                        Layout.fillWidth: true
                        spacing: 0

                        Controls.Label {
                            id: titleLabel
                            Layout.maximumWidth: Math.max(0, titleRow.room
                                - (idLabel.visible ? titleRow.idWidth + Kirigami.Units.largeSpacing : 0))
                            text: row.title
                            wrapMode: Text.Wrap
                            font.weight: Font.DemiBold
                            color: row.highlighted ? Kirigami.Theme.highlightedTextColor : Kirigami.Theme.textColor
                            Accessible.ignored: true
                        }
                        SecondaryLabel {
                            id: idLabel
                            Layout.alignment: Qt.AlignTop
                            Layout.leftMargin: Kirigami.Units.largeSpacing
                            Layout.maximumWidth: titleRow.idWidth
                            visible: row.title !== row.checkId
                            text: row.checkId
                            wrapMode: Text.Wrap
                            font: Kirigami.Theme.smallFont
                            selected: row.highlighted
                            Accessible.ignored: true
                        }
                        Item {
                            Layout.fillWidth: true
                        }
                    }

                    SecondaryLabel {
                        id: detailLabel
                        Layout.fillWidth: true
                        visible: row.shown.length > 0
                        text: row.shown
                        wrapMode: row.wrap ? Text.Wrap : Text.NoWrap
                        maximumLineCount: row.wrap ? undefined : 1
                        elide: row.wrap ? Text.ElideNone : Text.ElideRight
                        selected: row.highlighted
                        Accessible.ignored: true

                        HoverHandler {
                            id: detailHover
                        }
                        // The full text of a shortened detail, or the raw
                        // detail behind a replaced one. Shown on hover, and
                        // while the row is the keyboard's current row.
                        readonly property string fullText: row.raw.length > 0 && row.raw !== row.shown
                            ? row.raw : (detailLabel.truncated ? row.shown : "")
                        Controls.ToolTip.text: detailLabel.fullText
                        Controls.ToolTip.visible: (detailHover.hovered || row.highlighted)
                            && detailLabel.fullText.length > 0
                        Controls.ToolTip.delay: row.highlighted ? 0 : Kirigami.Units.toolTipDelay
                    }
                }
            }
        }

        // Placed at the top, as the other pages place theirs.
        Kirigami.LoadingPlaceholder {
            objectName: "loading"
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: Kirigami.Units.gridUnit * 4
            visible: root.doc === null && root.pending
            text: "Running the diagnostics…"
        }

        Kirigami.PlaceholderMessage {
            objectName: "empty"
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: Kirigami.Units.gridUnit * 2
            width: parent.width - Kirigami.Units.gridUnit * 4
            visible: checks.count === 0 && !(root.doc === null && root.pending)
            icon.name: root.loaded ? "tools-report-bug" : "dialog-warning"
            text: root.loaded ? "No checks were reported" : "No diagnostics available"
            explanation: root.loaded ? "irlume answered without any checks. Refresh to ask again."
                                     : "The message at the top says why. Refresh to ask again."
        }
    }

    footerPaddingEnabled: false
    footer: PageFooter {
        busy: root.pending
        // While nothing is on screen the loading placeholder says it.
        busyText: root.doc === null ? "" : "Running the diagnostics…"
        active: root.isCurrentPage
        actionText: root.loaded && !root.needsLook ? "Open irlume" : ""
        onActionTriggered: root.launch()
        onRefreshRequested: root.refresh()
    }
}
