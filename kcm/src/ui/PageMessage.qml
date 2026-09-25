// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A page-level message for the page header: a request that produced no
// document (the bridge's reason), or a typed refusal from the machine API
// (the error code's documented meaning, with Retry when the code is
// retryable).
import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import "labels.js" as L

Kirigami.InlineMessage {
    id: message

    // What the request was for, as the end of "Could not ...".
    property string action: ""
    // The bridge's reason when no document arrived, or "".
    property string failure: ""
    // The document when it is a refusal (ok:false), else null.
    property var refusal: null
    // Whether Retry is offered at all (a launch failure never retries).
    property bool canRetry: true
    // Whether a request that produced no document may succeed when asked
    // again: not when the irlume command is missing, since the module
    // looks for it only once.
    property bool failureRetryable: true

    signal retryRequested()

    readonly property bool refused: message.refusal !== null && message.refusal !== undefined
        && message.refusal.ok === false
    readonly property bool retryable: message.canRetry
        && (message.failure.length > 0 ? message.failureRetryable
            : (message.refused && !!message.refusal.error && message.refusal.error.retryable === true))

    Layout.fillWidth: true
    position: Kirigami.InlineMessage.Position.Header
    visible: message.failure.length > 0 || message.refused
    type: message.failure.length > 0 ? Kirigami.MessageType.Error : Kirigami.MessageType.Warning
    text: message.failure.length > 0
          ? ("Could not " + message.action + ": " + message.failure.replace(/\.+$/, "") + ".")
          : (message.refused ? L.errorText(message.refusal.error) : "")

    actions: [
        Kirigami.Action {
            text: "Retry"
            icon.name: "view-refresh"
            visible: message.retryable
            onTriggered: message.retryRequested()
        }
    ]
}
