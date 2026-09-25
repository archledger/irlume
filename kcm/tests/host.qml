// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// For kcm_pagetest: a copy of the root item KCMUtils 6 wraps every QML KCM
// in (the Kirigami.ApplicationItem that System Settings and kcmshell6
// use), without the widget plumbing. The test pushes the module's mainUi()
// and every page the module pushes, as KCModuleQml does.
import QtQuick
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCMUtils

Kirigami.ApplicationItem {
    id: host

    width: Window.width
    height: Window.height
    implicitWidth: Math.max(pageStack.implicitWidth, Kirigami.Units.gridUnit * 36)
    implicitHeight: Math.max(pageStack.implicitHeight, Kirigami.Units.gridUnit * 20)
    activeFocusOnTab: true

    property KCMUtils.ConfigModule kcm

    pageStack.separatorVisible: false
    pageStack.globalToolBar.style: Kirigami.ApplicationHeaderStyle.ToolBar
    pageStack.globalToolBar.showNavigationButtons: Kirigami.ApplicationHeaderStyle.ShowBackButton
    pageStack.columnView.columnResizeMode: Kirigami.ColumnView.SingleColumn
    footer: null

    function pushPage(item) {
        host.pageStack.push(item);
    }
}
