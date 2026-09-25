// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <KQuickConfigModule>

#include <QVariantMap>

#include "irlumebridge.h"

/**
 * The irlume System Settings module: a read-only dashboard over the machine
 * API plus launch actions into the TUI.
 *
 * The GUI layer holds no policy. Every value rendered comes from
 * `irlume <command> --json --contract 1` output via the IrlumeBridge; every
 * interactive or privileged action is delegated to the TUI (see the design
 * doc docs/superpowers/specs/2026-09-18-kcm-plasma-settings-design.md).
 */
class IrlumeKcm : public KQuickConfigModule
{
    Q_OBJECT

public:
    explicit IrlumeKcm(QObject *parent, const KPluginMetaData &data);
    ~IrlumeKcm() override;

    /// Absolute path of the irlume CLI this module execs, or an empty
    /// string when none was found (the UI renders that as a state).
    Q_INVOKABLE [[nodiscard]] QString irlumePath() const;

    /// Run one machine-API command by table name ("version", "status",
    /// "doctor", "census", "login") and report it asynchronously.
    /// Exactly one of documentReady or requestFailed is emitted per call,
    /// unless a later call for the same name supersedes it while it runs:
    /// the superseded call then reports nothing. A document whose envelope
    /// says ok:false is STILL a document: typed refusals are state, not
    /// failures.
    Q_INVOKABLE void request(const QString &name);

    /// Launch `irlume tui` (optionally deep-linked to a page) in a
    /// terminal: xdg-terminal-exec when available, otherwise the shipped
    /// desktop entry via KIO (no deep link in the fallback). Never blocks
    /// the UI. `origin` names the module page that asked (overview,
    /// diagnostics, cameras, login). A launch that cannot happen is
    /// reported as launchFailed(origin, reason), so the page that asked
    /// shows it whichever page is current by then. A click while a handoff
    /// to a running TUI is still pending replaces the page shown after it,
    /// and the origin any failure is reported to.
    Q_INVOKABLE void launchTui(const QString &page, const QString &origin);

Q_SIGNALS:
    /// `doc` is the parsed machine-API envelope, including ok/data/error.
    void documentReady(const QString &name, const QVariantMap &doc);
    /// Only for: binary missing, process crash/timeout, or output that is
    /// not a JSON document. Machine-API refusals arrive via documentReady.
    void requestFailed(const QString &name, const QString &reason);
    /// A launchTui call that could not open the TUI, for the page named by
    /// its origin.
    void launchFailed(const QString &origin, const QString &reason);

private:
    /// The terminal half of launchTui: xdg-terminal-exec, then the
    /// desktop entry.
    void openTerminal(const QString &page, const QString &origin);

    IrlumeBridge m_bridge;
    /// The origin of the latest launch click, which a pending handoff
    /// reports to when it falls back to a terminal.
    QString m_launchOrigin;
};
