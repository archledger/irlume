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
    /// Exactly one of documentReady or requestFailed is emitted per call.
    /// A document whose envelope says ok:false is STILL a document: typed
    /// refusals are state, not failures.
    Q_INVOKABLE void request(const QString &name);

    /// Launch `irlume tui` (optionally deep-linked to a page) in a
    /// terminal: xdg-terminal-exec when available, otherwise the shipped
    /// desktop entry via KIO (no deep link in the fallback).
    Q_INVOKABLE void launchTui(const QString &page);

Q_SIGNALS:
    /// `doc` is the parsed machine-API envelope, including ok/data/error.
    void documentReady(const QString &name, const QVariantMap &doc);
    /// Only for: binary missing, process crash/timeout, or output that is
    /// not a JSON document. Machine-API refusals arrive via documentReady.
    void requestFailed(const QString &name, const QString &reason);

private:
    IrlumeBridge m_bridge;
};
