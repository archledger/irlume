// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QByteArray>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariantMap>

#include <map>
#include <memory>

/**
 * The process bridge between the System Settings module and the irlume CLI.
 *
 * Owns no policy: it runs `irlume <command> --json --contract 1` by
 * absolute path, with a per-command time budget, and reports the parsed
 * machine-API envelope verbatim. A document whose envelope says ok:false
 * is still a document (typed refusals are state); only a missing binary,
 * a crash, a timeout, or non-JSON output are failures.
 *
 * Also knows how to start the TUI in a terminal via xdg-terminal-exec
 * (deep-linking to a page). When that is unavailable it reports false and
 * the caller falls back to the shipped desktop entry.
 */
class IrlumeBridge : public QObject
{
    Q_OBJECT

public:
    explicit IrlumeBridge(QObject *parent = nullptr);
    ~IrlumeBridge() override;

    /// Absolute path of the irlume CLI this bridge execs, or an empty
    /// string when none was found.
    [[nodiscard]] QString irlumePath() const;

    /// Whether `name` is a known machine-API command.
    [[nodiscard]] static bool knownRequest(const QString &name);

    /// Run one machine-API command by table name ("version", "status",
    /// "doctor", "census", "login"). Exactly one of documentReady or
    /// requestFailed is emitted per accepted call.
    void request(const QString &name);

    /// Launch `irlume tui` (optionally deep-linked to a page) via
    /// xdg-terminal-exec. Returns false when that launcher is unavailable
    /// (the caller then falls back to the shipped desktop entry, without a
    /// deep link).
    bool launchTuiDetached(const QString &page);

    /// Whether a TUI for this user's target account appears to be running:
    /// the single-instance guard's lock file exists and its kernel lock is
    /// held by someone. A UX probe only (the guard stays authoritative in
    /// the TUI; a stale guess worst case opens a terminal that hands off).
    bool tuiProbablyRunning();

    /// Outcome of a terminal-less handoff attempt.
    enum class HandoffResult {
        /// The child exited 0: the running TUI navigated to the page.
        Done,
        /// The child ran but did not report success: no live TUI accepted
        /// the handoff (it took the guard and hit the TTY check). The
        /// caller should fall back to opening a terminal.
        NotAccepted,
        /// The child crashed or did not finish within the budget.
        Unknown,
    };

    /// Run `irlume tui --page <page>` WITHOUT a terminal and WAIT for the
    /// verdict. When a TUI is already running the child performs the
    /// handoff and exits 0; when none is running it exits nonzero after
    /// taking the guard and hitting the TTY check. Deliberately
    /// synchronous: the caller must know whether a window is warranted.
    HandoffResult handoffTuiAndWait(const QString &page, int timeoutMs);

Q_SIGNALS:
    /// `doc` is the parsed machine-API envelope, including ok/data/error.
    void documentReady(const QString &name, const QVariantMap &doc);
    /// Only for: binary missing, unknown request, process crash, timeout,
    /// or output that is not a JSON document.
    void requestFailed(const QString &name, const QString &reason);

private:
    struct Inflight {
        std::unique_ptr<QProcess> process;
        std::unique_ptr<QTimer> timeout;
    };
    void finishWithDocument(const QString &name, const QByteArray &output);
    void finishWithFailure(const QString &name, const QString &reason);

    QString m_irlumePath;
    std::map<QString, Inflight> m_inflight;
};
