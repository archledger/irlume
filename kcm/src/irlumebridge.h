// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QByteArray>
#include <QObject>
#include <QPointer>
#include <QProcess>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariantMap>

#include <functional>
#include <map>
#include <optional>

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
 *
 * Process lifetime: no QProcess or QTimer is ever destroyed inside one of
 * its own signals. A finished, timed-out or superseded request is taken
 * out of the in-flight table, disconnected, and released with
 * deleteLater() (a still-running child is killed first and released once
 * it has been reaped). Every request carries a serial number, so a
 * process that is no longer the current one for its name never reports.
 */
class IrlumeBridge : public QObject
{
    Q_OBJECT

public:
    explicit IrlumeBridge(QObject *parent = nullptr);
    /// Test seam for kcm_bridgetest only: exec `irlumePath` instead of the
    /// resolved packaged path, and (when `budgetMs` > 0) use that budget
    /// for every command. The module itself always uses the default
    /// constructor; nothing in the environment can reach this.
    IrlumeBridge(const QString &irlumePath, int budgetMs, QObject *parent = nullptr);
    ~IrlumeBridge() override;

    /// Absolute path of the irlume CLI this bridge execs, or an empty
    /// string when none was found.
    [[nodiscard]] QString irlumePath() const;

    /// Whether `name` is a known machine-API command.
    [[nodiscard]] static bool knownRequest(const QString &name);

    /// Run one machine-API command by table name ("version", "status",
    /// "doctor", "census", "login"). Exactly one of documentReady or
    /// requestFailed is emitted per request that is not superseded. A
    /// request for a name that is still running supersedes the running
    /// one: that one is killed and never reports.
    void request(const QString &name);

    /// Launch `irlume tui` (optionally deep-linked to a page) via
    /// xdg-terminal-exec, by the same absolute path the machine requests
    /// use. Returns false when that launcher or the irlume CLI is
    /// unavailable (the caller then falls back to the shipped desktop
    /// entry, without a deep link).
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
        /// The child could not start, crashed, or did not finish within
        /// the budget.
        Unknown,
    };

    /// Run `irlume tui --page <page>` WITHOUT a terminal and report the
    /// verdict to `done`, asynchronously (the UI thread never waits). When
    /// a TUI is already running the child performs the handoff and exits
    /// 0; when none is running it exits nonzero after taking the guard and
    /// hitting the TTY check. The child gets 2 s to start and then
    /// `timeoutMs` to finish. `done` is called exactly once, unless the
    /// bridge is destroyed first.
    void handoffTui(const QString &page, int timeoutMs, std::function<void(HandoffResult)> done);

    /// Show `page` in a TUI: hand it to a running one (handoffTui), or call
    /// `open(page)` when none appears to run or none took the handoff.
    /// While a handoff is pending, a further call replaces the queued page
    /// instead of starting a second child. When the pending handoff ends,
    /// the latest queued page is handed off in turn (the TUI took the first
    /// one) or passed to `open` (it did not), so the last click always has
    /// an effect and at most one terminal opens.
    void showTuiPage(const QString &page, int timeoutMs, std::function<void(const QString &)> open);

Q_SIGNALS:
    /// `doc` is the parsed machine-API envelope, including ok/data/error.
    void documentReady(const QString &name, const QVariantMap &doc);
    /// Only for: binary missing, unknown request, process crash, timeout,
    /// or output that is not a JSON document.
    void requestFailed(const QString &name, const QString &reason);

private:
    struct Inflight {
        quint64 serial = 0;
        QPointer<QProcess> process;
        QPointer<QTimer> timeout;
    };
    [[nodiscard]] bool isCurrent(const QString &name, quint64 serial) const;
    /// Takes `name` out of the in-flight table and releases its process
    /// and timer without emitting anything.
    void retire(const QString &name);
    void finishWithDocument(const QString &name, const QByteArray &output);

    QString m_irlumePath;
    bool m_handoffPending = false;
    std::optional<QString> m_queuedPage;
    int m_budgetOverrideMs = 0;
    quint64 m_nextSerial = 0;
    std::map<QString, Inflight> m_inflight;
};
