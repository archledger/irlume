// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#include "irlumebridge.h"

#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QStandardPaths>

#include <algorithm>
#include <utility>

#include <fcntl.h>
#include <pwd.h>
#include <sys/file.h>
#include <unistd.h>

namespace
{
// The fixed machine-API command table. Arguments are literals from this
// table plus the fixed machine flags; nothing user-editable ever reaches
// the command line, and the irlume binary is exec'd by absolute path.
struct CommandSpec {
    QString name;
    QStringList argv;
    int timeoutMs;
};

const QList<CommandSpec> kCommands = {
    {QStringLiteral("version"), {QStringLiteral("version")}, 3000},
    {QStringLiteral("status"), {QStringLiteral("status")}, 3000},
    {QStringLiteral("doctor"), {QStringLiteral("doctor")}, 30000},
    {QStringLiteral("census"), {QStringLiteral("camera"), QStringLiteral("census")}, 20000},
    {QStringLiteral("login"), {QStringLiteral("login"), QStringLiteral("status")}, 10000},
};

const QStringList kMachineFlags = {QStringLiteral("--json"), QStringLiteral("--contract"), QStringLiteral("1")};

// Budget for the handoff child to start; the caller's budget then covers
// the run itself.
constexpr int kHandoffStartMs = 2000;

QString resolveIrlume()
{
    // Prefer the packaged absolute path: a settings panel must not run an
    // irlume planted earlier in the session PATH.
    const QString packaged = QStringLiteral("/usr/bin/irlume");
    const QFileInfo info(packaged);
    if (info.isExecutable() && info.isFile()) {
        return packaged;
    }
    return QStandardPaths::findExecutable(QStringLiteral("irlume"));
}

// Releases a child and its budget timer without anything being emitted for
// them: both are disconnected first, and a child that is still running is
// killed and deleted once it has been reaped. Nothing is destroyed inside
// its own signal, and QProcess never has to destroy a running child.
void release(QProcess *process, QTimer *timer)
{
    if (timer != nullptr) {
        timer->stop();
        timer->disconnect();
        timer->deleteLater();
    }
    if (process == nullptr) {
        return;
    }
    process->disconnect();
    if (process->state() == QProcess::NotRunning) {
        process->deleteLater();
        return;
    }
    QObject::connect(process, &QProcess::finished, process, &QObject::deleteLater);
    QObject::connect(process, &QProcess::errorOccurred, process, [process](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            process->deleteLater();
        }
    });
    process->kill();
}
} // namespace

IrlumeBridge::IrlumeBridge(QObject *parent)
    : QObject(parent)
    , m_irlumePath(resolveIrlume())
{
}

IrlumeBridge::IrlumeBridge(const QString &irlumePath, int budgetMs, QObject *parent)
    : QObject(parent)
    , m_irlumePath(irlumePath)
    , m_budgetOverrideMs(budgetMs)
{
}

IrlumeBridge::~IrlumeBridge()
{
    // Every child (in flight, being released, or a handoff) is parented to
    // this bridge. Stop them here, silently, so none reports into a
    // half-destroyed owner and QProcess does not warn about a running
    // child when QObject deletes it.
    m_inflight.clear();
    const auto processes = findChildren<QProcess *>(Qt::FindDirectChildrenOnly);
    for (QProcess *process : processes) {
        process->disconnect();
        if (process->state() != QProcess::NotRunning) {
            process->kill();
            process->waitForFinished(1000);
        }
    }
    const auto timers = findChildren<QTimer *>(Qt::FindDirectChildrenOnly);
    for (QTimer *timer : timers) {
        timer->disconnect();
        timer->stop();
    }
}

QString IrlumeBridge::irlumePath() const
{
    return m_irlumePath;
}

bool IrlumeBridge::knownRequest(const QString &name)
{
    return std::any_of(kCommands.cbegin(), kCommands.cend(),
                       [&name](const CommandSpec &spec) { return name == spec.name; });
}

bool IrlumeBridge::isCurrent(const QString &name, quint64 serial) const
{
    const auto it = m_inflight.find(name);
    return it != m_inflight.end() && it->second.serial == serial;
}

void IrlumeBridge::retire(const QString &name)
{
    const auto it = m_inflight.find(name);
    if (it == m_inflight.end()) {
        return;
    }
    Inflight entry = std::move(it->second);
    m_inflight.erase(it);
    release(entry.process.data(), entry.timeout.data());
}

void IrlumeBridge::request(const QString &name)
{
    if (m_irlumePath.isEmpty()) {
        Q_EMIT requestFailed(name, QStringLiteral("the irlume command was not found"));
        return;
    }
    const auto it = std::find_if(kCommands.cbegin(), kCommands.cend(),
                                 [&name](const CommandSpec &spec) { return name == spec.name; });
    if (it == kCommands.cend()) {
        Q_EMIT requestFailed(name, QStringLiteral("unknown request"));
        return;
    }

    // A re-request supersedes any in-flight exec of the same document:
    // the old child is killed and never reports.
    retire(name);

    const quint64 serial = ++m_nextSerial;
    auto *process = new QProcess(this);
    auto *timeout = new QTimer(this);
    timeout->setSingleShot(true);
    process->setProgram(m_irlumePath);
    process->setArguments(it->argv + kMachineFlags);
    process->setProcessChannelMode(QProcess::SeparateChannels);
    // Machine mode writes diagnostics to stderr; nothing here reads them.
    process->setStandardErrorFile(QProcess::nullDevice());

    connect(process, &QProcess::finished, this, [this, name, serial](int, QProcess::ExitStatus status) {
        if (!isCurrent(name, serial)) {
            return;
        }
        QProcess *child = m_inflight[name].process.data();
        const QByteArray output = child != nullptr ? child->readAllStandardOutput() : QByteArray();
        retire(name);
        if (status != QProcess::NormalExit) {
            Q_EMIT requestFailed(name, QStringLiteral("irlume crashed"));
            return;
        }
        finishWithDocument(name, output);
    });
    // A child that dies from a signal is reported by `finished` (crash
    // exit); only a child that never started ends up here.
    connect(process, &QProcess::errorOccurred, this, [this, name, serial](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart || !isCurrent(name, serial)) {
            return;
        }
        retire(name);
        Q_EMIT requestFailed(name, QStringLiteral("irlume could not be run"));
    });
    connect(timeout, &QTimer::timeout, this, [this, name, serial]() {
        if (!isCurrent(name, serial)) {
            return;
        }
        retire(name);
        Q_EMIT requestFailed(name, QStringLiteral("irlume did not answer in time"));
    });

    Inflight entry;
    entry.serial = serial;
    entry.process = process;
    entry.timeout = timeout;
    m_inflight[name] = std::move(entry);
    timeout->start(m_budgetOverrideMs > 0 ? m_budgetOverrideMs : it->timeoutMs);
    process->start(QIODevice::ReadOnly);
}

bool IrlumeBridge::tuiProbablyRunning()
{
    // Same path contract as the TUI guard: $XDG_RUNTIME_DIR/irlume/<lock>,
    // keyed by the invoking user's login name (the KCM never passes
    // --user, so the target account is the desktop session's own).
    const QByteArray runtimeDir = qgetenv("XDG_RUNTIME_DIR");
    if (runtimeDir.isEmpty()) {
        return false;
    }
    // SAFETY: geteuid cannot fail and touches no memory.
    const uid_t uid = geteuid();
    const struct passwd *pw = getpwuid(uid);
    if (pw == nullptr || pw->pw_name == nullptr) {
        return false;
    }
    QString user = QString::fromLatin1(pw->pw_name);
    for (QChar &ch : user) {
        // Must match the Rust guard's target_key exactly: ASCII
        // alphanumerics only (Unicode letters are underscores there).
        if (!((ch.unicode() < 128) && ch.isLetterOrNumber())
            && ch != u'-' && ch != u'_' && ch != u'.') {
            ch = u'_';
        }
    }
    const QString lockPath = QString::fromLatin1(runtimeDir)
        + QStringLiteral("/irlume/tui-%1.lock").arg(user);
    // Open an existing lock only: creating one here would fabricate state.
    // flock needs no write access, and the descriptor must not leak into
    // any child this process starts.
    const int fd = open(QFile::encodeName(lockPath).constData(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    // SAFETY: fd is valid and owned by this scope; flock touches only it.
    const int rc = flock(fd, LOCK_EX | LOCK_NB);
    close(fd); // releasing here also undoes a lock this probe took
    return rc != 0; // EWOULDBLOCK: someone holds it -> a TUI is live
}

void IrlumeBridge::handoffTui(const QString &page, int timeoutMs, std::function<void(HandoffResult)> done)
{
    if (m_irlumePath.isEmpty()) {
        done(HandoffResult::Unknown);
        return;
    }
    QStringList args{QStringLiteral("tui")};
    if (!page.isEmpty()) {
        args << QStringLiteral("--page") << page;
    }
    auto *child = new QProcess(this);
    auto *budget = new QTimer(this);
    budget->setSingleShot(true);
    child->setProgram(m_irlumePath);
    child->setArguments(args);
    child->setProcessChannelMode(QProcess::SeparateChannels);
    child->setStandardOutputFile(QProcess::nullDevice());
    child->setStandardErrorFile(QProcess::nullDevice());

    // Whichever handler fires first reports; release() disconnects the
    // others.
    auto finish = [child, budget, done](HandoffResult result) {
        release(child, budget);
        done(result);
    };
    connect(child, &QProcess::started, budget, [budget, timeoutMs]() {
        budget->start(timeoutMs);
    });
    connect(child, &QProcess::finished, this, [finish](int exitCode, QProcess::ExitStatus status) {
        if (status != QProcess::NormalExit) {
            finish(HandoffResult::Unknown);
            return;
        }
        // Exit 0 is the TUI's documented "handed off to the running
        // instance" outcome; any other code means no live TUI accepted
        // the handoff.
        finish(exitCode == 0 ? HandoffResult::Done : HandoffResult::NotAccepted);
    });
    connect(child, &QProcess::errorOccurred, this, [finish](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            finish(HandoffResult::Unknown);
        }
    });
    connect(budget, &QTimer::timeout, this, [finish]() {
        finish(HandoffResult::Unknown);
    });
    budget->start(kHandoffStartMs);
    child->start(QIODevice::ReadOnly);
}

void IrlumeBridge::showTuiPage(const QString &page, int timeoutMs, std::function<void(const QString &)> open)
{
    if (m_handoffPending) {
        // The pending child reports soon; the latest click wins then.
        m_queuedPage = page;
        return;
    }
    if (!tuiProbablyRunning()) {
        open(page);
        return;
    }
    m_handoffPending = true;
    handoffTui(page, timeoutMs, [this, page, timeoutMs, open](HandoffResult result) {
        m_handoffPending = false;
        const std::optional<QString> next = std::exchange(m_queuedPage, std::nullopt);
        if (result != HandoffResult::Done) {
            open(next.value_or(page));
        } else if (next && *next != page) {
            showTuiPage(*next, timeoutMs, open);
        }
    });
}

bool IrlumeBridge::launchTuiDetached(const QString &page)
{
    if (m_irlumePath.isEmpty()) {
        return false;
    }
    const QString xdgTerminal = QStandardPaths::findExecutable(QStringLiteral("xdg-terminal-exec"));
    if (xdgTerminal.isEmpty()) {
        return false;
    }
    QStringList args{m_irlumePath, QStringLiteral("tui")};
    if (!page.isEmpty()) {
        args << QStringLiteral("--page") << page;
    }
    return QProcess::startDetached(xdgTerminal, args);
}

void IrlumeBridge::finishWithDocument(const QString &name, const QByteArray &output)
{
    QJsonParseError parseError{};
    const QJsonDocument doc = QJsonDocument::fromJson(output, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        Q_EMIT requestFailed(name, QStringLiteral("irlume did not answer with a JSON document"));
        return;
    }
    Q_EMIT documentReady(name, doc.object().toVariantMap());
}
