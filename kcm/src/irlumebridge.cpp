// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#include "irlumebridge.h"

#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QStandardPaths>

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
} // namespace

IrlumeBridge::IrlumeBridge(QObject *parent)
    : QObject(parent)
    , m_irlumePath(resolveIrlume())
{
}

IrlumeBridge::~IrlumeBridge() = default;

QString IrlumeBridge::irlumePath() const
{
    return m_irlumePath;
}

bool IrlumeBridge::knownRequest(const QString &name)
{
    return std::any_of(kCommands.cbegin(), kCommands.cend(),
                       [&name](const CommandSpec &spec) { return name == spec.name; });
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

    // A re-request replaces any in-flight exec of the same document.
    m_inflight.erase(name);

    Inflight in;
    in.process = std::make_unique<QProcess>(this);
    in.timeout = std::make_unique<QTimer>(this);
    in.timeout->setSingleShot(true);

    QProcess *process = in.process.get();
    QTimer *timeout = in.timeout.get();
    process->setProgram(m_irlumePath);
    process->setArguments(it->argv + kMachineFlags);
    process->setProcessChannelMode(QProcess::SeparateChannels);

    connect(process, &QProcess::finished, this, [this, name, process](int, QProcess::ExitStatus status) {
        if (status != QProcess::NormalExit) {
            finishWithFailure(name, QStringLiteral("irlume crashed"));
            return;
        }
        finishWithDocument(name, process->readAllStandardOutput());
    });
    connect(process, &QProcess::errorOccurred, this, [this, name](QProcess::ProcessError) {
        finishWithFailure(name, QStringLiteral("irlume could not be run"));
    });
    connect(timeout, &QTimer::timeout, this, [this, name, process]() {
        process->kill();
        finishWithFailure(name, QStringLiteral("irlume did not answer within its budget"));
    });

    timeout->start(it->timeoutMs);
    m_inflight.emplace(name, std::move(in));
    m_inflight[name].process->start(QIODevice::ReadOnly);
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
    const int fd = open(QFile::encodeName(lockPath).constData(), O_RDWR);
    if (fd < 0) {
        return false;
    }
    // SAFETY: fd is valid and owned by this scope; flock touches only it.
    const int rc = flock(fd, LOCK_EX | LOCK_NB);
    close(fd); // releasing here also undoes a lock this probe took
    return rc != 0; // EWOULDBLOCK: someone holds it -> a TUI is live
}

IrlumeBridge::HandoffResult IrlumeBridge::handoffTuiAndWait(const QString &page, int timeoutMs)
{
    if (m_irlumePath.isEmpty()) {
        return HandoffResult::Unknown;
    }
    QStringList args{QStringLiteral("tui")};
    if (!page.isEmpty()) {
        args << QStringLiteral("--page") << page;
    }
    QProcess child;
    child.setProgram(m_irlumePath);
    child.setArguments(args);
    child.setProcessChannelMode(QProcess::SeparateChannels);
    child.start(QIODevice::ReadOnly);
    if (!child.waitForStarted(2000)) {
        return HandoffResult::Unknown;
    }
    if (!child.waitForFinished(timeoutMs)) {
        child.kill();
        child.waitForFinished(1000);
        return HandoffResult::Unknown;
    }
    if (child.exitStatus() != QProcess::NormalExit) {
        return HandoffResult::Unknown;
    }
    // Exit 0 is the TUI's documented "handed off to the running instance"
    // outcome; any other code means no live TUI accepted the handoff.
    return child.exitCode() == 0 ? HandoffResult::Done : HandoffResult::NotAccepted;
}

bool IrlumeBridge::launchTuiDetached(const QString &page)
{
    const QString xdgTerminal = QStandardPaths::findExecutable(QStringLiteral("xdg-terminal-exec"));
    if (xdgTerminal.isEmpty()) {
        return false;
    }
    QStringList args{QStringLiteral("irlume"), QStringLiteral("tui")};
    if (!page.isEmpty()) {
        args << QStringLiteral("--page") << page;
    }
    return QProcess::startDetached(xdgTerminal, args);
}

void IrlumeBridge::finishWithDocument(const QString &name, const QByteArray &output)
{
    if (m_inflight.erase(name) == 0) {
        return;
    }
    QJsonParseError parseError{};
    const QJsonDocument doc = QJsonDocument::fromJson(output, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        finishWithFailure(name, QStringLiteral("irlume did not answer with a JSON document"));
        return;
    }
    Q_EMIT documentReady(name, doc.object().toVariantMap());
}

void IrlumeBridge::finishWithFailure(const QString &name, const QString &reason)
{
    m_inflight.erase(name);
    Q_EMIT requestFailed(name, reason);
}

#include "irlumebridge.moc"
