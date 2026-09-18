// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#include "irlumebridge.h"

#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QStandardPaths>

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
