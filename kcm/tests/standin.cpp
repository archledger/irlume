// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#include "standin.h"

#include <KPluginFactory>

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QTimer>

K_PLUGIN_CLASS_WITH_JSON(IrlumeFixtureKcm, "kcm_irlume.json")

namespace
{
// The bridge's fixed request table (kcm/src/irlumebridge.cpp kCommands).
const QStringList kKnown = {
    QStringLiteral("version"), QStringLiteral("status"), QStringLiteral("doctor"),
    QStringLiteral("census"), QStringLiteral("login"),
};
} // namespace

IrlumeFixtureKcm::IrlumeFixtureKcm(QObject *parent, const KPluginMetaData &data, const QVariantList &args)
    : KQuickConfigModule(parent, data)
{
    // As IrlumeKcm: a read-only module with no Apply or Defaults buttons.
    setButtons({});
    if (!args.isEmpty()) {
        m_fixtures = args.at(0).toString();
    }
    if (args.size() > 1) {
        m_delayMs = args.at(1).toInt();
    }
}

IrlumeFixtureKcm::~IrlumeFixtureKcm() = default;

QString IrlumeFixtureKcm::irlumePath() const
{
    return QStringLiteral("/usr/bin/irlume");
}

int IrlumeFixtureKcm::outstanding() const
{
    return m_outstanding;
}

QStringList IrlumeFixtureKcm::launches() const
{
    return m_launches;
}

void IrlumeFixtureKcm::request(const QString &name)
{
    if (!kKnown.contains(name)) {
        Q_EMIT requestFailed(name, QStringLiteral("unknown request"));
        return;
    }
    const QDir dir(m_fixtures);
    QFile failFile(dir.filePath(name + QStringLiteral(".fail.txt")));
    QFile docFile(dir.filePath(name + QStringLiteral(".json")));

    QString reason;
    QVariantMap doc;
    bool isDoc = false;
    if (failFile.open(QIODevice::ReadOnly)) {
        reason = QString::fromUtf8(failFile.readLine()).trimmed();
    } else if (docFile.open(QIODevice::ReadOnly)) {
        // The same parse as IrlumeBridge::finishWithDocument.
        QJsonParseError parseError{};
        const QJsonDocument json = QJsonDocument::fromJson(docFile.readAll(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !json.isObject()) {
            reason = QStringLiteral("irlume did not answer with a JSON document");
        } else {
            doc = json.object().toVariantMap();
            isDoc = true;
        }
    } else {
        reason = QStringLiteral("no fixture for %1").arg(name);
    }

    ++m_outstanding;
    Q_EMIT outstandingChanged();
    QTimer::singleShot(m_delayMs, this, [this, name, doc, reason, isDoc]() {
        if (isDoc) {
            Q_EMIT documentReady(name, doc);
        } else {
            Q_EMIT requestFailed(name, reason);
        }
        --m_outstanding;
        Q_EMIT outstandingChanged();
    });
}

void IrlumeFixtureKcm::launchTui(const QString &page)
{
    m_launches << page;
    Q_EMIT launchesChanged();
}

#include "standin.moc"
