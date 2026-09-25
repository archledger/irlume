// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Test stand-in for IrlumeKcm (kcm/src/irlumekcm.h): the same QML-facing
// surface, loaded the same way System Settings loads the module, but it
// answers request() from fixture files instead of running the irlume CLI.
// Built as a plugin named kcm_irlume in a test-only directory; never
// installed.
#pragma once

#include <KQuickConfigModule>

#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

class IrlumeFixtureKcm : public KQuickConfigModule
{
    Q_OBJECT
    Q_PROPERTY(int outstanding READ outstanding NOTIFY outstandingChanged)
    Q_PROPERTY(QStringList launches READ launches NOTIFY launchesChanged)

public:
    /// args: the fixture directory, then the answer delay in ms.
    IrlumeFixtureKcm(QObject *parent, const KPluginMetaData &data, const QVariantList &args);
    ~IrlumeFixtureKcm() override;

    Q_INVOKABLE [[nodiscard]] QString irlumePath() const;
    /// Answers from <fixtures>/<name>.json (documentReady) or
    /// <name>.fail.txt (requestFailed with its first line), after the
    /// delay; an unknown name is refused synchronously, as the bridge does.
    Q_INVOKABLE void request(const QString &name);
    /// Records the page; nothing is launched.
    Q_INVOKABLE void launchTui(const QString &page);

    /// Requests not answered yet.
    [[nodiscard]] int outstanding() const;
    [[nodiscard]] QStringList launches() const;

Q_SIGNALS:
    void documentReady(const QString &name, const QVariantMap &doc);
    void requestFailed(const QString &name, const QString &reason);
    void outstandingChanged();
    void launchesChanged();

private:
    QString m_fixtures;
    int m_delayMs = 10;
    int m_outstanding = 0;
    QStringList m_launches;
};
