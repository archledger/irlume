// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Headless load test for the irlume KCM: loads the built plugin and checks
// its metadata + factory (the same way systemsettings discovers it), then
// exercises the IrlumeBridge process logic (compiled here, one copy)
// against the real irlume CLI. Exits non-zero on the first failed
// assertion.
// Usage: kcm_loadtest <path-to-kcm_irlume.so>

#include <QCoreApplication>
#include <QEventLoop>
#include <QPluginLoader>
#include <QTimer>
#include <QVariantMap>

#include <KPluginFactory>
#include <KPluginMetaData>

#include <cstdio>

#include "irlumebridge.h"

namespace
{
int failures = 0;

void check(bool ok, const QString &what)
{
    std::printf("%s  %s\n", ok ? "ok  " : "FAIL", qUtf8Printable(what));
    if (!ok) {
        ++failures;
    }
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (app.arguments().size() != 2) {
        std::fprintf(stderr, "usage: kcm_loadtest <path-to-kcm_irlume.so>\n");
        return 2;
    }

    // Plugin-level checks: discovery metadata and a KPluginFactory, the
    // same things systemsettings needs. (The class itself is not
    // instantiated here: qobject_cast across a second compiled copy of
    // the class cannot work, and full instantiation is kcmshell6's job.)
    QPluginLoader loader(app.arguments().at(1));
    if (!loader.load()) {
        std::fprintf(stderr, "cannot load plugin: %s\n", qUtf8Printable(loader.errorString()));
        return 1;
    }
    check(loader.metaData().value(QLatin1String("MetaData")).toObject()
              .value(QLatin1String("KPlugin")).toObject()
              .value(QLatin1String("Id")).toString() == QStringLiteral("kcm_irlume"),
          QStringLiteral("plugin metadata Id is kcm_irlume"));
    check(loader.metaData().value(QLatin1String("MetaData")).toObject()
              .value(QLatin1String("X-KDE-System-Settings-Parent-Category")).toString()
              == QStringLiteral("personalization"),
          QStringLiteral("plugin declares its System Settings category"));
    check(qobject_cast<KPluginFactory *>(loader.instance()) != nullptr,
          QStringLiteral("plugin provides a KPluginFactory"));
    loader.unload();

    // Bridge checks against the real CLI.
    IrlumeBridge bridge;
    check(!bridge.irlumePath().isEmpty(),
          QStringLiteral("irlume CLI resolved (%1)").arg(bridge.irlumePath()));

    QVariantMap lastDoc;
    QString lastName;
    QString lastFailure;
    // Recording handlers are installed BEFORE any request: a refusal can
    // be emitted synchronously, before any wait loop starts.
    QEventLoop completion;
    QObject::connect(&bridge, &IrlumeBridge::documentReady, &completion,
                     [&](const QString &n, const QVariantMap &doc) {
                         lastName = n;
                         lastDoc = doc;
                         lastFailure.clear();
                         completion.quit();
                     });
    QObject::connect(&bridge, &IrlumeBridge::requestFailed, &completion,
                     [&](const QString &n, const QString &reason) {
                         lastName = n;
                         lastFailure = reason;
                         completion.quit();
                     });
    auto waitFor = [&completion](int timeoutMs) {
        QTimer::singleShot(timeoutMs, &completion, &QEventLoop::quit);
        completion.exec();
    };

    // Unknown requests are refused without touching the process.
    bridge.request(QStringLiteral("bogus"));
    waitFor(1000);
    check(lastName == QStringLiteral("bogus") && !lastFailure.isEmpty(),
          QStringLiteral("unknown request is refused without a process"));
    check(!IrlumeBridge::knownRequest(QStringLiteral("rm -rf")),
          QStringLiteral("the request table is a fixed vocabulary"));

    // Version handshake against the real CLI.
    bridge.request(QStringLiteral("version"));
    waitFor(5000);
    check(lastDoc.value(QStringLiteral("ok")).toBool() == true
              && lastDoc.value(QStringLiteral("contract_version")).toInt() == 1,
          QStringLiteral("version document: contract 1 handshake"));

    // Status document against the real daemon (running on the test host).
    bridge.request(QStringLiteral("status"));
    waitFor(5000);
    check(lastDoc.value(QStringLiteral("ok")).toBool() == true,
          QStringLiteral("status document ok"));
    check(lastDoc.value(QStringLiteral("data")).toMap()
                  .contains(QStringLiteral("daemon")),
          QStringLiteral("status document carries the daemon field"));

    // Every remaining command in the table, against the real engine.
    const QList<QPair<QString, QString>> requests = {
        {QStringLiteral("doctor"), QStringLiteral("checks")},
        {QStringLiteral("census"), QStringLiteral("entries")},
        {QStringLiteral("login"), QStringLiteral("surfaces")},
    };
    for (const auto &entry : requests) {
        bridge.request(entry.first);
        waitFor(entry.first == QStringLiteral("doctor") ? 35000 : 25000);
        check(lastName == entry.first && lastDoc.value(QStringLiteral("ok")).toBool() == true
                  && lastDoc.value(QStringLiteral("data")).toMap().contains(entry.second),
              QStringLiteral("%1 document ok (data.%2)").arg(entry.first, entry.second));
    }

    std::printf("%s\n", failures == 0 ? "loadtest: PASS" : "loadtest: FAIL");
    return failures == 0 ? 0 : 1;
}
