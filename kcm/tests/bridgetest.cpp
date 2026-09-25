// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Failure-path test for IrlumeBridge (compiled here, one copy), against
// fake irlume programs written to a temporary directory. Checks the
// contract the pages rely on: exactly one documentReady or requestFailed
// per request that is not superseded, a superseded request stays silent,
// a child that dies from a signal or overruns its budget cannot crash the
// host, and QProcess never warns about destroying a running child.
// Exits non-zero on the first failed check's run.
// Usage: kcm_bridgetest

#include <QCoreApplication>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QTemporaryDir>
#include <QTimer>

#include <cstdio>
#include <memory>

#include "irlumebridge.h"

namespace
{
int failures = 0;
QStringList warnings;

void check(bool ok, const QString &what)
{
    std::printf("%s  %s\n", ok ? "ok  " : "FAIL", qUtf8Printable(what));
    if (!ok) {
        ++failures;
    }
}

void messageHandler(QtMsgType type, const QMessageLogContext &, const QString &message)
{
    if (type != QtDebugMsg && type != QtInfoMsg) {
        warnings << message;
        std::fprintf(stderr, "warning: %s\n", qUtf8Printable(message));
    }
}

void spin(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

struct Event {
    QString kind; // "document" or "failure"
    QString name;
    QVariantMap doc;
    QString reason;
};

// A bridge over one fake program, recording every signal it emits.
struct Recorder {
    std::unique_ptr<IrlumeBridge> bridge;
    QList<Event> events;

    Recorder(const QString &program, int budgetMs)
        : bridge(std::make_unique<IrlumeBridge>(program, budgetMs))
    {
        QObject::connect(bridge.get(), &IrlumeBridge::documentReady, bridge.get(),
                         [this](const QString &name, const QVariantMap &doc) {
                             events << Event{QStringLiteral("document"), name, doc, QString()};
                         });
        QObject::connect(bridge.get(), &IrlumeBridge::requestFailed, bridge.get(),
                         [this](const QString &name, const QString &reason) {
                             events << Event{QStringLiteral("failure"), name, {}, reason};
                         });
    }

    // Waits until `count` signals have arrived (or `limitMs` passed), then
    // a little longer, so a duplicate signal would be seen.
    void waitFor(int count, int limitMs)
    {
        for (int waited = 0; waited < limitMs && events.size() < count; waited += 20) {
            spin(20);
        }
        spin(400);
    }
};

QString writeProgram(const QTemporaryDir &dir, const QString &name, const QByteArray &body)
{
    const QString path = dir.filePath(name);
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return QString();
    }
    file.write("#!/bin/sh\n");
    file.write(body);
    file.close();
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    return path;
}

const QByteArray kDocument =
    "printf '%s\\n' '{\"contract_version\":1,\"engine_version\":\"0\",\"command\":\"version\",\"ok\":true,\"data\":{}}'\n";
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    qInstallMessageHandler(messageHandler);
    QTemporaryDir dir;
    if (!dir.isValid()) {
        std::fprintf(stderr, "cannot create a temporary directory\n");
        return 2;
    }

    // A normal document: exactly one documentReady, the envelope verbatim.
    {
        Recorder r(writeProgram(dir, QStringLiteral("ok"), kDocument), 0);
        r.bridge->request(QStringLiteral("version"));
        r.waitFor(1, 5000);
        check(r.events.size() == 1 && r.events.first().kind == QLatin1String("document")
                  && r.events.first().doc.value(QStringLiteral("ok")).toBool(),
              QStringLiteral("a document arrives once"));
    }

    // Output that is not JSON: exactly one requestFailed.
    {
        Recorder r(writeProgram(dir, QStringLiteral("garbage"), "echo not json\n"), 0);
        r.bridge->request(QStringLiteral("status"));
        r.waitFor(1, 5000);
        check(r.events.size() == 1 && r.events.first().kind == QLatin1String("failure"),
              QStringLiteral("non-JSON output fails once"));
    }

    // A child that dies from a signal: one requestFailed and no crash. This
    // used to destroy the QProcess inside its own errorOccurred signal.
    {
        Recorder r(writeProgram(dir, QStringLiteral("segv"), "ulimit -c 0\nkill -SEGV $$\n"), 0);
        r.bridge->request(QStringLiteral("doctor"));
        r.waitFor(1, 5000);
        check(r.events.size() == 1 && r.events.first().kind == QLatin1String("failure")
                  && r.events.first().reason.contains(QLatin1String("crashed")),
              QStringLiteral("a child killed by a signal fails once without crashing the host"));
    }

    // A child that overruns its budget: exactly one requestFailed, and the
    // child is not destroyed while it still runs.
    {
        const int before = warnings.size();
        Recorder r(writeProgram(dir, QStringLiteral("slow"), "exec sleep 10\n"), 300);
        r.bridge->request(QStringLiteral("census"));
        r.waitFor(1, 5000);
        check(r.events.size() == 1 && r.events.first().kind == QLatin1String("failure")
                  && r.events.first().reason.contains(QLatin1String("in time")),
              QStringLiteral("a timeout fails once"));
        check(warnings.size() == before, QStringLiteral("a timeout prints no warning"));
    }

    // A re-request while the first still runs: the first is superseded and
    // silent, the second answers once.
    {
        const QString marker = dir.filePath(QStringLiteral("first-started"));
        const QByteArray body = "if [ -e '" + QFile::encodeName(marker) + "' ]; then\n  " + kDocument
            + "else\n  touch '" + QFile::encodeName(marker) + "'\n  sleep 2\n  " + kDocument + "fi\n";
        Recorder r(writeProgram(dir, QStringLiteral("rerequest"), body), 0);
        r.bridge->request(QStringLiteral("doctor"));
        spin(300);
        r.bridge->request(QStringLiteral("doctor"));
        r.waitFor(1, 5000);
        spin(2500); // past the first child's own finish time
        check(r.events.size() == 1 && r.events.first().kind == QLatin1String("document"),
              QStringLiteral("a re-request supersedes the running one (%1 signal(s))").arg(r.events.size()));
    }

    // Two different requests run side by side and each answers once.
    {
        Recorder r(writeProgram(dir, QStringLiteral("pair"), kDocument), 0);
        r.bridge->request(QStringLiteral("version"));
        r.bridge->request(QStringLiteral("status"));
        r.waitFor(2, 5000);
        check(r.events.size() == 2, QStringLiteral("two names answer independently"));
    }

    // A program that does not exist: one requestFailed.
    {
        Recorder r(dir.filePath(QStringLiteral("missing")), 0);
        r.bridge->request(QStringLiteral("login"));
        r.waitFor(1, 5000);
        check(r.events.size() == 1 && r.events.first().kind == QLatin1String("failure"),
              QStringLiteral("a missing program fails once"));
    }

    // No program at all, and an unknown name: refused synchronously, once.
    {
        Recorder r(QString(), 0);
        r.bridge->request(QStringLiteral("version"));
        check(r.events.size() == 1 && r.events.first().kind == QLatin1String("failure"),
              QStringLiteral("no irlume command is refused at once"));
        Recorder r2(writeProgram(dir, QStringLiteral("unused"), kDocument), 0);
        r2.bridge->request(QStringLiteral("rm -rf"));
        r2.waitFor(1, 1000);
        check(r2.events.size() == 1 && r2.events.first().kind == QLatin1String("failure")
                  && !IrlumeBridge::knownRequest(QStringLiteral("rm -rf")),
              QStringLiteral("an unknown request is refused without a process"));
    }

    // Destroying the bridge with a child still running: silent, no warning.
    {
        const int before = warnings.size();
        auto r = std::make_unique<Recorder>(writeProgram(dir, QStringLiteral("slow2"), "exec sleep 10\n"), 0);
        r->bridge->request(QStringLiteral("doctor"));
        spin(200);
        r.reset();
        spin(200);
        check(warnings.size() == before, QStringLiteral("destroying the bridge mid-request prints no warning"));
    }

    // The handoff child reports asynchronously, exactly once.
    {
        int calls = 0;
        IrlumeBridge::HandoffResult result = IrlumeBridge::HandoffResult::Unknown;
        IrlumeBridge ok(writeProgram(dir, QStringLiteral("handoff-ok"), "exit 0\n"), 0);
        ok.handoffTui(QStringLiteral("faces"), 5000, [&](IrlumeBridge::HandoffResult r) {
            ++calls;
            result = r;
        });
        check(calls == 0, QStringLiteral("the handoff does not block the caller"));
        for (int waited = 0; waited < 5000 && calls == 0; waited += 20) {
            spin(20);
        }
        spin(200);
        check(calls == 1 && result == IrlumeBridge::HandoffResult::Done, QStringLiteral("a handoff that exits 0 is Done"));

        calls = 0;
        IrlumeBridge refused(writeProgram(dir, QStringLiteral("handoff-no"), "exit 3\n"), 0);
        refused.handoffTui(QString(), 5000, [&](IrlumeBridge::HandoffResult r) {
            ++calls;
            result = r;
        });
        for (int waited = 0; waited < 5000 && calls == 0; waited += 20) {
            spin(20);
        }
        spin(200);
        check(calls == 1 && result == IrlumeBridge::HandoffResult::NotAccepted,
              QStringLiteral("a handoff that exits nonzero is NotAccepted"));

        calls = 0;
        const int before = warnings.size();
        IrlumeBridge slow(writeProgram(dir, QStringLiteral("handoff-slow"), "exec sleep 10\n"), 0);
        slow.handoffTui(QString(), 300, [&](IrlumeBridge::HandoffResult r) {
            ++calls;
            result = r;
        });
        for (int waited = 0; waited < 5000 && calls == 0; waited += 20) {
            spin(20);
        }
        spin(400);
        check(calls == 1 && result == IrlumeBridge::HandoffResult::Unknown && warnings.size() == before,
              QStringLiteral("a handoff over its budget is Unknown, once, without a warning"));
    }

    check(warnings.isEmpty(), QStringLiteral("no warnings (%1 printed)").arg(warnings.size()));
    std::printf("%s\n", failures == 0 ? "bridgetest: PASS" : "bridgetest: FAIL");
    return failures == 0 ? 0 : 1;
}
