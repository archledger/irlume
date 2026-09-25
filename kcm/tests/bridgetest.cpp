// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Failure-path test for IrlumeBridge (compiled here, one copy), against
// fake irlume programs written to a temporary directory. Checks the
// contract the pages rely on: exactly one documentReady or requestFailed
// per request that is not superseded, a superseded request stays silent,
// a child that dies from a signal or overruns its budget cannot crash the
// host, QProcess never warns about destroying a running child, and clicks
// during a TUI handoff end on the latest page.
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

#include <fcntl.h>
#include <pwd.h>
#include <sys/file.h>
#include <unistd.h>

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

// Holds the TUI single-instance lock under a private XDG_RUNTIME_DIR, so
// the bridge's probe sees a running TUI. The file name follows the guard's
// contract (tui-<login name>.lock, non-ASCII-alphanumerics other than
// -_. as underscores); flock on a second open file description conflicts
// even within this process.
struct FakeRunningTui {
    int fd = -1;
    QByteArray savedRuntimeDir;

    explicit FakeRunningTui(const QTemporaryDir &dir)
        : savedRuntimeDir(qgetenv("XDG_RUNTIME_DIR"))
    {
        const QString runtime = dir.filePath(QStringLiteral("runtime"));
        QDir().mkpath(runtime + QStringLiteral("/irlume"));
        qputenv("XDG_RUNTIME_DIR", QFile::encodeName(runtime));
        const struct passwd *pw = getpwuid(geteuid());
        QString user = pw != nullptr ? QString::fromLatin1(pw->pw_name) : QString();
        for (QChar &ch : user) {
            if (!((ch.unicode() < 128) && ch.isLetterOrNumber()) && ch != u'-' && ch != u'_' && ch != u'.') {
                ch = u'_';
            }
        }
        const QString lock = runtime + QStringLiteral("/irlume/tui-%1.lock").arg(user);
        fd = open(QFile::encodeName(lock).constData(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) != 0) {
            close(fd);
            fd = -1;
        }
    }
    ~FakeRunningTui()
    {
        if (fd >= 0) {
            close(fd);
        }
        if (savedRuntimeDir.isNull()) {
            qunsetenv("XDG_RUNTIME_DIR");
        } else {
            qputenv("XDG_RUNTIME_DIR", savedRuntimeDir);
        }
    }
};

// A handoff child that appends its page to `log`, takes 300 ms and exits
// with `code`.
QByteArray handoffBody(const QString &log, int code)
{
    return QStringLiteral("printf '%s\\n' \"${3:-none}\" >> '%1'\nsleep 0.3\nexit %2\n")
        .arg(log)
        .arg(code)
        .toUtf8();
}

QStringList readLines(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    return QString::fromUtf8(file.readAll()).split(u'\n', Qt::SkipEmptyParts);
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

    // Clicks while a handoff is pending: the latest page wins, and at most
    // one terminal opens.
    {
        QStringList opened;
        const auto open = [&opened](const QString &page) {
            opened << page;
        };
        IrlumeBridge none(writeProgram(dir, QStringLiteral("unused-tui"), "exit 0\n"), 0);
        {
            const QByteArray saved = qgetenv("XDG_RUNTIME_DIR");
            qputenv("XDG_RUNTIME_DIR", QFile::encodeName(dir.filePath(QStringLiteral("no-runtime"))));
            none.showTuiPage(QStringLiteral("faces"), 5000, open);
            if (saved.isNull()) {
                qunsetenv("XDG_RUNTIME_DIR");
            } else {
                qputenv("XDG_RUNTIME_DIR", saved);
            }
        }
        check(opened == QStringList{QStringLiteral("faces")},
              QStringLiteral("with no TUI running the page opens at once, without a handoff"));

        FakeRunningTui tui(dir);
        check(tui.fd >= 0 && none.tuiProbablyRunning(), QStringLiteral("the fake TUI lock reads as a running TUI"));

        opened.clear();
        const QString takenLog = dir.filePath(QStringLiteral("taken.log"));
        IrlumeBridge taken(writeProgram(dir, QStringLiteral("handoff-taken"), handoffBody(takenLog, 0)), 0);
        taken.showTuiPage(QStringLiteral("faces"), 5000, open);
        spin(50);
        taken.showTuiPage(QStringLiteral("cameras"), 5000, open);
        taken.showTuiPage(QStringLiteral("settings"), 5000, open);
        for (int waited = 0; waited < 5000 && readLines(takenLog).size() < 2; waited += 20) {
            spin(20);
        }
        spin(600);
        check(readLines(takenLog) == QStringList{QStringLiteral("faces"), QStringLiteral("settings")} && opened.isEmpty(),
              QStringLiteral("a TUI that takes the handoff then gets the latest page clicked meanwhile"));

        const QString refusedLog = dir.filePath(QStringLiteral("refused.log"));
        IrlumeBridge refusedTui(writeProgram(dir, QStringLiteral("handoff-refused"), handoffBody(refusedLog, 3)), 0);
        refusedTui.showTuiPage(QStringLiteral("faces"), 5000, open);
        spin(50);
        refusedTui.showTuiPage(QStringLiteral("cameras"), 5000, open);
        for (int waited = 0; waited < 5000 && opened.isEmpty(); waited += 20) {
            spin(20);
        }
        spin(600);
        check(readLines(refusedLog) == QStringList{QStringLiteral("faces")} && opened == QStringList{QStringLiteral("cameras")},
              QStringLiteral("a refused handoff opens one terminal, on the latest page clicked"));
    }

    check(warnings.isEmpty(), QStringLiteral("no warnings (%1 printed)").arg(warnings.size()));
    std::printf("%s\n", failures == 0 ? "bridgetest: PASS" : "bridgetest: FAIL");
    return failures == 0 ? 0 : 1;
}
