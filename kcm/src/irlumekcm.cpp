// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#include "irlumekcm.h"

#include <KIO/ApplicationLauncherJob>
#include <KJob>
#include <KPluginFactory>
#include <KPluginMetaData>
#include <KService>

K_PLUGIN_CLASS_WITH_JSON(IrlumeKcm, "kcm_irlume.json")

IrlumeKcm::IrlumeKcm(QObject *parent, const KPluginMetaData &data)
    : KQuickConfigModule(parent, data)
    , m_bridge(this)
{
    setButtons({});

    connect(&m_bridge, &IrlumeBridge::documentReady, this, &IrlumeKcm::documentReady);
    connect(&m_bridge, &IrlumeBridge::requestFailed, this, &IrlumeKcm::requestFailed);
}

IrlumeKcm::~IrlumeKcm() = default;

QString IrlumeKcm::irlumePath() const
{
    return m_bridge.irlumePath();
}

void IrlumeKcm::request(const QString &name)
{
    m_bridge.request(name);
}

void IrlumeKcm::launchTui(const QString &page, const QString &origin)
{
    if (m_bridge.irlumePath().isEmpty()) {
        Q_EMIT launchFailed(origin, QStringLiteral("the irlume command was not found"));
        return;
    }
    m_launchOrigin = origin;
    // When a TUI is already running, hand the page over WITHOUT opening a
    // terminal: the child performs the handoff and exits at once, so no
    // window flashes open and closed. The verdict arrives asynchronously;
    // if no live TUI accepted the handoff (the probe raced an exit), open
    // the terminal so the click still does something visible. A click
    // while a handoff is pending replaces the page that follows it, and
    // the page a failure is reported to.
    m_bridge.showTuiPage(page, 5000, [this](const QString &target) {
        openTerminal(target, m_launchOrigin);
    });
}

void IrlumeKcm::openTerminal(const QString &page, const QString &origin)
{
    if (m_bridge.launchTuiDetached(page)) {
        return;
    }
    // Fallback: the shipped desktop entry (opens the TUI without a deep
    // link). The single-instance guard hands the page off when a TUI is
    // already running, but a plain launch cannot pick the page.
    const KService::Ptr service =
        KService::serviceByStorageId(QStringLiteral("io.github.archledger.Irlume.desktop"));
    if (!service) {
        Q_EMIT launchFailed(origin, QStringLiteral("the irlume desktop entry was not found"));
        return;
    }
    auto *job = new KIO::ApplicationLauncherJob(service, this);
    connect(job, &KJob::result, this, [this, origin](KJob *finished) {
        if (finished->error() != 0) {
            Q_EMIT launchFailed(origin, finished->errorString());
        }
    });
    job->start();
}

#include "irlumekcm.moc"
