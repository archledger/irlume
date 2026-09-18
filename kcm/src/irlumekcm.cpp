// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
#include "irlumekcm.h"

#include <KIO/ApplicationLauncherJob>
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

void IrlumeKcm::launchTui(const QString &page)
{
    // When a TUI is already running, hand the page over WITHOUT opening a
    // terminal: the child performs the handoff and exits instantly, so no
    // window flashes open and closed. The handoff is verified
    // synchronously: if no live TUI accepted it (the probe raced an exit),
    // fall through and open the terminal so the click still does
    // something visible.
    if (m_bridge.tuiProbablyRunning()
        && m_bridge.handoffTuiAndWait(page, 5000)
               == IrlumeBridge::HandoffResult::Done) {
        return;
    }
    if (m_bridge.launchTuiDetached(page)) {
        return;
    }
    // Fallback: the shipped desktop entry (opens the TUI without a deep
    // link). The single-instance guard hands the page off when a TUI is
    // already running, but a plain launch cannot pick the page.
    const KService::Ptr service =
        KService::serviceByStorageId(QStringLiteral("io.github.archledger.Irlume.desktop"));
    if (!service) {
        Q_EMIT requestFailed(QStringLiteral("launch"), QStringLiteral("the irlume desktop entry was not found"));
        return;
    }
    auto *job = new KIO::ApplicationLauncherJob(service, this);
    job->start();
}

#include "irlumekcm.moc"
