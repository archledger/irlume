// SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Offscreen page test for the irlume KCM. Loads every page through
// KQuickConfigModuleLoader, the way System Settings does, with a stand-in
// module that answers from the fixture sets in kcm/tests/fixtures/ and the
// module's real QML (compiled into the stand-in at qrc:/kcm/kcm_irlume/).
// Each page is checked for every fixture set at a narrow and a wide size,
// before and after Refresh:
//   - no QML warning (a few environment lines are allowed by exact text);
//   - no text outside the page, and no text wider than its item;
//   - rows in model order, actions outside the lists, section headers
//     with their counts, and the state and wording each fixture calls for.
// Exits non-zero when any check fails.
// Usage: kcm_pagetest [<stand-in module> <host.qml> <fixtures dir>]
// (the build supplies the defaults).

#include <KPluginMetaData>
#include <KQuickConfigModule>
#include <KQuickConfigModuleLoader>

#include <QAbstractItemModel>
#include <QApplication>
#include <QDir>
#include <QEventLoop>
#include <QMap>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQuickItem>
#include <QQuickWindow>
#include <QSGRendererInterface>
#include <QTemporaryDir>
#include <QTimer>

#include <cstdio>
#include <functional>
#include <memory>

namespace
{
int g_failures = 0;
int g_checks = 0;
QString g_context;
QStringList g_warnings;

void check(bool ok, const QString &what)
{
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::printf("FAIL  %s: %s\n", qUtf8Printable(g_context), qUtf8Printable(what));
    }
}

// Lines the environment prints that say nothing about the module. Matched
// as exact substrings; anything else a page prints fails the test.
const QStringList kAllowedMessages = {
    // The offscreen platform plugin, once per window.
    QStringLiteral("This plugin does not support propagateSizeHints()"),
};

void messageHandler(QtMsgType type, const QMessageLogContext &, const QString &message)
{
    if (type == QtDebugMsg || type == QtInfoMsg) {
        return;
    }
    for (const QString &allowed : kAllowedMessages) {
        if (message.contains(allowed)) {
            return;
        }
    }
    g_warnings << QStringLiteral("%1: %2").arg(g_context, message);
    std::fprintf(stderr, "warning [%s]: %s\n", qUtf8Printable(g_context), qUtf8Printable(message));
    if (type == QtFatalMsg) {
        std::abort();
    }
}

void spin(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

void waitSettled(QObject *module)
{
    for (int waited = 0; waited < 5000 && module->property("outstanding").toInt() > 0; waited += 10) {
        spin(10);
    }
    // Let bindings, layouts and polish settle.
    spin(150);
}

QList<QQuickItem *> allItems(QQuickItem *root)
{
    QList<QQuickItem *> out;
    QList<QQuickItem *> todo{root};
    while (!todo.isEmpty()) {
        QQuickItem *item = todo.takeFirst();
        out << item;
        todo << item->childItems();
    }
    return out;
}

QQuickItem *findItem(QQuickItem *root, const QString &name)
{
    const auto items = allItems(root);
    for (QQuickItem *item : items) {
        if (item->objectName() == name) {
            return item;
        }
    }
    return nullptr;
}

bool isDescendant(const QQuickItem *item, const QQuickItem *ancestor)
{
    for (const QQuickItem *p = item; p != nullptr; p = p->parentItem()) {
        if (p == ancestor) {
            return true;
        }
    }
    return false;
}

bool shown(const QQuickItem *item)
{
    return item != nullptr && item->isVisible() && item->opacity() > 0.0;
}

// The words an item shows: `text`, or `value` for a StateValue row.
QString textOf(const QQuickItem *item)
{
    if (item == nullptr) {
        return QString();
    }
    const QVariant text = item->property("text");
    return text.isValid() ? text.toString() : item->property("value").toString();
}

QRectF sceneRect(const QQuickItem *item)
{
    return QRectF(item->mapToScene(QPointF(0, 0)), QSizeF(item->width(), item->height()));
}

struct Page {
    QString label;
    QString file; // empty: the module's mainUi
};

struct Ctx {
    QQuickItem *page = nullptr;
    KQuickConfigModule *module = nullptr;
    QString set;

    [[nodiscard]] QQuickItem *item(const QString &name) const
    {
        return findItem(page, name);
    }
    void visible(const QString &name, bool expected = true) const
    {
        check(shown(item(name)) == expected,
              QStringLiteral("%1 is %2").arg(name, expected ? QStringLiteral("shown") : QStringLiteral("hidden")));
    }
    void textContains(const QString &name, const QString &needle) const
    {
        const QString text = textOf(item(name));
        check(text.contains(needle), QStringLiteral("%1 says \"%2\" (it says \"%3\")").arg(name, needle, text));
    }
    void level(const QString &name, const QString &expected) const
    {
        const QQuickItem *row = item(name);
        const QString actual = row != nullptr ? row->property("level").toString() : QString();
        check(actual == expected, QStringLiteral("%1 level is %2 (it is %3)").arg(name, expected, actual));
    }
    // Some item inside the named one shows exactly `expected`.
    void showsText(const QString &name, const QString &expected) const
    {
        const QQuickItem *target = item(name);
        bool found = false;
        if (target != nullptr) {
            const auto items = allItems(const_cast<QQuickItem *>(target));
            for (const QQuickItem *inner : items) {
                found = found || (shown(inner) && textOf(inner) == expected);
            }
        }
        check(found, QStringLiteral("%1 shows \"%2\"").arg(name, expected));
    }
    // No item on the page shows text containing `needle`.
    void nowhere(const QString &needle) const
    {
        const auto items = allItems(page);
        QString hit;
        for (const QQuickItem *inner : items) {
            if (shown(inner) && textOf(inner).contains(needle)) {
                hit = textOf(inner);
            }
        }
        check(hit.isEmpty(), QStringLiteral("no text says \"%1\" (found \"%2\")").arg(needle, hit));
    }
    // Every named item is shown and each starts below the one before it.
    void order(const QStringList &names) const
    {
        qreal last = -1e9;
        for (const QString &name : names) {
            const QQuickItem *row = item(name);
            if (!shown(row)) {
                check(false, QStringLiteral("%1 is shown (for the order check)").arg(name));
                return;
            }
            const qreal y = row->mapToScene(QPointF(0, 0)).y();
            check(y > last + 0.5, QStringLiteral("%1 comes after the row before it (y %2 after %3)").arg(name).arg(y).arg(last));
            last = y;
        }
    }
    // The named item is not inside the page's scrolling content: it sits in
    // the header or the footer.
    void outsideContent(const QString &name) const
    {
        const QQuickItem *target = item(name);
        auto *flickable = page->property("flickable").value<QQuickItem *>();
        if (flickable == nullptr) {
            flickable = page->property("view").value<QQuickItem *>();
        }
        check(shown(target) && flickable != nullptr && !isDescendant(target, flickable),
              QStringLiteral("%1 is outside the scrolling content").arg(name));
    }
};

// No text is painted outside the page, and none is wider than its item.
void checkBounds(const Ctx &ctx)
{
    const QRectF bounds = sceneRect(ctx.page);
    const auto items = allItems(ctx.page);
    for (QQuickItem *item : items) {
        if (!shown(item) || item->width() <= 0 || item->height() <= 0) {
            continue;
        }
        const QString type = QString::fromLatin1(item->metaObject()->className());
        if (type.startsWith(QLatin1String("KQuickStyleItem"))) {
            continue; // the desktop style repeats a button's text internally
        }
        const QVariant text = item->property("text");
        if (!text.isValid() || text.typeId() != QMetaType::QString || text.toString().isEmpty()) {
            continue;
        }
        QRectF painted = sceneRect(item);
        const QVariant contentWidth = item->property("contentWidth");
        const QVariant alignment = item->property("effectiveHorizontalAlignment");
        if (contentWidth.isValid() && alignment.isValid()) {
            const qreal cw = contentWidth.toReal();
            const int align = alignment.toInt();
            qreal left = painted.left();
            if (align & Qt::AlignRight) {
                left = painted.right() - cw;
            } else if (align & Qt::AlignHCenter) {
                left = painted.left() + (painted.width() - cw) / 2;
            }
            check(cw <= item->width() + 0.5,
                  QStringLiteral("text fits its item (%1 > %2): %3").arg(cw).arg(item->width()).arg(text.toString().left(60)));
            painted = QRectF(left, painted.top(), cw, painted.height());
        }
        check(painted.left() >= bounds.left() - 0.5 && painted.right() <= bounds.right() + 0.5,
              QStringLiteral("text inside the page (x %1..%2 in %3..%4): %5")
                  .arg(painted.left()).arg(painted.right()).arg(bounds.left()).arg(bounds.right())
                  .arg(text.toString().left(60)));
    }
}

QList<QVariantMap> modelRows(QAbstractItemModel *model)
{
    QList<QVariantMap> rows;
    if (model == nullptr) {
        return rows;
    }
    const auto roles = model->roleNames();
    for (int row = 0; row < model->rowCount(); ++row) {
        QVariantMap values;
        for (auto it = roles.cbegin(); it != roles.cend(); ++it) {
            values.insert(QString::fromUtf8(it.value()), model->data(model->index(row, 0), it.key()));
        }
        rows << values;
    }
    return rows;
}

void checkOverview(const Ctx &c)
{
    const QStringList rows = {
        QStringLiteral("daemonRow"), QStringLiteral("enrollmentRow"), QStringLiteral("keyringRow"),
        QStringLiteral("templatesRow"), QStringLiteral("recoveryRow"), QStringLiteral("sensorsRow"),
        QStringLiteral("fingerprintRow"),
    };
    const bool hasStatus = c.set != QLatin1String("refused") && c.set != QLatin1String("failure");
    // The short set's version document advertises no capabilities.
    const QStringList details = c.set == QLatin1String("short")
        ? QStringList{}
        : QStringList{QStringLiteral("detailsSection"), QStringLiteral("detailsActions")};
    c.visible(QStringLiteral("detailsSection"), !details.isEmpty());
    if (hasStatus) {
        // Face sensors and Fingerprint reader sit with the other status
        // rows, above the actions.
        c.order(QStringList{QStringLiteral("statusSection")} + rows
                + QStringList{QStringLiteral("changesSection"), QStringLiteral("enrollmentActions"),
                              QStringLiteral("secretsActions")}
                + details);
        c.visible(QStringLiteral("noStatus"), false);
    } else {
        c.visible(QStringLiteral("noStatus"));
        c.visible(QStringLiteral("statusMessage"));
        c.visible(QStringLiteral("daemonRow"), false);
        // The message sits under the version, above the navigation.
        c.order(QStringList{QStringLiteral("versionRow"), QStringLiteral("noStatus")} + details);
    }
    c.outsideContent(QStringLiteral("footerRefresh"));
    if (c.set == QLatin1String("real")) {
        for (const QString &row : rows.mid(0, 6)) {
            c.level(row, QStringLiteral("good"));
        }
        c.level(QStringLiteral("fingerprintRow"), QStringLiteral("neutral"));
        c.textContains(QStringLiteral("enrollmentRow"), QStringLiteral("1 profile, 16 scans"));
        c.visible(QStringLiteral("statusMessage"), false);
        c.showsText(QStringLiteral("keyringRow"), QStringLiteral("Sealing: Tier 2 \u00b7 pcrlock"));
        c.textContains(QStringLiteral("walletButton"), QStringLiteral("Manage wallet unlock"));
        c.textContains(QStringLiteral("recoveryButton"), QStringLiteral("Change recovery passphrase"));
    } else if (c.set == QLatin1String("unreachable")) {
        c.level(QStringLiteral("daemonRow"), QStringLiteral("problem"));
        c.level(QStringLiteral("sensorsRow"), QStringLiteral("unknown"));
        c.textContains(QStringLiteral("sensorsRow"), QStringLiteral("not checked (daemon not reachable)"));
        c.level(QStringLiteral("templatesRow"), QStringLiteral("unknown"));
    } else if (c.set == QLatin1String("starting")) {
        c.level(QStringLiteral("daemonRow"), QStringLiteral("attention"));
        // A starting daemon is reachable; the row must not say otherwise.
        c.textContains(QStringLiteral("sensorsRow"), QStringLiteral("not checked (daemon still starting)"));
        c.nowhere(QStringLiteral("not reachable"));
    } else if (c.set == QLatin1String("access-denied")) {
        c.level(QStringLiteral("daemonRow"), QStringLiteral("problem"));
        c.textContains(QStringLiteral("sensorsRow"), QStringLiteral("(daemon not reachable from this account)"));
    } else if (c.set == QLatin1String("edge")) {
        c.textContains(QStringLiteral("recoveryButton"), QStringLiteral("Set recovery passphrase"));
    } else if (c.set == QLatin1String("key-missing")) {
        c.level(QStringLiteral("templatesRow"), QStringLiteral("problem"));
        c.level(QStringLiteral("sensorsRow"), QStringLiteral("attention"));
        c.level(QStringLiteral("fingerprintRow"), QStringLiteral("good"));
    } else if (c.set == QLatin1String("refused")) {
        c.textContains(QStringLiteral("statusMessage"), QStringLiteral("could not be reached"));
    } else if (c.set == QLatin1String("failure")) {
        c.textContains(QStringLiteral("statusMessage"), QStringLiteral("did not answer in time"));
    }
}

void checkDiagnostics(const Ctx &c)
{
    QQuickItem *list = c.item(QStringLiteral("checkList"));
    auto *model = list != nullptr ? list->property("model").value<QAbstractItemModel *>() : nullptr;
    check(model != nullptr, QStringLiteral("the check list has a model"));
    const auto rows = modelRows(model);
    QStringList sections;
    for (const QVariantMap &row : rows) {
        const QString section = row.value(QStringLiteral("section")).toString();
        if (sections.isEmpty() || sections.last() != section) {
            check(!sections.contains(section), QStringLiteral("section %1 is contiguous").arg(section));
            sections << section;
        }
        check(row.value(QStringLiteral("checkId")).toString() != QLatin1String("credential-release-challenge"),
              QStringLiteral("the reserved legacy check is hidden"));
    }
    c.visible(QStringLiteral("empty"), rows.isEmpty());
    c.outsideContent(QStringLiteral("footerRefresh"));
    if (c.set == QLatin1String("real")) {
        check(sections == QStringList{QStringLiteral("Warnings (1)"), QStringLiteral("Not determined (2)"),
                                      QStringLiteral("Passing (21)"), QStringLiteral("Informational (7)")},
              QStringLiteral("sections in problem-first order with counts (%1)").arg(sections.join(QStringLiteral(", "))));
        for (const QVariantMap &row : rows) {
            const QString id = row.value(QStringLiteral("checkId")).toString();
            check(row.value(QStringLiteral("title")).toString() != id, QStringLiteral("%1 has a title").arg(id));
            if (id.startsWith(QLatin1String("emitter-"))) {
                check(row.value(QStringLiteral("shown")).toString().contains(QLatin1String("administrator rights")),
                      QStringLiteral("%1 explains it needs administrator rights").arg(id));
            }
            if (id == QLatin1String("capture-mode")) {
                check(!row.value(QStringLiteral("wrap")).toBool(), QStringLiteral("capture-mode detail is one line"));
            }
            if (id == QLatin1String("install-hygiene")) {
                check(!row.value(QStringLiteral("shown")).toString().isEmpty(),
                      QStringLiteral("a warning without detail says where to look"));
            }
            // Titles name what is checked, never an outcome.
            static const QMap<QString, QString> neutral = {
                {QStringLiteral("camera-nodes"), QStringLiteral("RGB and IR cameras")},
                {QStringLiteral("models"), QStringLiteral("Face models")},
                {QStringLiteral("templates"), QStringLiteral("Face template encryption")},
                {QStringLiteral("ir-stream-hello-minimum"), QStringLiteral("IR stream against the Windows Hello minimum")},
            };
            if (neutral.contains(id)) {
                check(row.value(QStringLiteral("title")).toString() == neutral.value(id),
                      QStringLiteral("%1 has a neutral title").arg(id));
            }
        }
        // The topmost section header on screen (a Refresh may leave the old
        // delegates hidden until they are released).
        const QQuickItem *header = nullptr;
        const auto items = allItems(c.page);
        for (const QQuickItem *item : items) {
            if (item->objectName() == QLatin1String("section") && shown(item)
                && (header == nullptr || item->mapToScene(QPointF(0, 0)).y() < header->mapToScene(QPointF(0, 0)).y())) {
                header = item;
            }
        }
        check(header != nullptr && textOf(header) == QLatin1String("Warnings (1)"),
              QStringLiteral("the first section header is shown (%1)").arg(textOf(header)));
        c.visible(QStringLiteral("summaryMessage"));
        c.textContains(QStringLiteral("summaryMessage"), QStringLiteral("1 warning, 2 not determined, 21 passing"));
        c.outsideContent(QStringLiteral("summaryMessage"));
        c.visible(QStringLiteral("footerAction"), false);
    } else if (c.set == QLatin1String("edge")) {
        check(sections.first() == QLatin1String("Failing (1)") && sections.last() == QLatin1String("Other (1)"),
              QStringLiteral("failing first, unknown states last (%1)").arg(sections.join(QStringLiteral(", "))));
        for (const QVariantMap &row : rows) {
            if (row.value(QStringLiteral("checkId")).toString() == QLatin1String("ir-calibration")) {
                check(row.value(QStringLiteral("shown")).toString() == QLatin1String("This check could not be carried out."),
                      QStringLiteral("an undetermined check without detail says it could not be carried out"));
            }
        }
    } else if (c.set == QLatin1String("refused")) {
        c.visible(QStringLiteral("requestMessage"));
        c.textContains(QStringLiteral("requestMessage"), QStringLiteral("could not be reached"));
        c.visible(QStringLiteral("summaryMessage"), false);
    } else if (c.set == QLatin1String("empty") || c.set == QLatin1String("short")) {
        c.visible(QStringLiteral("summaryMessage"), false);
    }
}

void checkCameras(const Ctx &c)
{
    c.outsideContent(QStringLiteral("footerRefresh"));
    if (c.set == QLatin1String("real")) {
        c.order({QStringLiteral("device-/dev/video0"), QStringLiteral("device-/dev/video2"), QStringLiteral("alsoFound")});
        c.visible(QStringLiteral("device-/dev/video1"), false);
        c.textContains(QStringLiteral("alsoFound"), QStringLiteral("/dev/video1, /dev/video3 (metadata interfaces, not cameras)"));
        c.outsideContent(QStringLiteral("footerAction"));
        c.textContains(QStringLiteral("footerAction"), QStringLiteral("Pick the camera pair"));
        c.visible(QStringLiteral("shutterMessage"), false);
        // `paired` is a fact about the device, not about face login.
        c.showsText(QStringLiteral("device-/dev/video0"), QStringLiteral("Supported · part of an RGB + IR pair"));
        c.nowhere(QStringLiteral("face login"));
    } else if (c.set == QLatin1String("edge")) {
        c.visible(QStringLiteral("shutterMessage"));
        // The machine-level row has no node; it is titled from its class.
        c.visible(QStringLiteral("device-"));
        const auto items = allItems(c.item(QStringLiteral("device-")));
        bool titled = false;
        for (const QQuickItem *item : items) {
            titled = titled || textOf(item) == QLatin1String("Intel IPU6 MIPI camera pipeline");
        }
        check(titled, QStringLiteral("a row without a node is titled from its class"));
    } else if (c.set == QLatin1String("empty") || c.set == QLatin1String("short")) {
        c.visible(QStringLiteral("empty"));
    } else if (c.set == QLatin1String("refused")) {
        c.visible(QStringLiteral("requestMessage"));
    }
}

void checkLogin(const Ctx &c)
{
    c.outsideContent(QStringLiteral("footerRefresh"));
    if (c.set == QLatin1String("real")) {
        c.order({QStringLiteral("managerRow"), QStringLiteral("selinuxRow"), QStringLiteral("surfacesSection"),
                 QStringLiteral("surface-plasmalogin"), QStringLiteral("surface-kde"), QStringLiteral("surface-sudo"),
                 QStringLiteral("surface-polkit-1")});
        c.visible(QStringLiteral("surface-sddm"), false);
        c.level(QStringLiteral("selinuxRow"), QStringLiteral("unknown"));
        // `unknown` is also what a host without the SELinux tools reports,
        // so the page claims no more than the contract does.
        c.showsText(QStringLiteral("selinuxRow"), QStringLiteral("not determined"));
        c.showsText(QStringLiteral("selinuxRow"), QStringLiteral("Reading it needs administrator rights on SELinux systems."));
        c.level(QStringLiteral("surface-plasmalogin"), QStringLiteral("good"));
        c.outsideContent(QStringLiteral("footerAction"));
        c.textContains(QStringLiteral("footerAction"), QStringLiteral("Change wiring"));
    } else if (c.set == QLatin1String("edge")) {
        c.level(QStringLiteral("managerRow"), QStringLiteral("attention"));
        c.visible(QStringLiteral("selinuxRow"), false);
        c.visible(QStringLiteral("unmappedMessage"));
        c.textContains(QStringLiteral("unmappedMessage"), QStringLiteral("lightdm-autologin"));
        c.visible(QStringLiteral("surface-lightdm"));
        // This machine's own login screen, not wired.
        c.level(QStringLiteral("surface-lightdm"), QStringLiteral("attention"));
        c.level(QStringLiteral("surface-sudo"), QStringLiteral("good"));
    } else if (c.set == QLatin1String("empty")) {
        c.visible(QStringLiteral("noSurfaces"));
        c.level(QStringLiteral("managerRow"), QStringLiteral("unknown"));
    } else if (c.set == QLatin1String("refused")) {
        // not-authorized is not retryable.
        c.visible(QStringLiteral("requestMessage"));
        c.textContains(QStringLiteral("requestMessage"), QStringLiteral("may not read"));
    }
}

bool runPage(const std::shared_ptr<QQmlEngine> &engine, const QString &modulePath, const QString &hostPath,
             const QString &fixtures, const Page &page, const QSize &size)
{
    const QString set = QDir(fixtures).dirName();
    g_context = QStringLiteral("%1/%2@%3x%4").arg(set, page.label).arg(size.width()).arg(size.height());

    const KPluginMetaData metaData(modulePath);
    auto result = KQuickConfigModuleLoader::loadModule(metaData, nullptr, QVariantList{fixtures, 10}, engine);
    if (!result) {
        check(false, QStringLiteral("the stand-in module loads: %1").arg(result.errorString));
        return false;
    }
    std::unique_ptr<KQuickConfigModule> module(result.plugin);

    auto window = std::make_unique<QQuickWindow>();
    window->resize(size);
    QQmlComponent hostComponent(engine.get(), QUrl::fromLocalFile(hostPath));
    std::unique_ptr<QObject> hostObject(hostComponent.createWithInitialProperties(
        {{QStringLiteral("kcm"), QVariant::fromValue<QObject *>(module.get())}}));
    auto *host = qobject_cast<QQuickItem *>(hostObject.get());
    if (host == nullptr) {
        check(false, QStringLiteral("the host loads: %1").arg(hostComponent.errorString()));
        return false;
    }
    host->setParentItem(window->contentItem());

    QQuickItem *mainUi = module->mainUi();
    if (mainUi == nullptr) {
        check(false, QStringLiteral("mainUi loads: %1").arg(module->errorString()));
        return false;
    }
    QObject::connect(module.get(), &KQuickConfigModule::pagePushed, host, [host](QQuickItem *pushed) {
        QMetaObject::invokeMethod(host, "pushPage", Q_ARG(QVariant, QVariant::fromValue<QObject *>(pushed)));
    });
    QMetaObject::invokeMethod(host, "pushPage", Q_ARG(QVariant, QVariant::fromValue<QObject *>(mainUi)));
    window->show();
    if (!page.file.isEmpty()) {
        waitSettled(module.get());
        module->push(page.file);
    }

    auto *pageStack = host->property("pageStack").value<QObject *>();
    auto *current = pageStack != nullptr ? pageStack->property("currentItem").value<QQuickItem *>() : nullptr;
    if (current == nullptr) {
        check(false, QStringLiteral("a page is on the stack"));
        return false;
    }
    // Before any answer: the loading placeholder, not bare rows.
    Ctx ctx{current, module.get(), set};
    {
        const QQuickItem *loading = findItem(current, QStringLiteral("loading"));
        check(loading != nullptr && loading->property("visible").toBool(),
              QStringLiteral("the loading placeholder shows while the first document is pending"));
    }

    const std::function<void(const Ctx &)> pageChecks = page.label == QLatin1String("overview") ? checkOverview
        : page.label == QLatin1String("diagnostics")                                         ? checkDiagnostics
        : page.label == QLatin1String("cameras")                                             ? checkCameras
                                                                                             : checkLogin;
    for (const bool refreshed : {false, true}) {
        g_context = QStringLiteral("%1/%2@%3x%4%5").arg(set, page.label).arg(size.width()).arg(size.height())
                        .arg(refreshed ? QStringLiteral(" after Refresh") : QString());
        if (refreshed) {
            QMetaObject::invokeMethod(current, "refresh");
        }
        waitSettled(module.get());
        ctx.visible(QStringLiteral("loading"), false);
        checkBounds(ctx);
        pageChecks(ctx);
    }
    check(module->property("launches").toStringList().isEmpty(), QStringLiteral("nothing was launched"));

    window->hide();
    hostObject.reset();
    window.reset();
    module.reset();
    spin(0);
    return true;
}
} // namespace

int main(int argc, char **argv)
{
    // Never touch the developer's display, session or configuration: an
    // offscreen software window, and private HOME and XDG directories.
    QTemporaryDir sandbox;
    if (!sandbox.isValid()) {
        std::fprintf(stderr, "cannot create a temporary directory\n");
        return 2;
    }
    for (const char *dir : {"home", "config", "cache", "data", "state", "runtime"}) {
        QDir(sandbox.path()).mkpath(QString::fromLatin1(dir));
    }
    QFile::setPermissions(sandbox.filePath(QStringLiteral("runtime")),
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    qputenv("HOME", QFile::encodeName(sandbox.filePath(QStringLiteral("home"))));
    qputenv("XDG_CONFIG_HOME", QFile::encodeName(sandbox.filePath(QStringLiteral("config"))));
    qputenv("XDG_CACHE_HOME", QFile::encodeName(sandbox.filePath(QStringLiteral("cache"))));
    qputenv("XDG_DATA_HOME", QFile::encodeName(sandbox.filePath(QStringLiteral("data"))));
    qputenv("XDG_STATE_HOME", QFile::encodeName(sandbox.filePath(QStringLiteral("state"))));
    qputenv("XDG_RUNTIME_DIR", QFile::encodeName(sandbox.filePath(QStringLiteral("runtime"))));
    qputenv("QT_QPA_PLATFORM", "offscreen");
    qputenv("QML_DISABLE_DISK_CACHE", "1");
    qunsetenv("DISPLAY");
    qunsetenv("WAYLAND_DISPLAY");
    qunsetenv("DBUS_SESSION_BUS_ADDRESS");
    QQuickWindow::setGraphicsApi(QSGRendererInterface::Software);

    QApplication app(argc, argv);
    QString modulePath = QStringLiteral(IRLUME_STANDIN_MODULE);
    QString hostPath = QStringLiteral(IRLUME_TEST_HOST);
    QString fixtureRoot = QStringLiteral(IRLUME_TEST_FIXTURES);
    if (app.arguments().size() == 4) {
        modulePath = app.arguments().at(1);
        hostPath = app.arguments().at(2);
        fixtureRoot = app.arguments().at(3);
    } else if (app.arguments().size() != 1) {
        std::fprintf(stderr, "usage: kcm_pagetest [<stand-in module> <host.qml> <fixtures dir>]\n");
        return 2;
    }
    qInstallMessageHandler(messageHandler);

    const QList<Page> pages = {
        {QStringLiteral("overview"), QString()},
        {QStringLiteral("diagnostics"), QStringLiteral("DiagnosticsPage.qml")},
        {QStringLiteral("cameras"), QStringLiteral("CamerasPage.qml")},
        {QStringLiteral("login"), QStringLiteral("LoginPage.qml")},
    };
    const QList<QSize> sizes = {QSize(420, 900), QSize(1530, 1044)};
    const QStringList sets = QDir(fixtureRoot).entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    check(sets.contains(QStringLiteral("real")), QStringLiteral("the fixture sets are found in %1").arg(fixtureRoot));

    auto engine = std::make_shared<QQmlEngine>();
    for (const QString &set : sets) {
        for (const Page &page : pages) {
            for (const QSize &size : sizes) {
                runPage(engine, modulePath, hostPath, QDir(fixtureRoot).filePath(set), page, size);
            }
        }
    }
    g_context = QStringLiteral("all");
    check(g_warnings.isEmpty(), QStringLiteral("no QML warning (%1 printed)").arg(g_warnings.size()));

    std::printf("%d checks, %d failed, %lld sets x %lld pages x %lld sizes\n", g_checks, g_failures,
                static_cast<long long>(sets.size()), static_cast<long long>(pages.size()),
                static_cast<long long>(sizes.size()));
    std::printf("%s\n", g_failures == 0 ? "pagetest: PASS" : "pagetest: FAIL");
    return g_failures == 0 ? 0 : 1;
}
