/*
 * PmVault extensions - GUI wiring and lifecycle manager implementation.
 */

#include "PmpManager.h"

#include "PmpAuditLog.h"
#include "PmpConfig.h"
#include "PmpIdentity.h"
#include "PmpQuickAccess.h"
#include "PmpSync.h"
#include "PmpTwoFactor.h"

#include "autotype/AutoType.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "gui/DatabaseTabWidget.h"
#include "gui/DatabaseWidget.h"
#include "gui/MainWindow.h"
#include "qrcode/QrCode.h"

#include <algorithm>

#include <QApplication>
#include <QAction>
#include <QBuffer>
#include <QClipboard>
#include <QColor>
#include <QPalette>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QSslSocket>
#include <QTimer>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QHostAddress>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QSvgWidget>
#include <QTableWidget>
#include <QVBoxLayout>

namespace
{
    bool isSixDigits(const QString& s)
    {
        return s.length() == 6 &&
               std::all_of(s.constBegin(), s.constEnd(), [](QChar c) { return c.isDigit(); });
    }

    // Configure a TOTP confirmation field:
    //  - starts EMPTY (no prefilled mask placeholders / dots),
    //  - digits appear in clear black text while typing (PasswordEchoOnEdit) and
    //    are masked only after the field loses focus / is accepted,
    //  - digits only, max 6, white background so black text stays readable.
    void setupCodeEdit(QLineEdit* edit, const QString& placeholder)
    {
        edit->setPlaceholderText(placeholder);
        edit->setMaxLength(6);
        edit->setEchoMode(QLineEdit::PasswordEchoOnEdit);
        edit->setValidator(
            new QRegularExpressionValidator(QRegularExpression(QStringLiteral("\\d{0,6}")), edit));
        edit->setStyleSheet(QStringLiteral("QLineEdit{color:#111111;background:#ffffff;"
                                           "selection-background-color:#4F6B9A;selection-color:#ffffff;}"));
        QPalette pal = edit->palette();
        pal.setColor(QPalette::Text, QColor(QStringLiteral("#111111")));
        pal.setColor(QPalette::PlaceholderText, QColor(QStringLiteral("#8a8f99")));
        edit->setPalette(pal);
    }

    // Prompt for a 6-digit TOTP code. Returns the code or an empty string if canceled.
    QString promptCode(QWidget* parent, const QString& title)
    {
        QDialog dlg(parent);
        dlg.setWindowTitle(title);
        auto* form = new QVBoxLayout(&dlg);
        auto* edit = new QLineEdit(&dlg);
        setupCodeEdit(edit, QObject::tr("6 位验证码"));
        form->addWidget(new QLabel(QObject::tr("请输入验证器 App 中当前显示的 6 位验证码："), &dlg));
        form->addWidget(edit);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
        form->addWidget(buttons);
        QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
        edit->setFocus();
        if (dlg.exec() == QDialog::Accepted) {
            return edit->text();
        }
        return {};
    }
} // namespace

PmpManager::PmpManager(QObject* parent)
    : QObject(parent)
{
}

PmpManager* PmpManager::instance()
{
    static PmpManager s_instance;
    return &s_instance;
}

Database* PmpManager::currentDatabase(DatabaseWidget** outWidget) const
{
    MainWindow* mw = getMainWindow();
    if (!mw) {
        return nullptr;
    }
    DatabaseTabWidget* tabs = mw->findChild<DatabaseTabWidget*>();
    if (!tabs) {
        return nullptr;
    }
    DatabaseWidget* w = tabs->currentDatabaseWidget();
    if (!w || !w->database()) {
        return nullptr;
    }
    if (outWidget) {
        *outWidget = w;
    }
    return w->database().data();
}

void PmpManager::install()
{
    if (m_installed) {
        return;
    }
    MainWindow* mw = getMainWindow();
    if (!mw || !mw->menuBar()) {
        return;
    }
    m_installed = true;

    ensureMenu();

    // PmVault: keep our menu alive even if Qt rebuilds/repopulates the menu bar
    // (root cause of the "LAN Sync" entry disappearing after a sync or tab change).
    mw->menuBar()->installEventFilter(this);
    if (auto* tabs = mw->findChild<DatabaseTabWidget*>()) {
        connect(tabs, &DatabaseTabWidget::databaseOpened, this, [this](DatabaseWidget*) { ensureMenu(); });
        connect(tabs, &DatabaseTabWidget::databaseUnlocked, this, [this](DatabaseWidget*) { ensureMenu(); });
    }

    // Register the global quick-access hotkey.
    PmpQuickAccess::instance()->install();

    // Tear down the global hotkey / native event filter while QApplication is
    // still alive (the singleton outlives QApplication; leaking the filter into
    // global destruction contributes to the Windows crash on exit).
    connect(qApp, &QCoreApplication::aboutToQuit, this, []() {
        PmpQuickAccess::instance()->shutdown();
    });

    // Record lock events centrally.
    connect(mw, &MainWindow::databaseLocked, this, [](DatabaseWidget*) {
        PmpAuditLog::instance()->record(PmpAuditLog::EvLock, PmpAuditLog::OcInfo, PmpAuditLog::FldNone,
                                        PmpAuditLog::TgtLocalDatabase);
    });
}

void PmpManager::ensureMenu()
{
    MainWindow* mw = getMainWindow();
    if (!mw || !mw->menuBar()) {
        return;
    }
    const QString kMenuObj = QStringLiteral("pmvault_menu");
    if (mw->menuBar()->findChild<QMenu*>(kMenuObj)) {
        return; // already present
    }
    auto* menu = mw->menuBar()->addMenu(QObject::tr("PmVault"));
    menu->setObjectName(kMenuObj);
    // PmVault: database management lives only in the recent-databases history
    // menu ("Manage databases…") to avoid duplicate entry points.
    menu->addAction(QObject::tr("启用第二因素（TOTP）…"), this, &PmpManager::enrollTwoFactor);
    menu->addAction(QObject::tr("移除第二因素…"), this, &PmpManager::removeTwoFactor);
    menu->addSeparator();
    // The password generator reuses the toolbar's checkable page-switch action
    // so menu and toolbar always drive the same stacked-widget page.
    if (auto* genAction = mw->findChild<QAction*>("actionPasswordGenerator")) {
        menu->addAction(genAction);
    }
    menu->addSeparator();
    menu->addAction(QObject::tr("查看审计日志…"), this, &PmpManager::showAuditLog);
    menu->addAction(QObject::tr("局域网同步…"), this, &PmpManager::showSync);
}

bool PmpManager::eventFilter(QObject* watched, QEvent* event)
{
    // When the menu bar loses a child (a menu being torn down/rebuilt), re-check on
    // the next event-loop iteration whether our PmVault menu is still there and
    // recreate it if not. Queued so we never mutate the widget tree mid-event.
    MainWindow* mw = getMainWindow();
    if (mw && watched == mw->menuBar() && event->type() == QEvent::ChildRemoved) {
        QTimer::singleShot(0, this, [this]() { ensureMenu(); });
    }
    return QObject::eventFilter(watched, event);
}

bool PmpManager::secondFactorGate(QWidget* parent, const QString& filePath)
{
    PmpTwoFactor* tf = PmpTwoFactor::instance();
    if (!tf->isEnrolled(filePath)) {
        return true;
    }

    PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactor, PmpAuditLog::OcInfo, PmpAuditLog::FldTotp,
                                    PmpAuditLog::TgtLocalDatabase);

    for (int attempt = 0; attempt < 6; ++attempt) {
        const QString code = promptCode(parent, QObject::tr("需要第二因素"));
        if (code.isEmpty()) {
            PmpAuditLog::instance()->record(PmpAuditLog::EvUnlock, PmpAuditLog::OcDenied, PmpAuditLog::FldNone,
                                            PmpAuditLog::TgtLocalDatabase);
            return false;
        }
        QString error;
        const PmpTwoFactor::VerifyResult r = tf->verifyInteractive(filePath, code, error);
        if (r == PmpTwoFactor::Ok) {
            return true;
        }
        if (r == PmpTwoFactor::Locked) {
            const qint64 secs = tf->lockedSecondsRemaining(filePath);
            QMessageBox::warning(
                parent, QObject::tr("第二因素已锁定"),
                QObject::tr("失败次数过多，请在 %1 秒后再试。").arg(secs));
            // Stay in the loop; verification keeps rejecting until the window passes.
            continue;
        }
        QMessageBox::warning(parent, QObject::tr("验证失败"),
                             error.isEmpty() ? QObject::tr("验证码不正确。") : error);
    }
    PmpAuditLog::instance()->record(PmpAuditLog::EvUnlock, PmpAuditLog::OcDenied, PmpAuditLog::FldNone,
                                    PmpAuditLog::TgtLocalDatabase);
    return false;
}

void PmpManager::bindAudit(const QString& filePath)
{
    auto* log = PmpAuditLog::instance();
    log->bindDatabase(filePath);
    log->setLimits(90, 10LL * 1024 * 1024);
    log->setVerboseEnabled(true);
}

void PmpManager::enrollTwoFactor()
{
    DatabaseWidget* w = nullptr;
    Database* db = currentDatabase(&w);
    if (!db) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("请先打开一个数据库。"));
        return;
    }
    const QString path = db->filePath();
    PmpTwoFactor* tf = PmpTwoFactor::instance();
    if (tf->isEnrolled(path)) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("本设备上已为该数据库启用第二因素。"));
        return;
    }

    const QString label = QFileInfo(path).fileName();
    const PmpTwoFactor::EnrollStart start = tf->beginEnroll(path, label);

    QDialog dlg;
    dlg.setWindowTitle(tr("启用第二因素（TOTP）"));
    auto* root = new QVBoxLayout(&dlg);
    root->addWidget(new QLabel(
        tr("1. 使用 Google 验证器（或任意 TOTP App）扫描二维码以添加 PmVault。\n"
           "PmVault 不会读取验证器 App 或其上显示的验证码，您只需在下方手动输入 "
           "6 位验证码进行确认。"),
        &dlg));

    const QrCode qr(start.otpauthUri);
    QByteArray svg;
    QBuffer buffer(&svg);
    buffer.open(QIODevice::WriteOnly);
    qr.writeSvg(&buffer, 96, 2);
    auto* svgWidget = new QSvgWidget(&dlg);
    svgWidget->load(svg);
    svgWidget->setFixedSize(220, 220);
    auto* qrRow = new QHBoxLayout();
    qrRow->addStretch(1);
    qrRow->addWidget(svgWidget);
    qrRow->addStretch(1);
    root->addLayout(qrRow);

    root->addWidget(new QLabel(tr("2. 输入当前的 6 位验证码以确认："), &dlg));
    auto* codeEdit = new QLineEdit(&dlg);
    setupCodeEdit(codeEdit, tr("6 位验证码"));
    root->addWidget(codeEdit);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    root->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) {
        return;
    }
    QString error;
    if (!isSixDigits(codeEdit->text()) || !tf->confirmEnroll(path, codeEdit->text(), error)) {
        QMessageBox::critical(nullptr, tr("启用失败"),
                              error.isEmpty() ? tr("确认验证码不匹配。") : error);
        return;
    }
    PmpConfig::setValue(db, PmpConfig::Key::TwoFactorEnabled, QStringLiteral("true"));
    db->markAsModified();
    if (w) {
        w->save();
    }
    QMessageBox::information(nullptr, tr("PmVault"),
                             tr("已在本设备启用第二因素。\n"
                                "种子仅保存在本设备的加密保险库中，不存入数据库。"));
}

void PmpManager::removeTwoFactor()
{
    Database* db = currentDatabase();
    if (!db) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("请先打开一个数据库。"));
        return;
    }
    const QString path = db->filePath();
    PmpTwoFactor* tf = PmpTwoFactor::instance();
    if (!tf->isEnrolled(path)) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("本设备上没有为该数据库启用第二因素。"));
        return;
    }
    const QString code = promptCode(nullptr, tr("移除第二因素"));
    if (code.isEmpty()) {
        return;
    }
    QString error;
    if (tf->verifyInteractive(path, code, error) != PmpTwoFactor::Ok) {
        QMessageBox::warning(nullptr, tr("PmVault"),
                             error.isEmpty() ? tr("验证失败。") : error);
        return;
    }
    tf->removeEnrollment(path);
    PmpConfig::setValue(db, PmpConfig::Key::TwoFactorEnabled, QStringLiteral("false"));
    PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactorUnenroll, PmpAuditLog::OcSuccess,
                                    PmpAuditLog::FldNone, PmpAuditLog::TgtLocalDatabase);
    db->markAsModified();
    QMessageBox::information(nullptr, tr("PmVault"), tr("已在本设备移除第二因素。"));
}

void PmpManager::showAuditLog()
{
    Database* db = currentDatabase();
    const QString path = db ? db->filePath() : QString();
    if (path.isEmpty()) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("请先打开一个数据库。"));
        return;
    }

    const PmpAuditLog::VerifyResult vr = PmpAuditLog::instance()->verify(path);
    const QVector<PmpAuditLog::Record> records = PmpAuditLog::instance()->readAll(path, 5000);

    QDialog dlg;
    dlg.setWindowTitle(tr("PmVault 审计日志"));
    dlg.resize(900, 560);
    auto* root = new QVBoxLayout(&dlg);

    const QString statusColor = (vr.chainOk && vr.anchorOk && !vr.truncated) ? QStringLiteral("#35705A")
                                                                            : QStringLiteral("#A14E50");
    auto* status = new QLabel(&dlg);
    status->setStyleSheet(QStringLiteral("color:%1; font-weight:bold;").arg(statusColor));
    status->setText(tr("完整性：链路=%1 锚点=%2 截断=%3  ·  可读记录 %4 条，末序号 %5\n%6")
                        .arg(vr.chainOk ? tr("正常") : tr("损坏"),
                             vr.anchorOk ? tr("正常") : tr("损坏"),
                             vr.truncated ? tr("是") : tr("否"))
                        .arg(vr.readableCount)
                        .arg(vr.lastSeq)
                        .arg(vr.message));
    root->addWidget(status);

    auto* table = new QTableWidget(static_cast<int>(records.size()), 6, &dlg);
    table->setHorizontalHeaderLabels({tr("时间（UTC）"), tr("事件"), tr("结果"), tr("字段"),
                                      tr("对象"), tr("详情（网络/TLS 诊断）")});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    int row = 0;
    for (auto it = records.crbegin(); it != records.crend(); ++it) {
        const auto& r = *it;
        const QString t = QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(r.ts)).toUTC().toString(Qt::ISODate);
        const QList<QString> cells = {
            t, PmpAuditLog::eventName(r.event), PmpAuditLog::outcomeName(r.outcome),
            PmpAuditLog::fieldName(r.field), PmpAuditLog::targetName(r.target),
            QString::fromUtf8(r.detail)};
        for (int c = 0; c < cells.size(); ++c) {
            table->setItem(row, c, new QTableWidgetItem(cells[c]));
        }
        ++row;
    }
    table->horizontalHeader()->setStretchLastSection(true);
    table->resizeColumnsToContents();
    root->addWidget(table);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    buttons->button(QDialogButtonBox::Close)->setText(tr("关闭"));
    root->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    dlg.exec();
}

void PmpManager::showSync()
{
    DatabaseWidget* w = nullptr;
    Database* db = currentDatabase(&w);
    if (!db) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("请先打开一个数据库。"));
        return;
    }

    // Validate the TLS stack and this device's identity BEFORE constructing the
    // dialog. Identity generation is exception-safe, but this also gives a clear
    // error instead of a crash if anything is unavailable.
    if (!QSslSocket::supportsSsl()) {
        QMessageBox::critical(nullptr, tr("PmVault 局域网同步（TLS 1.3）"),
                              tr("本构建未提供 TLS（OpenSSL），无法进行局域网同步。"));
        return;
    }
    const PmpIdentity identity = PmpIdentityStore::loadOrCreate();
    if (!identity.valid()) {
        QMessageBox::critical(nullptr, tr("PmVault 局域网同步（TLS 1.3）"),
                              tr("无法创建本机 TLS 身份，请检查安装后重试。"));
        return;
    }

    QDialog dlg;
    dlg.setWindowTitle(tr("PmVault 局域网同步（TLS 1.3）"));
    dlg.resize(600, 460);
    auto* root = new QVBoxLayout(&dlg);

    auto* mode = new QComboBox(&dlg);
    mode->addItem(tr("监听并等待对端连接（单次，60 秒）"));
    mode->addItem(tr("主动连接对端"));
    root->addWidget(mode);

    auto* form = new QFormLayout();
    auto* hostEdit = new QLineEdit(&dlg);
    hostEdit->setPlaceholderText(tr("对端局域网 IP，例如 192.168.1.20"));
    auto* portSpin = new QSpinBox(&dlg);
    portSpin->setRange(1024, 65535);
    portSpin->setValue(PmpConfig::getInt(db, PmpConfig::Key::SyncPort) > 0
                           ? PmpConfig::getInt(db, PmpConfig::Key::SyncPort)
                           : 19532);
    auto* policy = new QComboBox(&dlg);
    policy->addItem(tr("冲突时双方都保留（推荐）"));
    policy->addItem(tr("删除/编辑冲突时以删除为准"));
    form->addRow(tr("对端地址："), hostEdit);
    form->addRow(tr("端口："), portSpin);
    form->addRow(tr("冲突策略："), policy);
    root->addLayout(form);

    auto* nodeLabel = new QLabel(&dlg);
    nodeLabel->setText(tr("本机节点：%1").arg(identity.nodeId));
    nodeLabel->setWordWrap(true);
    root->addWidget(nodeLabel);

    // Show this PC's LAN IPv4 addresses up front so the user knows what to type on
    // the phone (and can spot a VPN/TUN virtual adapter hijacking the LAN).
    QStringList addrs;
    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& iface : interfaces) {
        if (!(iface.flags() & QNetworkInterface::IsUp) || !(iface.flags() & QNetworkInterface::IsRunning)
            || (iface.flags() & QNetworkInterface::IsLoopBack)) {
            continue;
        }
        for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
            const QHostAddress ip = entry.ip();
            if (ip.protocol() == QAbstractSocket::IPv4Protocol && !ip.isLoopback()) {
                addrs << QStringLiteral("%1 (%2)").arg(ip.toString(), iface.humanReadableName());
            }
        }
    }
    auto* ipLabel = new QLabel(&dlg);
    ipLabel->setWordWrap(true);
    ipLabel->setStyleSheet(QStringLiteral("color:#35537a;"));
    ipLabel->setText(addrs.isEmpty()
                         ? tr("未检测到活动的局域网 IPv4 地址，请先连接网络。")
                         : tr("本机局域网地址：%1").arg(addrs.join(", ")));
    root->addWidget(ipLabel);

    auto* hintLabel = new QLabel(&dlg);
    hintLabel->setWordWrap(true);
    hintLabel->setStyleSheet(QStringLiteral("color:#9A6A2F;"));
    hintLabel->setText(tr("提示：两端需在同一 Wi‑Fi/局域网；若连接失败，请关闭代理/VPN 的 TUN 或局域网"
                          "劫持，并在 Windows 防火墙允许本程序入站 TCP %1 端口。").arg(portSpin->value()));
    root->addWidget(hintLabel);

    auto* startBtn = new QPushButton(tr("开始"), &dlg);
    root->addWidget(startBtn);

    auto* log = new QPlainTextEdit(&dlg);
    log->setReadOnly(true);
    root->addWidget(log);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    buttons->button(QDialogButtonBox::Close)->setText(tr("关闭"));
    root->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    connect(mode, QOverload<int>::of(&QComboBox::currentIndexChanged), hostEdit, [mode, hostEdit]() {
        hostEdit->setEnabled(mode->currentIndex() == 1);
    });
    connect(portSpin, QOverload<int>::of(&QSpinBox::valueChanged), hintLabel, [hintLabel, portSpin]() {
        hintLabel->setText(QObject::tr("提示：两端需在同一 Wi‑Fi/局域网；若连接失败，请关闭代理/VPN 的 TUN 或局域网"
                                       "劫持，并在 Windows 防火墙允许本程序入站 TCP %1 端口。").arg(portSpin->value()));
    });
    hostEdit->setEnabled(false);

    connect(startBtn, &QPushButton::clicked, &dlg, [&]() {
        startBtn->setEnabled(false);
        log->appendPlainText(tr("正在启动…"));

        auto* sync = new PmpSyncEngine(&dlg);
        PmpSyncEngine::Options opt;
        opt.listen = (mode->currentIndex() == 0);
        opt.host = hostEdit->text().trimmed();
        opt.port = portSpin->value();
        opt.policy = policy->currentIndex() == 0 ? PmpSync::KeepBoth : PmpSync::DeleteWins;
        if (w) {
            opt.saveDatabase = [w]() { return w->save(); };
        }
        opt.confirmPeer = [&](const QString& fingerprint, const QString& peer) {
            const QString msg =
                tr("未知的对端证书。\n\n指纹（SHA-256）：\n%1\n\n是否在本数据库中信任该设备？")
                    .arg(fingerprint);
            Q_UNUSED(peer);
            auto* box = new QMessageBox(QMessageBox::Question, tr("是否信任对端？"), msg,
                                        QMessageBox::Yes | QMessageBox::No, &dlg);
            box->button(QMessageBox::Yes)->setText(tr("信任"));
            box->button(QMessageBox::No)->setText(tr("不信任"));
            const int chosen = box->exec();
            return chosen == QMessageBox::Yes;
        };

        connect(sync, &PmpSyncEngine::logMessage, log, &QPlainTextEdit::appendPlainText);
        connect(sync, &PmpSyncEngine::finished, &dlg, [&, startBtn](const PmpSyncEngine::Report& r) {
            startBtn->setEnabled(true);
            if (r.ok) {
                log->appendPlainText(tr("完成：%1（更新 %2，删除 %3，冲突副本 %4）")
                                         .arg(r.message)
                                         .arg(r.upserted)
                                         .arg(r.deleted)
                                         .arg(r.conflictCopies));
            } else {
                log->appendPlainText(tr("失败：%1").arg(r.message));
            }
            sender()->deleteLater();
        });

        sync->start(db, opt);
    });

    dlg.exec();
}

void PmpManager::hardenDatabase(Database* db)
{
    if (!db || !db->metadata()) {
        return;
    }
    Metadata* meta = db->metadata();
    bool changed = false;
    if (meta->recycleBinEnabled()) {
        meta->setRecycleBinEnabled(false);
        changed = true;
    }
    if (Group* bin = meta->recycleBin()) {
        // Permanently drop the recycle-bin group (and the entries inside it).
        // The QPointer held by Metadata is cleared when the Group is destroyed.
        delete bin;
        meta->setRecycleBin(nullptr);
        changed = true;
    }
    if (changed) {
        db->markAsModified();
    }
}

QVector<PmpManager::QuickEntry> PmpManager::quickEntries()
{
    QVector<QuickEntry> result;
    Database* db = instance()->currentDatabase();
    Group* root = db ? db->rootGroup() : nullptr;
    if (!root) {
        return result;
    }

    const QList<Entry*> entries = root->entriesRecursive(false);
    for (Entry* entry : entries) {
        if (!entry) {
            continue;
        }
        QuickEntry item;
        item.uuid = entry->uuid().toString(QUuid::WithoutBraces);
        item.title = entry->title();
        item.username = entry->username();
        if (item.title.isEmpty()) {
            item.title = QObject::tr("（未命名）");
        }
        result.append(item);
    }

    std::sort(result.begin(), result.end(),
              [](const QuickEntry& a, const QuickEntry& b) { return a.title.toLower() < b.title.toLower(); });
    return result;
}

void PmpManager::quickCopy(const QString& uuid, bool password)
{
    Database* db = instance()->currentDatabase();
    Group* root = db ? db->rootGroup() : nullptr;
    if (!root) {
        return;
    }
    Entry* entry = root->findEntryByUuid(QUuid::fromString(uuid));
    if (!entry) {
        return;
    }
    const QString value = password ? entry->password() : entry->username();
    if (value.isEmpty()) {
        return;
    }

    QApplication::clipboard()->setText(value);
    PmpAuditLog::instance()->record(PmpAuditLog::EvCopy, PmpAuditLog::OcSuccess,
                                    password ? PmpAuditLog::FldPassword : PmpAuditLog::FldUsername,
                                    PmpAuditLog::TgtLocalDatabase);

    int clearSeconds = PmpConfig::getInt(db, PmpConfig::Key::ClipboardClearSeconds);
    if (clearSeconds <= 0) {
        clearSeconds = 10;
    }
    const QString expected = value;
    QTimer::singleShot(clearSeconds * 1000, qApp, [expected]() {
        QClipboard* clipboard = QApplication::clipboard();
        // Only clear if the clipboard still holds our value, never wipe
        // something the user copied afterwards.
        if (clipboard && clipboard->text() == expected) {
            clipboard->clear();
        }
    });
}

void PmpManager::quickAutoType(const QString& uuid)
{
    Database* db = instance()->currentDatabase();
    Group* root = db ? db->rootGroup() : nullptr;
    if (!root) {
        return;
    }
    Entry* entry = root->findEntryByUuid(QUuid::fromString(uuid));
    if (!entry) {
        return;
    }
    PmpAuditLog::instance()->record(PmpAuditLog::EvAutoType, PmpAuditLog::OcInfo, PmpAuditLog::FldNone,
                                    PmpAuditLog::TgtDesktopWindow);
    AutoType::instance()->performAutoType(entry);
}

bool PmpManager::hasUnlockedDatabase()
{
    return instance()->currentDatabase() != nullptr;
}

void PmpManager::requestMainWindow()
{
    MainWindow* mw = getMainWindow();
    if (!mw) {
        return;
    }
    mw->showNormal();
    mw->raise();
    mw->activateWindow();
}

void PmpManager::openDatabaseSecurity()
{
    DatabaseWidget* widget = nullptr;
    if (!currentDatabase(&widget) || !widget) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("请先打开一个数据库。"));
        return;
    }
    widget->switchToDatabaseSecurity();
}

void PmpManager::quickAccessSettings()
{
    PmpQuickAccess::instance()->showSettings();
}

void PmpManager::onDatabaseCreated(DatabaseWidget* widget)
{
    if (!widget || !widget->database()) {
        return;
    }
    Database* db = widget->database().data();
    hardenDatabase(db);
    ensureMenu();

    const auto answer = QMessageBox::question(
        getMainWindow(), tr("PmVault"),
        tr("是否为该数据库启用第二因素（TOTP）？\n\n"
           "用 Google 验证器扫描二维码，之后每次解锁都需输入 6 位验证码。\n"
           "您也可以稍后在 PmVault 菜单中启用。"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
    if (answer != QMessageBox::Yes) {
        return;
    }

    // The 2FA vault is keyed by a hash of the database path, so the new database
    // must be saved to a stable location before enrollment.
    if (db->filePath().isEmpty() && !widget->saveAs()) {
        return;
    }
    if (db->filePath().isEmpty()) {
        return;
    }
    enrollTwoFactor();
}
