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
        setupCodeEdit(edit, QObject::tr("6-digit code"));
        form->addWidget(new QLabel(QObject::tr("Enter the current code from your authenticator app:"), &dlg));
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

    auto* menu = mw->menuBar()->addMenu(QObject::tr("PmVault"));
    menu->addAction(QObject::tr("Enable Second Factor (TOTP)…"), this, &PmpManager::enrollTwoFactor);
    menu->addAction(QObject::tr("Remove Second Factor…"), this, &PmpManager::removeTwoFactor);
    menu->addSeparator();
    menu->addAction(QObject::tr("Database Security / Key File…"), this, &PmpManager::openDatabaseSecurity);
    menu->addAction(QObject::tr("Quick Access Hotkey Settings…"), this, &PmpManager::quickAccessSettings);
    menu->addSeparator();
    menu->addAction(QObject::tr("View Audit Log…"), this, &PmpManager::showAuditLog);
    menu->addAction(QObject::tr("LAN Sync…"), this, &PmpManager::showSync);

    // Register the global quick-access hotkey.
    PmpQuickAccess::instance()->install();

    // Record lock events centrally.
    connect(mw, &MainWindow::databaseLocked, this, [](DatabaseWidget*) {
        PmpAuditLog::instance()->record(PmpAuditLog::EvLock, PmpAuditLog::OcInfo, PmpAuditLog::FldNone,
                                        PmpAuditLog::TgtLocalDatabase);
    });
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
        const QString code = promptCode(parent, QObject::tr("Second Factor Required"));
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
                parent, QObject::tr("Second Factor Locked"),
                QObject::tr("Too many failed attempts. Try again in %1 seconds.").arg(secs));
            // Stay in the loop; verification keeps rejecting until the window passes.
            continue;
        }
        QMessageBox::warning(parent, QObject::tr("Verification Failed"),
                             error.isEmpty() ? QObject::tr("The code was incorrect.") : error);
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
        QMessageBox::information(nullptr, tr("PmVault"), tr("Open a database first."));
        return;
    }
    const QString path = db->filePath();
    PmpTwoFactor* tf = PmpTwoFactor::instance();
    if (tf->isEnrolled(path)) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("A second factor is already enrolled for this database on this device."));
        return;
    }

    const QString label = QFileInfo(path).fileName();
    const PmpTwoFactor::EnrollStart start = tf->beginEnroll(path, label);

    QDialog dlg;
    dlg.setWindowTitle(tr("Enable Second Factor (TOTP)"));
    auto* root = new QVBoxLayout(&dlg);
    root->addWidget(new QLabel(
        tr("1. Scan the QR code with Google Authenticator (or any TOTP app) to add PmVault.\n"
           "PmVault never reads the authenticator app or the code shown on it; you only type the "
           "6-digit code below to confirm."),
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

    root->addWidget(new QLabel(tr("2. Enter the current 6-digit code to confirm:"), &dlg));
    auto* codeEdit = new QLineEdit(&dlg);
    setupCodeEdit(codeEdit, tr("6-digit code"));
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
        QMessageBox::critical(nullptr, tr("Enrollment Failed"),
                              error.isEmpty() ? tr("The confirmation code did not match.") : error);
        return;
    }
    PmpConfig::setValue(db, PmpConfig::Key::TwoFactorEnabled, QStringLiteral("true"));
    db->markAsModified();
    if (w) {
        w->save();
    }
    QMessageBox::information(nullptr, tr("PmVault"),
                             tr("Second factor enabled on this device.\n"
                                "The seed is stored only in this device's encrypted vault, not in the database."));
}

void PmpManager::removeTwoFactor()
{
    Database* db = currentDatabase();
    if (!db) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("Open a database first."));
        return;
    }
    const QString path = db->filePath();
    PmpTwoFactor* tf = PmpTwoFactor::instance();
    if (!tf->isEnrolled(path)) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("No second factor is enrolled on this device."));
        return;
    }
    const QString code = promptCode(nullptr, tr("Remove Second Factor"));
    if (code.isEmpty()) {
        return;
    }
    QString error;
    if (tf->verifyInteractive(path, code, error) != PmpTwoFactor::Ok) {
        QMessageBox::warning(nullptr, tr("PmVault"),
                             error.isEmpty() ? tr("Verification failed.") : error);
        return;
    }
    tf->removeEnrollment(path);
    PmpConfig::setValue(db, PmpConfig::Key::TwoFactorEnabled, QStringLiteral("false"));
    PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactorUnenroll, PmpAuditLog::OcSuccess,
                                    PmpAuditLog::FldNone, PmpAuditLog::TgtLocalDatabase);
    db->markAsModified();
    QMessageBox::information(nullptr, tr("PmVault"), tr("Second factor removed on this device."));
}

void PmpManager::showAuditLog()
{
    Database* db = currentDatabase();
    const QString path = db ? db->filePath() : QString();
    if (path.isEmpty()) {
        QMessageBox::information(nullptr, tr("PmVault"), tr("Open a database first."));
        return;
    }

    const PmpAuditLog::VerifyResult vr = PmpAuditLog::instance()->verify(path);
    const QVector<PmpAuditLog::Record> records = PmpAuditLog::instance()->readAll(path, 5000);

    QDialog dlg;
    dlg.setWindowTitle(tr("PmVault Audit Log"));
    dlg.resize(720, 520);
    auto* root = new QVBoxLayout(&dlg);

    const QString statusColor = (vr.chainOk && vr.anchorOk && !vr.truncated) ? QStringLiteral("#35705A")
                                                                            : QStringLiteral("#A14E50");
    auto* status = new QLabel(&dlg);
    status->setStyleSheet(QStringLiteral("color:%1; font-weight:bold;").arg(statusColor));
    status->setText(tr("Integrity: chain=%1 anchor=%2 truncated=%3  ·  %4 readable records, last seq %5\n%6")
                        .arg(vr.chainOk ? tr("OK") : tr("BROKEN"),
                             vr.anchorOk ? tr("OK") : tr("BROKEN"),
                             vr.truncated ? tr("YES") : tr("no"))
                        .arg(vr.readableCount)
                        .arg(vr.lastSeq)
                        .arg(vr.message));
    root->addWidget(status);

    auto* table = new QTableWidget(static_cast<int>(records.size()), 5, &dlg);
    table->setHorizontalHeaderLabels({tr("Time (UTC)"), tr("Event"), tr("Outcome"), tr("Field"), tr("Target")});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    int row = 0;
    for (auto it = records.crbegin(); it != records.crend(); ++it) {
        const auto& r = *it;
        const QString t = QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(r.ts)).toUTC().toString(Qt::ISODate);
        const QList<QString> cells = {
            t, PmpAuditLog::eventName(r.event), PmpAuditLog::outcomeName(r.outcome),
            PmpAuditLog::fieldName(r.field), PmpAuditLog::targetName(r.target)};
        for (int c = 0; c < cells.size(); ++c) {
            table->setItem(row, c, new QTableWidgetItem(cells[c]));
        }
        ++row;
    }
    table->horizontalHeader()->setStretchLastSection(true);
    table->resizeColumnsToContents();
    root->addWidget(table);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
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
        QMessageBox::information(nullptr, tr("PmVault"), tr("Open a database first."));
        return;
    }

    // Validate the TLS stack and this device's identity BEFORE constructing the
    // dialog. Identity generation is exception-safe, but this also gives a clear
    // error instead of a crash if anything is unavailable.
    if (!QSslSocket::supportsSsl()) {
        QMessageBox::critical(nullptr, tr("PmVault LAN Sync (TLS 1.3)"),
                              tr("TLS (OpenSSL) is not available in this build, so LAN sync cannot run."));
        return;
    }
    const PmpIdentity identity = PmpIdentityStore::loadOrCreate();
    if (!identity.valid()) {
        QMessageBox::critical(nullptr, tr("PmVault LAN Sync (TLS 1.3)"),
                              tr("This device's TLS identity could not be created. Check the installation and retry."));
        return;
    }

    QDialog dlg;
    dlg.setWindowTitle(tr("PmVault LAN Sync (TLS 1.3)"));
    dlg.resize(560, 420);
    auto* root = new QVBoxLayout(&dlg);

    auto* mode = new QComboBox(&dlg);
    mode->addItem(tr("Listen for an incoming peer (single, 30 s)"));
    mode->addItem(tr("Connect to a peer"));
    root->addWidget(mode);

    auto* form = new QFormLayout();
    auto* hostEdit = new QLineEdit(QStringLiteral("192.168.1."), &dlg);
    hostEdit->setPlaceholderText(tr("peer LAN IP, e.g. 192.168.1.20"));
    auto* portSpin = new QSpinBox(&dlg);
    portSpin->setRange(1024, 65535);
    portSpin->setValue(PmpConfig::getInt(db, PmpConfig::Key::SyncPort) > 0
                           ? PmpConfig::getInt(db, PmpConfig::Key::SyncPort)
                           : 19532);
    auto* policy = new QComboBox(&dlg);
    policy->addItem(tr("Keep both on conflict (recommended)"));
    policy->addItem(tr("Delete wins on delete/edit conflict"));
    form->addRow(tr("Peer host:"), hostEdit);
    form->addRow(tr("Port:"), portSpin);
    form->addRow(tr("Conflict policy:"), policy);
    root->addLayout(form);

    auto* nodeLabel = new QLabel(&dlg);
    nodeLabel->setText(tr("This device node: %1").arg(identity.nodeId));
    nodeLabel->setWordWrap(true);
    root->addWidget(nodeLabel);

    auto* startBtn = new QPushButton(tr("Start"), &dlg);
    root->addWidget(startBtn);

    auto* log = new QPlainTextEdit(&dlg);
    log->setReadOnly(true);
    root->addWidget(log);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    root->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    connect(mode, QOverload<int>::of(&QComboBox::currentIndexChanged), hostEdit, [mode, hostEdit]() {
        hostEdit->setEnabled(mode->currentIndex() == 1);
    });
    hostEdit->setEnabled(false);

    connect(startBtn, &QPushButton::clicked, &dlg, [&]() {
        startBtn->setEnabled(false);
        log->appendPlainText(tr("Starting…"));

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
                tr("Unknown peer certificate.\n\nFingerprint (SHA-256):\n%1\n\nTrust this device for this database?")
                    .arg(fingerprint);
            Q_UNUSED(peer);
            return QMessageBox::question(&dlg, tr("Trust Peer?"), msg, QMessageBox::Yes | QMessageBox::No)
                   == QMessageBox::Yes;
        };

        connect(sync, &PmpSyncEngine::logMessage, log, &QPlainTextEdit::appendPlainText);
        connect(sync, &PmpSyncEngine::finished, &dlg, [&, startBtn](const PmpSyncEngine::Report& r) {
            startBtn->setEnabled(true);
            if (r.ok) {
                log->appendPlainText(tr("DONE: %1  (updated %2, deleted %3, conflict copies %4)")
                                         .arg(r.message)
                                         .arg(r.upserted)
                                         .arg(r.deleted)
                                         .arg(r.conflictCopies));
            } else {
                log->appendPlainText(tr("FAILED: %1").arg(r.message));
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
            item.title = QObject::tr("(untitled)");
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
        QMessageBox::information(nullptr, tr("PmVault"), tr("Open a database first."));
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

    const auto answer = QMessageBox::question(
        getMainWindow(), tr("PmVault"),
        tr("Protect this database with a second factor (TOTP)?\n\n"
           "Scan a QR code with Google Authenticator and enter a 6-digit code on every unlock.\n"
           "You can also enable this later from the PmVault menu."),
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
