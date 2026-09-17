/*
 * PmVault extensions - GUI wiring and lifecycle manager implementation.
 */

#include "PmpManager.h"

#include "PmpAuditLog.h"
#include "PmpConfig.h"
#include "PmpIdentity.h"
#include "PmpSync.h"
#include "PmpTwoFactor.h"

#include "core/Database.h"
#include "gui/DatabaseTabWidget.h"
#include "gui/DatabaseWidget.h"
#include "gui/MainWindow.h"
#include "qrcode/QrCode.h"

#include <algorithm>

#include <QBuffer>
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

    // Prompt for a 6-digit TOTP code. Returns the code or an empty string if canceled.
    QString promptCode(QWidget* parent, const QString& title)
    {
        QDialog dlg(parent);
        dlg.setWindowTitle(title);
        auto* form = new QVBoxLayout(&dlg);
        auto* edit = new QLineEdit(&dlg);
        edit->setPlaceholderText(QObject::tr("6-digit code"));
        edit->setMaxLength(6);
        edit->setEchoMode(QLineEdit::Password);
        edit->setInputMask("999999");
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
    menu->addAction(QObject::tr("View Audit Log…"), this, &PmpManager::showAuditLog);
    menu->addAction(QObject::tr("LAN Sync…"), this, &PmpManager::showSync);

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
        tr("1. Add this secret to Google Authenticator (or any TOTP app).\n"
           "You can scan the QR code or type the key manually. PmVault never reads the app."),
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

    auto* secretEdit = new QLineEdit(start.secretB32, &dlg);
    secretEdit->setReadOnly(true);
    auto* secretForm = new QFormLayout();
    secretForm->addRow(tr("Setup key (Base32):"), secretEdit);
    root->addLayout(secretForm);

    root->addWidget(new QLabel(tr("2. Enter the current 6-digit code to confirm:"), &dlg));
    auto* codeEdit = new QLineEdit(&dlg);
    codeEdit->setInputMask("999999");
    codeEdit->setMaxLength(6);
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
    const PmpIdentity id = PmpIdentityStore::loadOrCreate();
    nodeLabel->setText(tr("This device node: %1").arg(id.nodeId));
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
