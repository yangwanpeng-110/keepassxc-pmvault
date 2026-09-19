/*
 * PmVault extensions - global hotkey and quick-access panel implementation.
 * See PmpQuickAccess.h for the behaviour contract.
 */

#include "PmpQuickAccess.h"

#include "PmpManager.h"

#include <QApplication>
#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QKeySequenceEdit>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QPoint>
#include <QPushButton>
#include <QScreen>
#include <QSettings>
#include <QTimer>
#include <QVBoxLayout>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifndef MOD_NOREPEAT
#define MOD_NOREPEAT 0x4000
#endif
#endif

PmpQuickAccess* PmpQuickAccess::instance()
{
    static PmpQuickAccess s_inst;
    return &s_inst;
}

void PmpQuickAccess::install()
{
    if (m_installed) {
        return;
    }
    m_installed = true;
    qApp->installNativeEventFilter(this);
    loadSettings();
    registerHotkey();
}

void PmpQuickAccess::loadSettings()
{
    QSettings settings(QStringLiteral("PmVault"), QStringLiteral("PmVault"));
    m_enabled = settings.value(QStringLiteral("quickaccess/enabled"), true).toBool();
    const QString hotkey = settings.value(QStringLiteral("quickaccess/hotkey"), QStringLiteral("Ctrl+Alt+P")).toString();
    m_sequence = QKeySequence(hotkey);
    if (m_sequence.isEmpty()) {
        m_sequence = QKeySequence(QStringLiteral("Ctrl+Alt+P"));
    }
}

void PmpQuickAccess::registerHotkey()
{
#ifdef Q_OS_WIN
    unregisterHotkey();
    if (!m_enabled || m_sequence.isEmpty()) {
        return;
    }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    const int combo = m_sequence[0].toCombined();
#else
    const int combo = m_sequence[0];
#endif
    if (combo == 0) {
        return;
    }

    UINT mods = MOD_NOREPEAT;
    if (combo & Qt::CTRL) {
        mods |= MOD_CONTROL;
    }
    if (combo & Qt::ALT) {
        mods |= MOD_ALT;
    }
    if (combo & Qt::SHIFT) {
        mods |= MOD_SHIFT;
    }

    const int base = combo & ~Qt::KeyboardModifierMask;
    UINT vk = 0;
    if (base >= Qt::Key_A && base <= Qt::Key_Z) {
        vk = static_cast<UINT>('A' + (base - Qt::Key_A));
    } else if (base >= Qt::Key_0 && base <= Qt::Key_9) {
        vk = static_cast<UINT>('0' + (base - Qt::Key_0));
    } else if (base >= Qt::Key_F1 && base <= Qt::Key_F12) {
        vk = VK_F1 + static_cast<UINT>(base - Qt::Key_F1);
    }
    if (vk == 0) {
        return;
    }

    if (!RegisterHotKey(nullptr, static_cast<int>(m_hotId), mods, vk)) {
        qWarning("PmVault: failed to register global hotkey (error %lu)", GetLastError());
    }
#endif
}

void PmpQuickAccess::unregisterHotkey()
{
#ifdef Q_OS_WIN
    UnregisterHotKey(nullptr, static_cast<int>(m_hotId));
#endif
}

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
bool PmpQuickAccess::nativeEventFilter(const QByteArray& eventType, void* message, qintptr*)
#else
bool PmpQuickAccess::nativeEventFilter(const QByteArray& eventType, void* message, long*)
#endif
{
#ifdef Q_OS_WIN
    if (eventType == QByteArrayLiteral("windows_generic_MSG")) {
        MSG* msg = static_cast<MSG*>(message);
        if (msg && msg->message == WM_HOTKEY && static_cast<int>(msg->wParam) == m_hotId) {
            QMetaObject::invokeMethod(this, "showPanel", Qt::QueuedConnection);
        }
    }
#else
    (void)eventType;
    (void)message;
#endif
    return false;
}

void PmpQuickAccess::showPanel()
{
    if (!PmpManager::hasUnlockedDatabase()) {
        // Bring the main window (and its unlock screen) to the front.
        PmpManager::requestMainWindow();
        return;
    }

    QDialog dlg;
    dlg.setWindowTitle(tr("PmVault Quick Access"));
    dlg.setWindowFlags(Qt::Dialog | Qt::WindowStaysOnTopHint | Qt::Tool);

    auto* layout = new QVBoxLayout(&dlg);
    auto* filter = new QLineEdit(&dlg);
    filter->setPlaceholderText(tr("Search title or username"));
    filter->setClearButtonEnabled(true);
    auto* list = new QListWidget(&dlg);

    const auto entries = PmpManager::quickEntries();
    for (const PmpManager::QuickEntry& entry : entries) {
        QString label = entry.title;
        if (!entry.username.isEmpty()) {
            label += QStringLiteral(" \u2014 ") + entry.username;
        }
        auto* item = new QListWidgetItem(label, list);
        item->setData(Qt::UserRole, entry.uuid);
    }
    if (list->count() > 0) {
        list->setCurrentRow(0);
    }

    auto* buttons = new QHBoxLayout();
    auto* copyUserBtn = new QPushButton(tr("Copy Username"), &dlg);
    auto* copyPassBtn = new QPushButton(tr("Copy Password"), &dlg);
    auto* autoTypeBtn = new QPushButton(tr("Auto-Type"), &dlg);
    auto* closeBtn = new QPushButton(tr("Close"), &dlg);
    buttons->addWidget(copyUserBtn);
    buttons->addWidget(copyPassBtn);
    buttons->addWidget(autoTypeBtn);
    buttons->addStretch();
    buttons->addWidget(closeBtn);

    layout->addWidget(filter);
    layout->addWidget(list);
    layout->addLayout(buttons);

    bool doAutoType = false;
    QString targetUuid;

    auto selectedUuid = [list]() -> QString {
        QListWidgetItem* item = list->currentItem();
        return (item && !item->isHidden()) ? item->data(Qt::UserRole).toString() : QString();
    };

    const bool hasEntries = list->count() > 0;
    copyUserBtn->setEnabled(hasEntries);
    copyPassBtn->setEnabled(hasEntries);
    autoTypeBtn->setEnabled(hasEntries);

    QObject::connect(filter, &QLineEdit::textChanged, &dlg,
                     [list, copyUserBtn, copyPassBtn, autoTypeBtn](const QString& text) {
                         const QString needle = text.trimmed().toLower();
                         QListWidgetItem* first = nullptr;
                         for (int i = 0; i < list->count(); ++i) {
                             QListWidgetItem* item = list->item(i);
                             const bool match = needle.isEmpty() || item->text().toLower().contains(needle);
                             item->setHidden(!match);
                             if (match && !first) {
                                 first = item;
                             }
                         }
                         list->setCurrentItem(first);
                         const bool on = first != nullptr;
                         copyUserBtn->setEnabled(on);
                         copyPassBtn->setEnabled(on);
                         autoTypeBtn->setEnabled(on);
                     });
    QObject::connect(filter, &QLineEdit::returnPressed, &dlg, [&]() {
        // Enter in the search box runs Auto-Type on the selected entry.
        const QString uuid = selectedUuid();
        if (!uuid.isEmpty()) {
            targetUuid = uuid;
            doAutoType = true;
            dlg.accept();
        }
    });

    QObject::connect(list, &QListWidget::itemDoubleClicked, &dlg, [&](QListWidgetItem*) {
        targetUuid = selectedUuid();
        doAutoType = true;
        dlg.accept();
    });
    QObject::connect(list, &QListWidget::currentItemChanged, &dlg,
                     [&](QListWidgetItem* cur, QListWidgetItem*) {
                         const bool on = cur != nullptr && !cur->isHidden();
                         copyUserBtn->setEnabled(on);
                         copyPassBtn->setEnabled(on);
                         autoTypeBtn->setEnabled(on);
                     });
    QObject::connect(copyUserBtn, &QPushButton::clicked, &dlg, [&]() {
        const QString uuid = selectedUuid();
        if (!uuid.isEmpty()) {
            PmpManager::quickCopy(uuid, false);
            dlg.accept();
        }
    });
    QObject::connect(copyPassBtn, &QPushButton::clicked, &dlg, [&]() {
        const QString uuid = selectedUuid();
        if (!uuid.isEmpty()) {
            PmpManager::quickCopy(uuid, true);
            dlg.accept();
        }
    });
    QObject::connect(autoTypeBtn, &QPushButton::clicked, &dlg, [&]() {
        targetUuid = selectedUuid();
        doAutoType = true;
        dlg.accept();
    });
    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::reject);

    filter->setFocus();
    dlg.resize(460, 480);
    if (QScreen* screen = QGuiApplication::primaryScreen()) {
        const QRect available = screen->availableGeometry();
        dlg.move(available.center() - QPoint(dlg.width() / 2, dlg.height() / 2));
    }

    dlg.exec();

    if (doAutoType && !targetUuid.isEmpty()) {
        const QString uuid = targetUuid;
        // Let the previously focused window return to the foreground before
        // synthesising keystrokes into it.
        QTimer::singleShot(180, qApp, [uuid]() { PmpManager::quickAutoType(uuid); });
    }
}

void PmpQuickAccess::showSettings()
{
    QDialog dlg;
    dlg.setWindowTitle(tr("Quick Access Hotkey"));
    auto* layout = new QVBoxLayout(&dlg);

    auto* enable = new QCheckBox(tr("Enable the global hotkey"), &dlg);
    enable->setChecked(m_enabled);

    auto* editor = new QKeySequenceEdit(m_sequence, &dlg);

    auto* hint = new QLabel(
        tr("The hotkey opens a small panel to copy credentials or run Auto-Type from anywhere. "
           "When the database is locked, it raises the unlock screen."),
        &dlg);
    hint->setWordWrap(true);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, [&]() {
        m_enabled = enable->isChecked();
        m_sequence = editor->key();
        QSettings settings(QStringLiteral("PmVault"), QStringLiteral("PmVault"));
        settings.setValue(QStringLiteral("quickaccess/enabled"), m_enabled);
        settings.setValue(QStringLiteral("quickaccess/hotkey"), m_sequence.toString());
        registerHotkey();
        dlg.accept();
    });
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    layout->addWidget(enable);
    layout->addWidget(editor);
    layout->addWidget(hint);
    layout->addWidget(buttons);
    dlg.resize(420, 180);
    dlg.exec();
}
