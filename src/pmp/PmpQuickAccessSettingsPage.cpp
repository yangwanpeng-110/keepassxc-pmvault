/*
 * PmVault extensions - quick-access hotkey settings page implementation.
 */

#include "PmpQuickAccessSettingsPage.h"

#include "PmpQuickAccess.h"
#include "gui/Icons.h"

#include <QCheckBox>
#include <QKeySequence>
#include <QKeySequenceEdit>
#include <QLabel>
#include <QSettings>
#include <QVBoxLayout>

namespace
{
    const char* kOrg = "PmVault";
    const char* kApp = "PmVault";
    const char* kEnabledKey = "quickaccess/enabled";
    const char* kHotkeyKey = "quickaccess/hotkey";
    const char* kDefaultHotkey = "Ctrl+Alt+P";
}

QString PmpQuickAccessSettingsPage::name()
{
    return QObject::tr("Quick Access Hotkey");
}

QIcon PmpQuickAccessSettingsPage::icon()
{
    return icons()->icon(QStringLiteral("auto-type"));
}

QWidget* PmpQuickAccessSettingsPage::createWidget()
{
    auto* widget = new QWidget();
    widget->setObjectName(QStringLiteral("pmpQuickAccessSettingsPage"));

    auto* layout = new QVBoxLayout(widget);
    layout->setContentsMargins(0, 0, 0, 0);

    auto* enableBox = new QCheckBox(QObject::tr("Enable the global hotkey"), widget);
    enableBox->setObjectName(QStringLiteral("pmpHotkeyEnabled"));

    auto* sequenceEdit = new QKeySequenceEdit(widget);
    sequenceEdit->setObjectName(QStringLiteral("pmpHotkeySequence"));

    auto* hint = new QLabel(
        QObject::tr("The hotkey opens a small panel to copy credentials or run Auto-Type from anywhere. "
                    "When the database is locked, it raises the unlock screen."),
        widget);
    hint->setWordWrap(true);

    layout->addWidget(enableBox);
    layout->addWidget(sequenceEdit);
    layout->addWidget(hint);
    layout->addStretch();

    return widget;
}

void PmpQuickAccessSettingsPage::loadSettings(QWidget* widget)
{
    auto* enableBox = widget->findChild<QCheckBox*>(QStringLiteral("pmpHotkeyEnabled"));
    auto* sequenceEdit = widget->findChild<QKeySequenceEdit*>(QStringLiteral("pmpHotkeySequence"));
    if (!enableBox || !sequenceEdit) {
        return;
    }

    QSettings settings(QString::fromLatin1(kOrg), QString::fromLatin1(kApp));
    const bool enabled = settings.value(QString::fromLatin1(kEnabledKey), true).toBool();
    QString hotkey = settings.value(QString::fromLatin1(kHotkeyKey), QString::fromLatin1(kDefaultHotkey)).toString();

    QKeySequence sequence(hotkey);
    if (sequence.isEmpty()) {
        sequence = QKeySequence(QString::fromLatin1(kDefaultHotkey));
    }

    enableBox->setChecked(enabled);
    sequenceEdit->setKeySequence(sequence);
}

void PmpQuickAccessSettingsPage::saveSettings(QWidget* widget)
{
    auto* enableBox = widget->findChild<QCheckBox*>(QStringLiteral("pmpHotkeyEnabled"));
    auto* sequenceEdit = widget->findChild<QKeySequenceEdit*>(QStringLiteral("pmpHotkeySequence"));
    if (!enableBox || !sequenceEdit) {
        return;
    }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    QKeySequence sequence = sequenceEdit->key();
#else
    QKeySequence sequence = sequenceEdit->keySequence();
#endif

    QSettings settings(QString::fromLatin1(kOrg), QString::fromLatin1(kApp));
    settings.setValue(QString::fromLatin1(kEnabledKey), enableBox->isChecked());
    settings.setValue(QString::fromLatin1(kHotkeyKey),
                      sequence.isEmpty() ? QString::fromLatin1(kDefaultHotkey) : sequence.toString());

    // Re-register the global shortcut immediately with the new configuration.
    PmpQuickAccess::instance()->reload();
}
