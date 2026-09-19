/*
 * PmVault extensions - application settings page for the global quick-access
 * hotkey. Lives in the standard application settings dialog (View -> Settings)
 * instead of a separate PmVault menu entry.
 *
 * The hotkey is a device-local UI preference (it has to work before a database
 * is unlocked), so it is stored in a local QSettings store, never in a KDBX.
 */

#ifndef PMP_QUICKACCESS_SETTINGSPAGE_H
#define PMP_QUICKACCESS_SETTINGSPAGE_H

#include "gui/ApplicationSettingsWidget.h"

class PmpQuickAccessSettingsPage : public ISettingsPage
{
public:
    PmpQuickAccessSettingsPage() = default;

    QString name() override;
    QIcon icon() override;
    QWidget* createWidget() override;
    void loadSettings(QWidget* widget) override;
    void saveSettings(QWidget* widget) override;
};

#endif // PMP_QUICKACCESS_SETTINGSPAGE_H
