/*
 * PmVault extensions - global hotkey and quick-access panel.
 *
 * A single configurable global shortcut (default Ctrl+Alt+P) works even when
 * the application is not focused:
 *
 *   - Database locked / not open: raise the main window to the unlock screen.
 *   - Database unlocked: show a small always-on-top panel listing entries,
 *     with one-click copy of the username / password or direct Auto-Type into
 *     the previously focused window.
 *
 * The hotkey is a device-local UI preference (it must work before any database
 * is unlocked, so it cannot live in KDBX CustomData); it is stored in a local
 * QSettings store and never uploaded. On Windows it uses RegisterHotKey.
 */

#ifndef PMP_QUICKACCESS_H
#define PMP_QUICKACCESS_H

#include <QAbstractNativeEventFilter>
#include <QKeySequence>
#include <QObject>

class PmpQuickAccess : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

public:
    static PmpQuickAccess* instance();

    // Register the global hotkey and wire the manager. Safe to call once.
    void install();

    // Re-read the device-local QSettings and re-register the hotkey.
    // Called by the application settings page after the user edits the shortcut.
    void reload();

    // Tear down the native event filter and global hotkey on application quit.
    void shutdown();

    // QAbstractNativeEventFilter
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;
#else
    bool nativeEventFilter(const QByteArray& eventType, void* message, long* result) override;
#endif

public slots:
    void showPanel();
    void showSettings();

private:
    PmpQuickAccess() = default;
    void loadSettings();
    void registerHotkey();
    void unregisterHotkey();

    bool m_installed = false;
    bool m_enabled = true;
    int m_hotId = 0x504D; // 'PM'
    QKeySequence m_sequence;
};

#endif // PMP_QUICKACCESS_H
