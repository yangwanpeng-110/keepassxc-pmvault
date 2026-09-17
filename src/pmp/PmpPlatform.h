/*
 * PmVault extensions - platform abstraction for the on-device vault.
 *
 * The device key is a stable, per-installation 32-byte secret used to protect
 * the local TOTP seed vault and the audit log. It never leaves the device and
 * is never written into the KDBX database.
 *
 *   Windows : the on-disk blob is protected with DPAPI (CryptProtectData), so it
 *             is bound to the current Windows user.
 *   Other   : a 0600 random key file under the per-user data directory. This is
 *             a portable fallback; it relies on filesystem permissions rather
 *             than an OS-bound secret store.
 */

#ifndef PMP_PLATFORM_H
#define PMP_PLATFORM_H

#include <QByteArray>
#include <QString>

class PmpPlatform
{
public:
    // Per-user, off-database application data directory (created on demand).
    //   Windows: %APPDATA%/PmVault
    //   Other  : ~/.local/share/PmVault
    static QString appDataDir();
    static QString ensureSubDir(const QString& name);

    // Stable 32-byte device master key.
    static QByteArray deviceKey();

    // Domain-separated key derived from the device key (HKDF-SHA256).
    static QByteArray deriveKey(const QByteArray& domain, int len = 32);

    // Stable non-reversible identifier for a database file path (hex).
    static QString dbId(const QString& databaseFilePath);

    static constexpr int KeySize = 32;
};

#endif // PMP_PLATFORM_H
