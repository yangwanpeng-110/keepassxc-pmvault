/*
 * PmVault extensions - Windows Hello quick unlock for MinGW/GCC builds.
 *
 * The upstream winhello/ implementation drives Windows Hello through C++/WinRT
 * and therefore only compiles under MSVC (it is guarded by Q_CC_MSVC). This
 * class provides the SAME behaviour on MinGW builds without any build-time
 * WinRT dependency:
 *
 *   - Availability check and the actual credential prompt are performed by the
 *     system Windows PowerShell (always present on Windows 10/11), which calls
 *     the WinRT UserConsentVerifier API. That API shows the operating system's
 *     own PIN / fingerprint / face dialog; PmVault never sees the PIN.
 *   - The serialized CompositeKey (the same blob upstream Quick Unlock stores)
 *     is kept in a per-device file sealed with AES-256-GCM under a DPAPI-bound
 *     key (PmpPlatform::deriveKey). It is only unsealed AFTER the user passes
 *     the interactive Windows Hello challenge.
 *
 * The public method names/signatures mirror WindowsHello so the open-database
 * widget can use either through a single macro.
 */

#ifndef PMP_HELLO_H
#define PMP_HELLO_H

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QString>

class PmpHello : public QObject
{
    Q_OBJECT

public:
    static PmpHello* instance();

    bool isAvailable() const;
    QString errorString() const;
    void reset();

    bool storeKey(const QString& dbPath, const QByteArray& key);
    bool getKey(const QString& dbPath, QByteArray& key);
    bool hasKey(const QString& dbPath) const;
    void reset(const QString& dbPath);

private:
    PmpHello(QObject* parent = nullptr);
    Q_DISABLE_COPY(PmpHello)

    bool probeAvailability() const;
    static bool requestVerification();
    static int runEncoded(const QString& encodedScript, int timeoutMs);
    QString blobPath(const QString& dbPath) const;

    // -1 = not probed yet, 0 = unavailable, 1 = available
    mutable int m_available = -1;
    mutable QString m_error;
};

// Compatibility shim matching the upstream getWindowsHello() accessor name.
inline PmpHello* getPmpHello()
{
    return PmpHello::instance();
}

#endif // PMP_HELLO_H
