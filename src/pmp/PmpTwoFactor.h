/*
 * PmVault extensions - TOTP second-factor unlock gate.
 *
 * After the master password successfully decrypts the database, the user may
 * additionally be required to enter a 6-digit TOTP code. This is a manual code
 * entry compatible with Google Authenticator-style apps; the seed is generated
 * here and shown as an otpauth:// URI / QR code for the user to add. The
 * application never reads codes from an authenticator app.
 *
 * The TOTP seed is stored in an on-device, AES-GCM encrypted vault (DPAPI bound
 * on Windows). It is NOT part of the database, does NOT participate in the KDF,
 * and is bound per device.
 *
 * Defences: +/-1 time-step tolerance, one-time use with replay rejection,
 * exponential back-off and a hard temporary lockout after repeated failures.
 */

#ifndef PMP_TWOFACTOR_H
#define PMP_TWOFACTOR_H

#include <QHash>
#include <QString>

class PmpTwoFactor
{
public:
    enum VerifyResult
    {
        Ok = 0,
        NotEnrolled = 1,
        Locked = 2,
        Replay = 3,
        Wrong = 4,
        Error = 5,
    };

    struct EnrollStart
    {
        QString secretB32;
        QString otpauthUri;
    };

    static PmpTwoFactor* instance();

    bool isEnrolled(const QString& databaseFilePath) const;

    // Step 1: generate a seed + otpauth URI (held in memory until confirmed).
    EnrollStart beginEnroll(const QString& databaseFilePath, const QString& label);
    // Step 2: user enters a current code to confirm; the vault is then written.
    bool confirmEnroll(const QString& databaseFilePath, const QString& code, QString& error);
    void removeEnrollment(const QString& databaseFilePath);

    // Verify a code during unlock. Applies replay/back-off/lockout policy and
    // writes audit records.
    VerifyResult verifyInteractive(const QString& databaseFilePath, const QString& code, QString& error);

    int failCount(const QString& databaseFilePath) const;
    qint64 lockedSecondsRemaining(const QString& databaseFilePath) const;

    static constexpr int Digits = 6;
    static constexpr int Step = 30;
    static constexpr int HardLockFailures = 10;

private:
    PmpTwoFactor() = default;

    struct Vault
    {
        bool enabled = false;
        QString secretB32;
        qulonglong lastCounter = 0;
        int failCount = 0;
        qlonglong lockUntilMs = 0;
        qlonglong enrolledAtMs = 0;
    };

    QString idFor(const QString& databaseFilePath) const;
    QString vaultPathFor(const QString& id16) const;
    bool loadVault(const QString& id16, Vault& vault) const;
    bool saveVault(const QString& id16, const Vault& vault) const;

    static QString generateTotp(const QString& secretB32, qulonglong epochSeconds, bool* valid = nullptr);
    static bool constantTimeEqual(const QString& a, const QString& b);

    QHash<QString, EnrollStart> m_pending;
};

#endif // PMP_TWOFACTOR_H
