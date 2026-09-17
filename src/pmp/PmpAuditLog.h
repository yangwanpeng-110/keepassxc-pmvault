/*
 * PmVault extensions - local encrypted, tamper-evident audit log.
 *
 * Security contract:
 *  - The log records a FIXED event enumeration. The recording API deliberately
 *    accepts no value-class parameters (no passwords, user names, TOTP codes,
 *    entry titles or URLs). Only event / outcome / field-type / target-type
 *    enums are accepted.
 *  - Each record is sealed independently with AES-256-GCM. The AAD is the
 *    previous chain link, so deleting, reordering or altering a record breaks
 *    authentication of every following record (a hash/HMAC chain).
 *  - A separately sealed anchor stores the last sequence number and last chain
 *    link, so truncation of the file tail is detected on the next open.
 *  - Logs live OUTSIDE the database (per-user app data dir) and are never
 *    synced.
 */

#ifndef PMP_AUDITLOG_H
#define PMP_AUDITLOG_H

#include <QByteArray>
#include <QMutex>
#include <QString>
#include <QVector>

class PmpAuditLog
{
public:
    // Numeric values are part of the on-disk format: never renumber.
    enum Event
    {
        EvUnknown = 0,
        EvUnlock = 1,
        EvUnlockFailed = 2,
        EvTwoFactor = 3,
        EvTwoFactorFailed = 4,
        EvTwoFactorEnroll = 5,
        EvTwoFactorUnenroll = 6,
        EvLock = 7,
        EvPasswordChange = 8,
        EvCopy = 9,
        EvBrowserFill = 10,
        EvAutoType = 11,
        EvSync = 12,
        EvSyncFailed = 13,
        EvConfigChange = 14,
        EvLogRotate = 15,
    };

    enum Outcome
    {
        OcInfo = 0,
        OcSuccess = 1,
        OcFailure = 2,
        OcDenied = 3,
    };

    // Field TYPE only - never the value.
    enum Field
    {
        FldNone = 0,
        FldUsername = 1,
        FldPassword = 2,
        FldTotp = 3,
        FldUrl = 4,
        FldNotes = 5,
        FldOther = 6,
    };

    enum Target
    {
        TgtNone = 0,
        TgtLocalDatabase = 1,
        TgtBrowserDom = 2,
        TgtDesktopWindow = 3,
        TgtLanPeer = 4,
    };

    struct Record
    {
        qulonglong seq = 0;
        qulonglong ts = 0; // ms since epoch, UTC
        int event = 0;
        int outcome = 0;
        int field = 0;
        int target = 0;
        QString dbId;
    };

    struct VerifyResult
    {
        bool chainOk = false;
        bool anchorOk = false;
        bool truncated = false;
        int readableCount = 0;
        qulonglong lastSeq = 0;
        QString message;
    };

    static PmpAuditLog* instance();

    // Bind the currently open database file (drives log file name + keys).
    void bindDatabase(const QString& databaseFilePath);
    void closeDatabase();

    // Master switch for high-volume/low-risk events. Security-critical events
    // (unlock, 2FA, password change, sync) are always recorded.
    void setVerboseEnabled(bool enabled);
    void setLimits(int retentionDays, qint64 maxBytes);

    // The ONLY recording entry point. No free-text / value parameters.
    void record(Event event, Outcome outcome = OcSuccess, Field field = FldNone, Target target = TgtNone);

    VerifyResult verify(const QString& databaseFilePath = {}) const;
    QVector<Record> readAll(const QString& databaseFilePath = {}, int maxRecords = 5000) const;

    static QString eventName(int event);
    static QString outcomeName(int outcome);
    static QString fieldName(int field);
    static QString targetName(int target);

private:
    PmpAuditLog() = default;
    struct ChainState
    {
        qulonglong seq = 0;
        QByteArray link; // 32 bytes
    };
    QString idFor(const QString& databaseFilePath) const;
    QString logPathFor(const QString& id16) const;
    QString anchorPathFor(const QString& id16) const;
    QByteArray logKey(const QString& id16) const;
    QByteArray chainKey(const QString& id16) const;
    static QByteArray genesisLink();
    static QByteArray sealRecord(const QByteArray& key, const QByteArray& plain, const QByteArray& prevLink);
    static bool openRecord(const QByteArray& key, const QByteArray& frame, const QByteArray& prevLink,
                           QByteArray& plain);
    static QByteArray encodePlain(const Record& r, const QString& id16, const QByteArray& prevAnchor);
    static bool decodePlain(const QByteArray& plain, Record& r, QString& id16, QByteArray& prevAnchor);
    ChainState replay(const QString& id16, int* readable = nullptr) const;
    void rotateIfNeeded(const QString& id16, const QByteArray& lastLink);
    void pruneArchives(const QString& id16) const;
    void writeAnchor(const QString& id16, const ChainState& st) const;

    mutable QMutex m_mutex;
    QString m_currentPath;
    QString m_currentId;
    bool m_loaded = false;
    qulonglong m_lastSeq = 0;
    QByteArray m_lastLink;
    bool m_verbose = true;
    int m_retentionDays = 90;
    qint64 m_maxBytes = 10 * 1024 * 1024;
};

#endif // PMP_AUDITLOG_H
