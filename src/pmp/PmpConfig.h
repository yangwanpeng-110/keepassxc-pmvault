/*
 * PmVault extensions - configuration model.
 *
 * Every PmVault setting is stored inside the KDBX4 database CustomData
 * extension under the "PM:" key prefix. Nothing is stored in the cloud or in
 * OS-level settings for configuration.
 *
 *   Global settings : Metadata::customData()
 *   Per-entry override : Entry::customData(), same "PM:" keys
 *
 * Resolution order for an entry: entry override > global setting > built-in
 * default.
 */

#ifndef PMP_CONFIG_H
#define PMP_CONFIG_H

#include <QHash>
#include <QString>
#include <QVariant>

class Database;
class Entry;

namespace PmpConfig
{
    constexpr const char* PREFIX = "PM:";

    namespace Key
    {
        extern const QString SchemaVersion;

        extern const QString TwoFactorEnabled; // second factor (TOTP) unlock gate

        extern const QString AuditEnabled;
        extern const QString AuditRetentionDays;
        extern const QString AuditMaxBytes;

        extern const QString SyncEnabled;
        extern const QString SyncPort;
        extern const QString SyncConflictPolicy; // "KeepBoth" | "DeleteWins"
        extern const QString SyncTrustedPeers; // JSON array of pinned fingerprints

        extern const QString ClipboardClearSeconds;
        extern const QString IdleLockSeconds;

        extern const QString FillRequireConfirm;
        extern const QString FillAutoSubmit;
        extern const QString FillHttpsOnly;

        extern const QString AutoTypeKeyDelayMs;
        extern const QString AutoTypeDefaultSequence;

        // Per-entry-only override keys (not meaningful globally)
        extern const QString EntrySyncDisabled; // exclude this entry from sync
    }

    // Built-in defaults (also the security baseline).
    const QHash<QString, QVariant>& defaults();

    // Global settings (Metadata CustomData).
    QString getString(const Database* db, const QString& key);
    bool getBool(const Database* db, const QString& key);
    int getInt(const Database* db, const QString& key);
    void setValue(Database* db, const QString& key, const QString& value);

    // Effective value for an entry (entry override > global > default).
    QString effectiveString(const Entry* entry, const QString& key);
    bool effectiveBool(const Entry* entry, const QString& key);
    int effectiveInt(const Entry* entry, const QString& key);

    bool hasEntryOverride(const Entry* entry, const QString& key);
    void setEntryOverride(Entry* entry, const QString& key, const QString& value);
    void clearEntryOverride(Entry* entry, const QString& key);
} // namespace PmpConfig

#endif // PMP_CONFIG_H
