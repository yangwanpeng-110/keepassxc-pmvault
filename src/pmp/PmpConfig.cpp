/*
 * PmVault extensions - configuration model implementation.
 */

#include "PmpConfig.h"

#include "PmpAuditLog.h"

#include "core/CustomData.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Metadata.h"

namespace PmpConfig
{
    namespace Key
    {
        const QString SchemaVersion = QStringLiteral("PM:SchemaVersion");

        const QString TwoFactorEnabled = QStringLiteral("PM:TwoFactor:Enabled");

        const QString AuditEnabled = QStringLiteral("PM:Audit:Enabled");
        const QString AuditRetentionDays = QStringLiteral("PM:Audit:RetentionDays");
        const QString AuditMaxBytes = QStringLiteral("PM:Audit:MaxBytes");

        const QString SyncEnabled = QStringLiteral("PM:Sync:Enabled");
        const QString SyncPort = QStringLiteral("PM:Sync:Port");
        const QString SyncConflictPolicy = QStringLiteral("PM:Sync:ConflictPolicy");
        const QString SyncTrustedPeers = QStringLiteral("PM:Sync:TrustedPeers");

        const QString ClipboardClearSeconds = QStringLiteral("PM:Clipboard:ClearSeconds");
        const QString IdleLockSeconds = QStringLiteral("PM:Idle:LockSeconds");

        const QString FillRequireConfirm = QStringLiteral("PM:Fill:RequireConfirm");
        const QString FillAutoSubmit = QStringLiteral("PM:Fill:AutoSubmit");
        const QString FillHttpsOnly = QStringLiteral("PM:Fill:HttpsOnly");

        const QString AutoTypeKeyDelayMs = QStringLiteral("PM:AutoType:KeyDelayMs");
        const QString AutoTypeDefaultSequence = QStringLiteral("PM:AutoType:DefaultSequence");

        const QString EntrySyncDisabled = QStringLiteral("PM:Entry:SyncDisabled");
    }

    const QHash<QString, QVariant>& defaults()
    {
        static const QHash<QString, QVariant> d = {
            {Key::SchemaVersion, QStringLiteral("1")},
            {Key::TwoFactorEnabled, false},
            {Key::AuditEnabled, true},
            {Key::AuditRetentionDays, 90},
            {Key::AuditMaxBytes, 10 * 1024 * 1024},
            {Key::SyncEnabled, false},
            {Key::SyncPort, 19532},
            {Key::SyncConflictPolicy, QStringLiteral("KeepBoth")},
            {Key::SyncTrustedPeers, QStringLiteral("[]")},
            {Key::ClipboardClearSeconds, 10},
            {Key::IdleLockSeconds, 300},
            {Key::FillRequireConfirm, true},
            {Key::FillAutoSubmit, false},
            {Key::FillHttpsOnly, true},
            {Key::AutoTypeKeyDelayMs, 8},
            {Key::AutoTypeDefaultSequence, QStringLiteral("{USERNAME}{TAB}{PASSWORD}{ENTER}")},
            {Key::EntrySyncDisabled, false},
        };
        return d;
    }

    static QVariant defaultOf(const QString& key)
    {
        const auto& d = defaults();
        return d.contains(key) ? d.value(key) : QVariant();
    }

    QString getString(const Database* db, const QString& key)
    {
        if (db && db->metadata() && db->metadata()->customData()->contains(key)) {
            return db->metadata()->customData()->value(key);
        }
        return defaultOf(key).toString();
    }

    bool getBool(const Database* db, const QString& key)
    {
        if (db && db->metadata() && db->metadata()->customData()->contains(key)) {
            const QString v = db->metadata()->customData()->value(key);
            return v.compare(QStringLiteral("true"), Qt::CaseInsensitive) == 0 || v == QStringLiteral("1");
        }
        return defaultOf(key).toBool();
    }

    int getInt(const Database* db, const QString& key)
    {
        if (db && db->metadata() && db->metadata()->customData()->contains(key)) {
            bool ok = false;
            int v = db->metadata()->customData()->value(key).toInt(&ok);
            if (ok) {
                return v;
            }
        }
        return defaultOf(key).toInt();
    }

    void setValue(Database* db, const QString& key, const QString& value)
    {
        if (db && db->metadata() && db->metadata()->customData()) {
            db->metadata()->customData()->set(key, value);
            PmpAuditLog::instance()->record(PmpAuditLog::EvConfigChange, PmpAuditLog::OcInfo,
                                            PmpAuditLog::FldNone, PmpAuditLog::TgtLocalDatabase);
        }
    }

    bool hasEntryOverride(const Entry* entry, const QString& key)
    {
        return entry && entry->customData() && entry->customData()->contains(key);
    }

    QString effectiveString(const Entry* entry, const QString& key)
    {
        if (hasEntryOverride(entry, key)) {
            return entry->customData()->value(key);
        }
        return getString(entry ? entry->database() : nullptr, key);
    }

    bool effectiveBool(const Entry* entry, const QString& key)
    {
        if (hasEntryOverride(entry, key)) {
            const QString v = entry->customData()->value(key);
            return v.compare(QStringLiteral("true"), Qt::CaseInsensitive) == 0 || v == QStringLiteral("1");
        }
        return getBool(entry ? entry->database() : nullptr, key);
    }

    int effectiveInt(const Entry* entry, const QString& key)
    {
        if (hasEntryOverride(entry, key)) {
            bool ok = false;
            int v = entry->customData()->value(key).toInt(&ok);
            if (ok) {
                return v;
            }
        }
        return getInt(entry ? entry->database() : nullptr, key);
    }

    void setEntryOverride(Entry* entry, const QString& key, const QString& value)
    {
        if (entry && entry->customData()) {
            entry->customData()->set(key, value);
        }
    }

    void clearEntryOverride(Entry* entry, const QString& key)
    {
        if (entry && entry->customData() && entry->customData()->contains(key)) {
            entry->customData()->remove(key);
        }
    }
} // namespace PmpConfig
