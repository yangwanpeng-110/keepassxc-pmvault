/*
 * PmVault extensions - LAN sync data model and conflict resolution.
 *
 * Pure (no Qt Network / Database) types so the merge logic is deterministic
 * and testable:
 *   - Vector clocks track per-node causal ordering of each entry.
 *   - Deletions are represented by tombstones.
 *   - Concurrent edits default to KeepBoth (both sides survive, the remote
 *     side is stored as a separate "conflict copy"); DeleteWins only affects
 *     the concurrent delete-vs-edit case.
 */

#ifndef PMP_SYNCTYPES_H
#define PMP_SYNCTYPES_H

#include "PmpCrypto.h"

#include <QHash>
#include <QJsonObject>
#include <QJsonValue>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVector>

namespace PmpSync
{
    // ---------- Vector clock ----------
    struct VClock
    {
        QHash<QString, qulonglong> ticks;

        bool isEmpty() const
        {
            return ticks.isEmpty();
        }
        void tick(const QString& node)
        {
            ticks[node] = ticks.value(node, 0) + 1;
        }
        QJsonObject toJson() const
        {
            QJsonObject o;
            for (auto it = ticks.constBegin(); it != ticks.constEnd(); ++it) {
                o.insert(it.key(), static_cast<double>(it.value()));
            }
            return o;
        }
        static VClock fromJson(const QJsonValue& v)
        {
            VClock c;
            const QJsonObject o = v.toObject();
            for (auto it = o.constBegin(); it != o.constEnd(); ++it) {
                c.ticks.insert(it.key(), static_cast<qulonglong>(it.value().toDouble()));
            }
            return c;
        }
    };

    inline VClock mergeClock(const VClock& a, const VClock& b)
    {
        VClock out = a;
        for (auto it = b.ticks.constBegin(); it != b.ticks.constEnd(); ++it) {
            out.ticks[it.key()] = qMax(out.ticks.value(it.key(), 0), it.value());
        }
        return out;
    }

    enum Ordering
    {
        ClkEqual = 0,
        ClkBefore = 1,   // a happens before b
        ClkAfter = 2,    // a happens after b
        ClkConcurrent = 3
    };

    inline Ordering compare(const VClock& a, const VClock& b)
    {
        bool aLess = false;
        bool bLess = false;
        const QSet<QString> nodes = QSet<QString>::fromList(a.ticks.keys()) |
                                    QSet<QString>::fromList(b.ticks.keys());
        for (const QString& n : nodes) {
            const qulonglong av = a.ticks.value(n, 0);
            const qulonglong bv = b.ticks.value(n, 0);
            if (av < bv) {
                aLess = true;
            } else if (av > bv) {
                bLess = true;
            }
        }
        if (!aLess && !bLess) {
            return ClkEqual;
        }
        if (aLess && !bLess) {
            return ClkBefore;
        }
        if (bLess && !aLess) {
            return ClkAfter;
        }
        return ClkConcurrent;
    }

    // ---------- Entry snapshot ----------
    struct Snapshot
    {
        QString uuid;
        VClock vclock;
        QJsonObject fields; // standard + custom string attributes only
        // Device that originally created the entry: "desktop" or "mobile".
        // Metadata only: it is exchanged out-of-band (not part of fields/hash)
        // so a different creating device never causes a spurious content conflict.
        QString origin;
        mutable QString contentHash;

        QString computeHash() const
        {
            // Deterministic, key-sorted canonicalisation (no JSON whitespace
            // dependence), never includes anything beyond entry attributes.
            QStringList keys = fields.keys();
            keys.sort();
            QByteArray canon;
            for (const QString& k : keys) {
                canon.append(k.toUtf8());
                canon.append('\0');
                canon.append(fields.value(k).toString().toUtf8());
                canon.append('\0');
            }
            contentHash = QString::fromLatin1(PmpCrypto::sha256(canon).toHex());
            return contentHash;
        }

        QJsonObject toJson() const
        {
            QJsonObject o;
            o["uuid"] = uuid;
            o["vclock"] = vclock.toJson();
            o["fields"] = fields;
            o["origin"] = origin;
            o["hash"] = contentHash;
            return o;
        }
        static Snapshot fromJson(const QJsonObject& o)
        {
            Snapshot s;
            s.uuid = o.value("uuid").toString();
            s.vclock = VClock::fromJson(o.value("vclock"));
            s.fields = o.value("fields").toObject();
            s.origin = o.value("origin").toString();
            s.contentHash = o.value("hash").toString();
            return s;
        }
    };

    // ---------- Tombstone ----------
    struct Tombstone
    {
        QString uuid;
        VClock vclock;
        QJsonObject toJson() const
        {
            QJsonObject o;
            o["uuid"] = uuid;
            o["vclock"] = vclock.toJson();
            return o;
        }
        static Tombstone fromJson(const QJsonObject& o)
        {
            Tombstone t;
            t.uuid = o.value("uuid").toString();
            t.vclock = VClock::fromJson(o.value("vclock"));
            return t;
        }
    };

    enum ConflictPolicy
    {
        KeepBoth = 0,
        DeleteWins = 1
    };

    // ---------- Merge plan (what the local database should do) ----------
    enum ActionKind
    {
        ActIgnore = 0,
        ActUpsert = 1,     // insert/update from remote
        ActDelete = 2,     // apply remote tombstone
        ActConflictCopy = 3 // store remote side under a new uuid
    };

    struct Action
    {
        ActionKind kind = ActIgnore;
        Snapshot snap;
        QString localUuid; // uuid in local db (for copy: source uuid)
    };

    struct State
    {
        QHash<QString, VClock> live;     // uuid -> vclock
        QHash<QString, VClock> tombs;    // uuid -> tombstone vclock
        QHash<QString, Snapshot> snaps; // uuid -> snapshot (remote side filled)
    };

    inline QVector<Action> planMerge(const State& local, const State& remote, ConflictPolicy policy)
    {
        QVector<Action> actions;
        QSet<QString> uuids = QSet<QString>::fromList(remote.live.keys()) |
                              QSet<QString>::fromList(remote.tombs.keys());

        for (const QString& uuid : uuids) {
            const bool rLive = remote.live.contains(uuid);
            const bool lLive = local.live.contains(uuid);
            const bool lTomb = local.tombs.contains(uuid);
            const bool rTomb = remote.tombs.contains(uuid);

            if (rLive) {
                const VClock rv = remote.live.value(uuid);
                Snapshot rsnap = remote.snaps.value(uuid);
                if (!lLive && !lTomb) {
                    // Remote-only entry.
                    Action a{ActUpsert, rsnap, uuid};
                    actions.append(a);
                } else if (lLive) {
                    switch (compare(local.live.value(uuid), rv)) {
                    case ClkAfter:
                    case ClkEqual:
                        break; // local newer/equal
                    case ClkBefore:
                        actions.append(Action{ActUpsert, rsnap, uuid});
                        break;
                    case ClkConcurrent: {
                        // Only keep a separate copy if the content actually differs.
                        const QString localHash = local.snaps.value(uuid).contentHash;
                        if (!rsnap.contentHash.isEmpty() && localHash != rsnap.contentHash) {
                            actions.append(Action{ActConflictCopy, rsnap, uuid});
                        }
                        break;
                    }
                    default:
                        break;
                    }
                } else if (lTomb) {
                    // Local deleted, remote has a version.
                    const Ordering ord = compare(local.tombs.value(uuid), rv);
                    if (ord == ClkBefore) {
                        actions.append(Action{ActUpsert, rsnap, uuid}); // remote edited after delete
                    } else if (ord == ClkConcurrent) {
                        if (policy == KeepBoth) {
                            actions.append(Action{ActConflictCopy, rsnap, uuid});
                        }
                        // DeleteWins: stay deleted.
                    }
                }
            } else if (rTomb) {
                const VClock rv = remote.tombs.value(uuid);
                if (lLive) {
                    const Ordering ord = compare(local.live.value(uuid), rv);
                    if (ord == ClkBefore) {
                        actions.append(Action{ActDelete, {}, uuid});
                    } else if (ord == ClkConcurrent) {
                        if (policy == DeleteWins) {
                            actions.append(Action{ActDelete, {}, uuid});
                        }
                        // KeepBoth: keep the locally edited entry.
                    }
                }
                // local absent or already tombstoned: nothing to do.
                Q_UNUSED(rTomb);
            }
        }
        return actions;
    }
} // namespace PmpSync

#endif // PMP_SYNCTYPES_H
