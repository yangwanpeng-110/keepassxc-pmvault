/*
 * PmVault extensions - LAN two-way sync over mutually authenticated TLS 1.3.
 *
 * Topology: one side listens for a SINGLE inbound connection (30 s timeout,
 * not a resident service), the other connects. Both sides then run the same
 * symmetric merge:
 *
 *   HELLO (node id, database id)
 *   MANIFEST (per-entry vector clock + content hash; tombstones)
 *   WANT (uuids whose content is needed)
 *   ENTRIES (entry snapshots)
 *   APPLIED (merge counts) / BYE
 *
 * Security:
 *   - TLS 1.3 only; self-signed certificates with SHA-256 fingerprint pinning.
 *   - Mutual certificate verification (client and server both present certs);
 *     system CAs are not trusted, only the explicit per-database peer list
 *     (stored in KDBX CustomData PM:Sync:TrustedPeers), with a one-time user
 *     confirmation for unknown fingerprints.
 *   - LAN-only: loopback / RFC1918 / link-local peer addresses are enforced.
 *   - Conflicts merge with vector clocks; concurrent edits default to
 *     KeepBoth, concurrent delete-vs-edit honours the configured policy.
 *   - Defaults to disabled; port 19532.
 */

#ifndef PMP_SYNCSERVER_H
#define PMP_SYNCSERVER_H

#include "PmpIdentity.h"
#include "PmpSyncTypes.h"

#include <QObject>
#include <QString>
#include <functional>

class Database;
class QSslSocket;
class QTcpServer;

class PmpSyncEngine : public QObject
{
    Q_OBJECT
public:
    enum ConflictPolicy
    {
        KeepBothPolicy = PmpSync::KeepBoth,
        DeleteWinsPolicy = PmpSync::DeleteWins
    };
    Q_ENUM(ConflictPolicy)

    struct Options
    {
        bool listen = false;                 // true: accept once; false: connect
        QString host;                        // connect target (IPv4/host)
        int port = 19532;
        PmpSync::ConflictPolicy policy = PmpSync::KeepBoth;
        std::function<bool()> saveDatabase; // persist after merge (UI injected)
        // Called synchronously to ask the user to trust a new fingerprint.
        std::function<bool(const QString& fingerprint, const QString& peer)> confirmPeer;
    };

    struct Report
    {
        bool ok = false;
        QString message;
        QString peerNode;
        QString peerFingerprint;
        int upserted = 0;
        int deleted = 0;
        int conflictCopies = 0;
    };

    explicit PmpSyncEngine(QObject* parent = nullptr);

    // Start asynchronously; result delivered via finished().
    void start(Database* db, const Options& options);

    static bool isLanAddress(const class QHostAddress& addr);

signals:
    void logMessage(const QString& text);
    void finished(const Report& report);

private slots:
    void onReadyRead();
    void onEncrypted();
    void onSslErrors(const QList<class QSslError>& errors);
    void onSocketError();
    void onTimeout();
    void onNewConnection();

private:
    void configureSocket(QSslSocket* socket);
    void fail(const QString& message);
    void finishOk(const QString& message);
    // Emit a log line and append it to a bounded trace used for audit-log diagnostics.
    void note(const QString& text);
    QString traceTail(int max = 600) const;
    void sendJson(const QJsonObject& obj);
    void handleMessage(const QJsonObject& msg);
    void sendHelloAndManifest();
    QJsonObject buildManifestJson();
    PmpSync::State buildLocalState();
    QStringList computeWants(const QJsonObject& remoteManifest);
    void sendEntries(const QStringList& uuids);
    void receiveEntries(const QJsonArray& items);
    void applyMergeAndReply();
    void addTrustedPeer(const QString& fingerprint);
    bool isPeerTrusted(const QString& fingerprint) const;

    PmpIdentity m_identity;
    Database* m_db = nullptr;
    Options m_options;
    QString m_selfNode;
    QString m_dbId;

    QTcpServer* m_server = nullptr;
    QSslSocket* m_socket = nullptr;
    class QTimer* m_timer = nullptr;
    QByteArray m_rxBuffer;

    PmpSync::State m_local;
    QJsonObject m_remoteManifest;
    QHash<QString, PmpSync::Snapshot> m_remoteSnaps;
    int m_expectedEntries = 0;
    bool m_applied = false;
    bool m_peerApplied = false;
    bool m_done = false;
    QString m_peerFingerprint;
    QString m_peerNode;
    QString m_trace;
    Report m_report;
};

#endif // PMP_SYNCSERVER_H
