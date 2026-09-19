/*
 * PmVault extensions - LAN TLS 1.3 two-way sync implementation.
 */

#include "PmpSync.h"

#include "PmpAuditLog.h"
#include "PmpConfig.h"
#include "PmpPlatform.h"

#include "core/CustomData.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/Metadata.h"

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <QCryptographicHash>

#include <QSslCertificate>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>

// Value types (VClock, Snapshot, State, ...) live in the PmpSync namespace
// declared in PmpSyncTypes.h. The QObject engine class is PmpSyncEngine.
using namespace PmpSync;

namespace
{
    const QString MSG_HELLO = QStringLiteral("HELLO");
    const QString MSG_MANIFEST = QStringLiteral("MANIFEST");
    const QString MSG_WANT = QStringLiteral("WANT");
    const QString MSG_ENTRIES = QStringLiteral("ENTRIES");
    const QString MSG_APPLIED = QStringLiteral("APPLIED");
    const QString MSG_BYE = QStringLiteral("BYE");

    const QString K_VCLOCK = QStringLiteral("PM:VClock");
    const QString K_LASTHASH = QStringLiteral("PM:LastSyncHash");
    const QString K_TOMBS = QStringLiteral("PM:Tombstones");
    const QString K_ORIGIN = QStringLiteral("PM:Origin");

    QString uuidStr(const Entry* e)
    {
        return e->uuid().toString(QUuid::WithoutBraces);
    }

    // TLS server that upgrades every inbound TCP connection to SSL.
    class PmpSslServer : public QTcpServer
    {
    public:
        std::function<void(QSslSocket*)> setupSocket;

        explicit PmpSslServer(QObject* parent)
            : QTcpServer(parent)
        {
        }

    protected:
        void incomingConnection(qintptr socketDescriptor) override
        {
            auto* socket = new QSslSocket(this);
            if (!socket->setSocketDescriptor(socketDescriptor)) {
                delete socket;
                return;
            }
            if (setupSocket) {
                setupSocket(socket);
            }
            socket->startServerEncryption();
            addPendingConnection(socket);
        }
    };
} // namespace

PmpSyncEngine::PmpSyncEngine(QObject* parent)
    : QObject(parent)
{
}

bool PmpSyncEngine::isLanAddress(const QHostAddress& addr)
{
    if (addr.isLoopback() || addr.isLinkLocal()) {
        return true;
    }
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 v = addr.toIPv4Address();
        const quint32 a = (v >> 24) & 0xff;
        const quint32 b = (v >> 16) & 0xff;
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        return a == 10 || (a == 172 && (b & 0xf0) == 16) || (a == 192 && b == 168);
    }
    if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
        const Q_IPV6ADDR m = addr.toIPv6Address();
        return m[0] == 0xfc || m[0] == 0xfd; // unique local fc00::/7
    }
    return false;
}

void PmpSyncEngine::start(Database* db, const Options& options)
{
    m_db = db;
    m_options = options;

    // Fail loudly (into the dialog log) instead of crashing if the TLS stack
    // or this device's identity is unavailable.
    if (!QSslSocket::supportsSsl()) {
        fail(QObject::tr("TLS (OpenSSL) is not available in this build, so LAN sync cannot run."));
        return;
    }

    m_identity = PmpIdentityStore::loadOrCreate();
    if (!m_identity.valid()) {
        fail(QObject::tr("This device's TLS identity could not be created. Check the installation and retry."));
        return;
    }
    m_selfNode = m_identity.nodeId;
    m_dbId = PmpPlatform::dbId(db ? db->filePath() : QString());

    m_timer = new QTimer(this);
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, &PmpSyncEngine::onTimeout);
    m_timer->start(options.listen ? 30000 : 15000);

    if (options.listen) {
        emit logMessage(QObject::tr("Listening for a single LAN peer on port %1 (30 s)…").arg(options.port));
        auto* server = new PmpSslServer(this);
        server->setupSocket = [this](QSslSocket* s) { configureSocket(s); };
        connect(server, &QTcpServer::newConnection, this, &PmpSyncEngine::onNewConnection);
        if (!server->listen(QHostAddress::Any, static_cast<quint16>(options.port))) {
            fail(QObject::tr("Could not listen on port %1: %2").arg(options.port).arg(server->errorString()));
            return;
        }
        m_server = server;
    } else {
        emit logMessage(QObject::tr("Connecting to %1:%2 over TLS 1.3…").arg(options.host).arg(options.port));
        auto* socket = new QSslSocket(this);
        configureSocket(socket);
        m_socket = socket;
        socket->connectToHostEncrypted(options.host, static_cast<quint16>(options.port));
    }
}

void PmpSyncEngine::configureSocket(QSslSocket* socket)
{
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
#if QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)
    cfg.setProtocol(QSsl::TlsV1_3);
#else
    cfg.setProtocol(QSsl::TlsV1_2OrLater);
#endif
    cfg.setLocalCertificate(m_identity.certificate);
    cfg.setPrivateKey(m_identity.privateKey);
    // Mutual TLS: always demand a peer certificate. Trust is decided solely by
    // fingerprint pinning, never by the system CA store.
    cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
    cfg.setPeerVerifyDepth(1);
    socket->setSslConfiguration(cfg);

    connect(socket,
            static_cast<void (QSslSocket::*)()>(&QSslSocket::encrypted),
            this,
            &PmpSyncEngine::onEncrypted);
    connect(socket,
            qOverload<const QList<QSslError>&>(&QSslSocket::sslErrors),
            this,
            &PmpSyncEngine::onSslErrors);
    connect(socket, &QSslSocket::readyRead, this, &PmpSyncEngine::onReadyRead);
    connect(socket,
            static_cast<void (QSslSocket::*)(QAbstractSocket::SocketError)>(&QSslSocket::errorOccurred),
            this,
            &PmpSyncEngine::onSocketError);
    connect(socket, &QSslSocket::disconnected, this, [this]() {
        if (!m_done && m_applied) {
            finishOk(QObject::tr("Sync completed; peer disconnected."));
        }
    });
}

void PmpSyncEngine::onNewConnection()
{
    if (!m_server) {
        return;
    }
    m_server->pauseAccepting(); // single connection only
    m_socket = qobject_cast<QSslSocket*>(m_server->nextPendingConnection());
    if (!m_socket) {
        fail(QObject::tr("Incoming connection was not a TLS socket."));
        return;
    }
    emit logMessage(QObject::tr("Peer connected from %1").arg(m_socket->peerAddress().toString()));
}

void PmpSyncEngine::onSslErrors(const QList<QSslError>& errors)
{
    auto* socket = qobject_cast<QSslSocket*>(sender());
    if (!socket) {
        return;
    }
    const QSslCertificate peer = socket->peerCertificate();
    if (peer.isNull()) {
        // Mutual TLS: a peer without a certificate is never acceptable.
        fail(QObject::tr("Peer presented no certificate; mutual TLS required."));
        socket->abort();
        return;
    }
    const QString fp = QString::fromLatin1(peer.digest(QCryptographicHash::Sha256).toHex()).toLower();
    if (isPeerTrusted(fp)) {
        socket->ignoreSslErrors(errors);
        return;
    }
    bool accepted = false;
    if (m_options.confirmPeer) {
        accepted = m_options.confirmPeer(fp, m_options.host);
    }
    if (accepted) {
        addTrustedPeer(fp);
        socket->ignoreSslErrors(errors);
    } else {
        socket->abort();
        fail(QObject::tr("Peer certificate fingerprint not trusted:\n%1").arg(fp));
    }
}

void PmpSyncEngine::onEncrypted()
{
    auto* socket = qobject_cast<QSslSocket*>(sender());
    if (!socket || socket != m_socket) {
        return;
    }
    const QSslCertificate peer = socket->peerCertificate();
    if (peer.isNull()) {
        fail(QObject::tr("Mutual TLS failed: no peer certificate."));
        return;
    }
    if (!isLanAddress(socket->peerAddress())) {
        fail(QObject::tr("Peer address %1 is not on the local network.").arg(socket->peerAddress().toString()));
        return;
    }
#if QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)
    if (socket->sessionCipher().protocol() != QSsl::TlsV1_3) {
        fail(QObject::tr("Negotiated protocol is not TLS 1.3; aborting."));
        return;
    }
#endif
    m_peerFingerprint = QString::fromLatin1(peer.digest(QCryptographicHash::Sha256).toHex()).toLower();
    m_peerNode = m_peerFingerprint.left(16);
    emit logMessage(QObject::tr("TLS 1.3 secured with peer %1").arg(m_peerNode));

    // Build the local state lazily and send HELLO + MANIFEST once.
    if (m_local.live.isEmpty()) {
        m_local = buildLocalState();
    }
    sendHelloAndManifest();
}

void PmpSyncEngine::onSocketError()
{
    auto* socket = qobject_cast<QSslSocket*>(sender());
    if (socket && !m_done) {
        fail(socket->errorString());
    }
}

void PmpSyncEngine::onTimeout()
{
    if (!m_done) {
        if (m_applied) {
            finishOk(QObject::tr("Sync completed before timeout."));
        } else {
            fail(QObject::tr("Sync timed out waiting for the peer."));
        }
    }
}

void PmpSyncEngine::sendJson(const QJsonObject& obj)
{
    if (!m_socket) {
        return;
    }
    m_socket->write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
    m_socket->write("\n");
    m_socket->flush();
}

void PmpSyncEngine::sendHelloAndManifest()
{
    QJsonObject hello;
    hello["type"] = MSG_HELLO;
    hello["node"] = m_selfNode;
    hello["dbId"] = m_dbId;
    sendJson(hello);
    sendJson(buildManifestJson());
}

QJsonObject PmpSyncEngine::buildManifestJson()
{
    QJsonArray live;
    for (auto it = m_local.live.constBegin(); it != m_local.live.constEnd(); ++it) {
        QJsonObject item;
        item["uuid"] = it.key();
        item["vclock"] = it.value().toJson();
        item["hash"] = m_local.snaps.value(it.key()).contentHash;
        live.append(item);
    }
    QJsonArray tombs;
    for (auto it = m_local.tombs.constBegin(); it != m_local.tombs.constEnd(); ++it) {
        PmpSync::Tombstone t{it.key(), it.value()};
        tombs.append(t.toJson());
    }
    QJsonObject manifest;
    manifest["type"] = MSG_MANIFEST;
    manifest["node"] = m_selfNode;
    manifest["dbId"] = m_dbId;
    manifest["live"] = live;
    manifest["tombs"] = tombs;
    return manifest;
}

PmpSync::State PmpSyncEngine::buildLocalState()
{
    State state;
    if (!m_db || !m_db->rootGroup()) {
        return state;
    }
    Group* root = m_db->rootGroup();
    const QList<Entry*> entries = root->entriesRecursive(false);
    for (Entry* e : entries) {
        const QString uuid = uuidStr(e);

        // Snapshot attributes (never the internal PM: keys).
        QJsonObject fields;
        const EntryAttributes* attr = e->attributes();
        for (const QString& k : attr->keys()) {
            if (k.startsWith("PM:")) {
                continue;
            }
            fields[k] = attr->value(k);
        }
        Snapshot snap;
        snap.uuid = uuid;
        snap.fields = fields;
        // Creating-device marker. This build is a desktop client: entries without
        // an explicit origin are tagged "desktop" and persisted so the mobile
        // client can distinguish them after sync.
        QString origin = e->customData()->value(K_ORIGIN);
        if (origin.isEmpty()) {
            origin = QStringLiteral("desktop");
            e->customData()->set(K_ORIGIN, origin);
        }
        snap.origin = origin;
        snap.computeHash();

        // Vector clock: initialise if needed, and tick when content changed
        // since the last sync (detects local edits made outside sync).
        VClock vc = VClock::fromJson(QJsonDocument::fromJson(e->customData()->value(K_VCLOCK).toUtf8()).object());
        const QString lastHash = e->customData()->value(K_LASTHASH);
        if (vc.isEmpty()) {
            vc.tick(m_selfNode);
        }
        if (lastHash != snap.contentHash) {
            vc.tick(m_selfNode);
        }
        snap.vclock = vc;
        e->customData()->set(K_VCLOCK, QString::fromUtf8(QJsonDocument(vc.toJson()).toJson(QJsonDocument::Compact)));
        e->customData()->set(K_LASTHASH, snap.contentHash);

        state.live.insert(uuid, vc);
        state.snaps.insert(uuid, snap);
    }

    // Tombstones live in database Metadata CustomData.
    const auto tombs = QJsonDocument::fromJson(m_db->metadata()->customData()->value(K_TOMBS).toUtf8()).array();
    for (const QJsonValue& v : tombs) {
        const Tombstone t = Tombstone::fromJson(v.toObject());
        state.tombs.insert(t.uuid, t.vclock);
    }
    return state;
}

QStringList PmpSyncEngine::computeWants(const QJsonObject& remoteManifest)
{
    QStringList wants;
    const QJsonArray live = remoteManifest.value("live").toArray();
    for (const QJsonValue& v : live) {
        const QJsonObject item = v.toObject();
        const QString uuid = item.value("uuid").toString();
        const QString hash = item.value("hash").toString();
        const bool localLive = m_local.live.contains(uuid);
        if (!localLive) {
            wants.append(uuid);
        } else if (m_local.snaps.value(uuid).contentHash != hash) {
            wants.append(uuid);
        }
    }
    return wants;
}

void PmpSyncEngine::sendEntries(const QStringList& uuids)
{
    QJsonArray items;
    for (const QString& uuid : uuids) {
        if (m_local.snaps.contains(uuid)) {
            items.append(m_local.snaps.value(uuid).toJson());
        }
    }
    QJsonObject msg;
    msg["type"] = MSG_ENTRIES;
    msg["items"] = items;
    sendJson(msg);
}

void PmpSyncEngine::receiveEntries(const QJsonArray& items)
{
    for (const QJsonValue& v : items) {
        const Snapshot s = Snapshot::fromJson(v.toObject());
        if (!s.uuid.isEmpty()) {
            m_remoteSnaps.insert(s.uuid, s);
        }
    }
}

void PmpSyncEngine::onReadyRead()
{
    auto* socket = qobject_cast<QSslSocket*>(sender());
    if (!socket) {
        return;
    }
    m_rxBuffer.append(socket->readAll());
    int nl;
    while ((nl = m_rxBuffer.indexOf('\n')) >= 0) {
        const QByteArray line = m_rxBuffer.left(nl);
        m_rxBuffer.remove(0, nl + 1);
        if (line.trimmed().isEmpty()) {
            continue;
        }
        const QJsonDocument doc = QJsonDocument::fromJson(line);
        if (doc.isObject()) {
            handleMessage(doc.object());
        }
    }
}

void PmpSyncEngine::handleMessage(const QJsonObject& msg)
{
    const QString type = msg.value("type").toString();

    if (type == MSG_HELLO) {
        m_peerNode = msg.value("node").toString();
        return;
    }

    if (type == MSG_MANIFEST) {
        // Both sides send HELLO + MANIFEST from onEncrypted().
        m_remoteManifest = msg;
        const QStringList wants = computeWants(msg);
        m_expectedEntries = wants.size();
        QJsonObject w;
        w["type"] = MSG_WANT;
        QJsonArray arr;
        for (const QString& u : wants) {
            arr.append(u);
        }
        w["uuids"] = arr;
        sendJson(w);
        if (wants.isEmpty()) {
            applyMergeAndReply();
        }
        return;
    }

    if (type == MSG_WANT) {
        QStringList uuids;
        for (const QJsonValue& v : msg.value("uuids").toArray()) {
            uuids.append(v.toString());
        }
        sendEntries(uuids);
        return;
    }

    if (type == MSG_ENTRIES) {
        receiveEntries(msg.value("items").toArray());
        if (m_remoteSnaps.size() >= m_expectedEntries) {
            applyMergeAndReply();
        }
        return;
    }

    if (type == MSG_APPLIED) {
        m_peerApplied = true;
        emit logMessage(QObject::tr("Peer applied changes (upsert %1, delete %2, copies %3)")
                            .arg(msg.value("upserted").toInt())
                            .arg(msg.value("deleted").toInt())
                            .arg(msg.value("copies").toInt()));
        if (m_applied) {
            QJsonObject bye;
            bye["type"] = MSG_BYE;
            sendJson(bye);
            finishOk(QObject::tr("Two-way sync completed."));
        }
        return;
    }

    if (type == MSG_BYE) {
        if (m_applied) {
            finishOk(QObject::tr("Two-way sync completed."));
        }
    }
}

void PmpSyncEngine::applyMergeAndReply()
{
    if (m_applied || !m_db) {
        return;
    }

    // Assemble remote state from manifest + fetched snapshots.
    State remote;
    const QJsonArray live = m_remoteManifest.value("live").toArray();
    for (const QJsonValue& v : live) {
        const QJsonObject item = v.toObject();
        const QString uuid = item.value("uuid").toString();
        remote.live.insert(uuid, VClock::fromJson(item.value("vclock")));
        if (m_remoteSnaps.contains(uuid)) {
            remote.snaps.insert(uuid, m_remoteSnaps.value(uuid));
        }
    }
    for (const QJsonValue& v : m_remoteManifest.value("tombs").toArray()) {
        const Tombstone t = Tombstone::fromJson(v.toObject());
        remote.tombs.insert(t.uuid, t.vclock);
    }

    const QVector<Action> actions = planMerge(m_local, remote, m_options.policy);
    Group* root = m_db->rootGroup();

    int upserted = 0;
    int deleted = 0;
    int copies = 0;

    QJsonArray tombs = QJsonDocument::fromJson(m_db->metadata()->customData()->value(K_TOMBS).toUtf8()).array();

    auto writeClockAndHash = [&](Entry* e, const VClock& vc, const QString& hash) {
        e->customData()->set(K_VCLOCK,
                            QString::fromUtf8(QJsonDocument(vc.toJson()).toJson(QJsonDocument::Compact)));
        e->customData()->set(K_LASTHASH, hash);
    };

    for (const Action& a : actions) {
        if (a.kind == ActIgnore) {
            continue;
        }
        if (a.kind == ActUpsert) {
            const QUuid quuid = QUuid::fromString(a.snap.uuid);
            Entry* e = root->findEntryByUuid(quuid);
            bool created = false;
            if (!e) {
                e = new Entry();
                e->setUuid(quuid);
                e->setGroup(root);
                created = true;
            }
            for (auto it = a.snap.fields.constBegin(); it != a.snap.fields.constEnd(); ++it) {
                const bool protect = (it.key() == EntryAttributes::PasswordKey);
                e->attributes()->set(it.key(), it.value().toString(), protect);
            }
            e->customData()->set(K_ORIGIN,
                                 a.snap.origin.isEmpty() ? QStringLiteral("desktop") : a.snap.origin);
            VClock vc = mergeClock(m_local.live.value(a.snap.uuid), a.snap.vclock);
            vc.tick(m_selfNode);
            writeClockAndHash(e, vc, a.snap.computeHash());
            Q_UNUSED(created);
            ++upserted;
        } else if (a.kind == ActConflictCopy) {
            Entry* e = new Entry();
            e->setUuid(QUuid::createUuid());
            e->setGroup(root);
            QJsonObject fields = a.snap.fields;
            const QString title = fields.value(EntryAttributes::TitleKey).toString();
            fields[EntryAttributes::TitleKey] =
                title + QObject::tr(" (conflict copy %1)").arg(m_peerNode.left(6));
            for (auto it = fields.constBegin(); it != fields.constEnd(); ++it) {
                const bool protect = (it.key() == EntryAttributes::PasswordKey);
                e->attributes()->set(it.key(), it.value().toString(), protect);
            }
            e->customData()->set(K_ORIGIN,
                                 a.snap.origin.isEmpty() ? QStringLiteral("desktop") : a.snap.origin);
            Snapshot copySnap = a.snap;
            copySnap.fields = fields;
            VClock vc = a.snap.vclock;
            vc.tick(m_selfNode);
            writeClockAndHash(e, vc, copySnap.computeHash());
            ++copies;
        } else if (a.kind == ActDelete) {
            Entry* e = root->findEntryByUuid(QUuid::fromString(a.localUuid));
            if (e) {
                VClock vc = mergeClock(m_local.live.value(a.localUuid), remote.tombs.value(a.localUuid));
                vc.tick(m_selfNode);
                Tombstone t{a.localUuid, vc};
                tombs.append(t.toJson());
                root->removeEntry(e);
                ++deleted;
            }
        }
    }

    if (deleted > 0 || upserted > 0 || copies > 0) {
        m_db->metadata()->customData()->set(
            K_TOMBS, QString::fromUtf8(QJsonDocument(tombs).toJson(QJsonDocument::Compact)));
        m_db->markAsModified();
        if (m_options.saveDatabase) {
            m_options.saveDatabase();
        }
    }

    m_report.upserted = upserted;
    m_report.deleted = deleted;
    m_report.conflictCopies = copies;
    m_applied = true;

    PmpAuditLog::instance()->record(PmpAuditLog::EvSync, PmpAuditLog::OcSuccess, PmpAuditLog::FldNone,
                                    PmpAuditLog::TgtLanPeer);

    QJsonObject applied;
    applied["type"] = MSG_APPLIED;
    applied["upserted"] = upserted;
    applied["deleted"] = deleted;
    applied["copies"] = copies;
    sendJson(applied);

    emit logMessage(QObject::tr("Merged: %1 updated, %2 deleted, %3 conflict copies.")
                        .arg(upserted)
                        .arg(deleted)
                        .arg(copies));

    if (m_peerApplied) {
        QJsonObject bye;
        bye["type"] = MSG_BYE;
        sendJson(bye);
        finishOk(QObject::tr("Two-way sync completed."));
    }
}

bool PmpSyncEngine::isPeerTrusted(const QString& fingerprint) const
{
    const QString raw = PmpConfig::getString(m_db, PmpConfig::Key::SyncTrustedPeers);
    const auto arr = QJsonDocument::fromJson(raw.toUtf8()).array();
    for (const QJsonValue& v : arr) {
        if (v.toString().compare(fingerprint, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}

void PmpSyncEngine::addTrustedPeer(const QString& fingerprint)
{
    QJsonArray arr = QJsonDocument::fromJson(
                         PmpConfig::getString(m_db, PmpConfig::Key::SyncTrustedPeers).toUtf8())
                         .array();
    arr.append(fingerprint.toLower());
    PmpConfig::setValue(m_db, PmpConfig::Key::SyncTrustedPeers,
                        QString::fromUtf8(QJsonDocument(arr).toJson(QJsonDocument::Compact)));
}

void PmpSyncEngine::fail(const QString& message)
{
    if (m_done) {
        return;
    }
    m_done = true;
    if (m_timer) {
        m_timer->stop();
    }
    if (m_socket) {
        m_socket->abort();
    }
    if (m_server) {
        m_server->close();
    }
    PmpAuditLog::instance()->record(PmpAuditLog::EvSyncFailed, PmpAuditLog::OcFailure, PmpAuditLog::FldNone,
                                    PmpAuditLog::TgtLanPeer);
    m_report.ok = false;
    m_report.message = message;
    m_report.peerNode = m_peerNode;
    m_report.peerFingerprint = m_peerFingerprint;
    emit logMessage(QObject::tr("Sync failed: %1").arg(message));
    emit finished(m_report);
}

void PmpSyncEngine::finishOk(const QString& message)
{
    if (m_done) {
        return;
    }
    m_done = true;
    if (m_timer) {
        m_timer->stop();
    }
    if (m_server) {
        m_server->close();
    }
    if (m_socket) {
        m_socket->disconnectFromHost();
    }
    m_report.ok = true;
    m_report.message = message;
    m_report.peerNode = m_peerNode;
    m_report.peerFingerprint = m_peerFingerprint;
    emit logMessage(message);
    emit finished(m_report);
}
