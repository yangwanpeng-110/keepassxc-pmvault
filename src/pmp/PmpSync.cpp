/*
 * PmVault extensions - LAN TLS 1.3 two-way sync implementation.
 */

#include "PmpSync.h"

#include "PmpAuditLog.h"
#include "PmpFileLogger.h"
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
#include <QSet>

#include <QSslCertificate>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QNetworkInterface>

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
    // One-time marker: built-in empty templates mistakenly synced into root were removed.
    const QString K_CLEANED = QStringLiteral("PM:CleanedOrphanTemplates");

    // KeePassDX built-in entry-template blueprint titles (Plan A: never synced).
    const QSet<QString> builtinTemplateTitles()
    {
        return {
            QStringLiteral("Email"),
            QStringLiteral("Wi-Fi"),
            QStringLiteral("Notes"),
            QStringLiteral("ID Card"),
            QStringLiteral("Debit / Credit Card"),
            QStringLiteral("Bank"),
            QStringLiteral("Cryptocurrency wallet")
        };
    }

    // A snapshot is an empty built-in template only when its title matches and it
    // carries no username / password / URL value (avoids deleting real entries).
    bool snapshotIsEmptyTemplate(const QJsonObject& fields)
    {
        const QString title =
            fields.value(EntryAttributes::TitleKey).toString().trimmed();
        if (!builtinTemplateTitles().contains(title)) {
            return false;
        }
        return fields.value(EntryAttributes::UserNameKey).toString().isEmpty()
               && fields.value(EntryAttributes::PasswordKey).toString().isEmpty()
               && fields.value(EntryAttributes::URLKey).toString().isEmpty();
    }

    QString uuidStr(const Entry* e)
    {
        return e->uuid().toString(QUuid::WithoutBraces);
    }

    // Enumerate this device's usable LAN IPv4 addresses, so the user knows exactly
    // which address to type on the other device (Wi‑Fi vs Ethernet vs VPN adapters
    // often coexist and the wrong one is a common cause of failed syncs).
    QStringList localIpv4List()
    {
        QStringList out;
        const auto interfaces = QNetworkInterface::allInterfaces();
        for (const QNetworkInterface& iface : interfaces) {
            if (!(iface.flags() & QNetworkInterface::IsUp)
                || !(iface.flags() & QNetworkInterface::IsRunning)
                || (iface.flags() & QNetworkInterface::IsLoopBack)) {
                continue;
            }
            for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
                const QHostAddress ip = entry.ip();
                if (ip.protocol() == QAbstractSocket::IPv4Protocol && !ip.isLoopback()) {
                    out << QStringLiteral("%1 (%2)").arg(ip.toString(), iface.humanReadableName());
                }
            }
        }
        return out;
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

void PmpSyncEngine::note(const QString& text)
{
    emit logMessage(text);
    // Mirror every phase line to the plaintext diagnostic log (connection-level
    // data only; callers must never put secrets in note()).
    PmpFileLogger::log(QStringLiteral("phase"), text);
    if (m_trace.size() > 2400) {
        m_trace.remove(0, m_trace.size() - 2000);
    }
    m_trace += text;
    m_trace += QLatin1Char('\n');
}

QString PmpSyncEngine::traceTail(int max) const
{
    QString s = m_trace;
    s.replace(QLatin1Char('\n'), QStringLiteral("; "));
    s = s.trimmed();
    if (s.size() > max) {
        s = s.right(max);
    }
    return s;
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
        fail(QObject::tr("本构建未提供 TLS（OpenSSL），无法进行局域网同步。"));
        return;
    }

    m_identity = PmpIdentityStore::loadOrCreate();
    if (!m_identity.valid()) {
        fail(QObject::tr("无法创建本机 TLS 身份，请检查安装后重试。"));
        return;
    }
    m_selfNode = m_identity.nodeId;
    m_dbId = PmpPlatform::dbId(db ? db->filePath() : QString());

    PmpFileLogger::log(QStringLiteral("start"),
                       QStringLiteral("role=%1 target=%2:%3 db=%4")
                           .arg(options.listen ? QStringLiteral("listen") : QStringLiteral("connect"),
                                options.host)
                           .arg(options.port)
                           .arg(m_dbId));

    note(QObject::tr("OpenSSL 版本：%1；编译期 SSL 版本：%2")
             .arg(QSslSocket::sslLibraryVersionString(),
                  QSslSocket::sslLibraryBuildVersionString()));

    m_timer = new QTimer(this);
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, &PmpSyncEngine::onTimeout);
    m_timer->start(options.listen ? 60000 : 20000);

    const QStringList localAddrs = localIpv4List();

    if (options.listen) {
        note(QObject::tr("正在端口 %1 监听单个局域网对端（60 秒）…").arg(options.port));
        auto* server = new PmpSslServer(this);
        server->setupSocket = [this](QSslSocket* s) { configureSocket(s); };
        connect(server, &QTcpServer::newConnection, this, &PmpSyncEngine::onNewConnection);
        if (!server->listen(QHostAddress::Any, static_cast<quint16>(options.port))) {
            fail(QObject::tr("无法在端口 %1 监听：%2").arg(options.port).arg(server->errorString()));
            return;
        }
        m_server = server;
        if (localAddrs.isEmpty()) {
            note(QObject::tr("未检测到活动的局域网 IPv4 地址，请先连接网络。"));
        } else {
            note(QObject::tr("本机局域网地址：%1").arg(localAddrs.join(", ")));
        }
        note(QObject::tr("请在另一台设备选择“主动连接对端”，并输入上述地址之一。"));
    } else {
        note(QObject::tr("正在通过 TLS 1.3 连接 %1:%2 …").arg(options.host).arg(options.port));
        if (!localAddrs.isEmpty()) {
            note(QObject::tr("本机局域网地址：%1").arg(localAddrs.join(", ")));
        }
        auto* socket = new QSslSocket(this);
        configureSocket(socket);
        // Stage logging distinguishes a TCP failure (firewall / wrong IP / AP
        // isolation) from a TLS-handshake failure (certificate / protocol).
        connect(socket, &QAbstractSocket::stateChanged, this,
                [this](QAbstractSocket::SocketState state) {
                    QString name;
                    switch (state) {
                    case QAbstractSocket::HostLookupState:
                        name = QObject::tr("正在解析主机名");
                        break;
                    case QAbstractSocket::ConnectingState:
                        name = QObject::tr("正在建立 TCP 连接");
                        break;
                    case QAbstractSocket::ConnectedState:
                        name = QObject::tr("TCP 已连接");
                        break;
                    // Note: there is no portable EncryptedState enum in Qt 5; the
                    // encrypted() signal (onEncrypted) logs the secured-channel stage.
                    case QAbstractSocket::UnconnectedState:
                        name = QObject::tr("连接已断开");
                        break;
                    default:
                        break;
                    }
                    if (!name.isEmpty()) {
                        note(QObject::tr("阶段：%1").arg(name));
                    }
                });
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
            finishOk(QObject::tr("同步完成，对端已断开。"));
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
        fail(QObject::tr("入站连接不是 TLS 套接字。"));
        return;
    }
    note(QObject::tr("对端从 %1:%2 建立 TCP 连接，等待 TLS 1.3 握手…")
             .arg(m_socket->peerAddress().toString())
             .arg(m_socket->peerPort()));
}

void PmpSyncEngine::onSslErrors(const QList<QSslError>& errors)
{
    auto* socket = qobject_cast<QSslSocket*>(sender());
    if (!socket) {
        return;
    }
    for (const QSslError& e : errors) {
        note(QObject::tr("TLS 提示（自签名证书属正常）：%1").arg(e.errorString()));
    }
    const QSslCertificate peer = socket->peerCertificate();
    if (peer.isNull()) {
        // Mutual TLS: a peer without a certificate is never acceptable.
        fail(QObject::tr("对端未提供证书；双向 TLS 要求双方都出示证书。"));
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
        fail(QObject::tr("对端证书指纹未被信任：\n%1").arg(fp));
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
        fail(QObject::tr("双向 TLS 失败：对端没有证书。"));
        return;
    }
    if (!isLanAddress(socket->peerAddress())) {
        fail(QObject::tr("对端地址 %1 不在局域网内，已拒绝。").arg(socket->peerAddress().toString()));
        return;
    }
#if QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)
    if (socket->sessionCipher().protocol() != QSsl::TlsV1_3) {
        fail(QObject::tr("协商结果不是 TLS 1.3（实际：%1），已中止。")
                 .arg(socket->sessionCipher().protocolString()));
        return;
    }
#endif
    m_peerFingerprint = QString::fromLatin1(peer.digest(QCryptographicHash::Sha256).toHex()).toLower();
    m_peerNode = m_peerFingerprint.left(16);
    note(QObject::tr("已与对端 %1 建立 TLS 1.3 加密通道（%2）")
             .arg(m_peerNode, socket->sessionCipher().name()));

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
        const QString peer = socket->peerAddress().isNull()
                                 ? m_options.host
                                 : QStringLiteral("%1:%2").arg(socket->peerAddress().toString()).arg(socket->peerPort());
        QString detail = QObject::tr("套接字错误（%1）：%2；对端 %3，本机 %4")
                             .arg(QString::number(static_cast<int>(socket->error())),
                                  socket->errorString(),
                                  peer.isEmpty() ? QStringLiteral("?") : peer,
                                  QStringLiteral("%1:%2").arg(socket->localAddress().toString()).arg(socket->localPort()));
        switch (socket->error()) {
        case QAbstractSocket::ConnectionRefusedError:
            detail += QObject::tr("\n判断：该地址/端口没有程序监听，或 Windows 防火墙拦截了入站连接。"
                                  "请在监听端允许 keepassxc.exe 通过防火墙，并确认两端端口一致。");
            break;
        case QAbstractSocket::HostNotFoundError:
            detail += QObject::tr("\n判断：对端 IP 地址有误，请使用监听设备上显示的地址。");
            break;
        case QAbstractSocket::NetworkError:
        case QAbstractSocket::SocketTimeoutError:
        case QAbstractSocket::RemoteHostClosedError:
            detail += QObject::tr("\n判断：请确认两台设备在同一 Wi‑Fi/局域网、关闭路由器 AP（客户端）隔离，"
                                  "且没有 VPN/TUN 代理（如 Clash TUN）劫持局域网流量。");
            break;
        case QAbstractSocket::SslHandshakeFailedError:
        case QAbstractSocket::SslInternalError:
            detail += QObject::tr("\n判断：TLS 1.3 双向认证失败；双方都必须出示 PmVault 证书，"
                                  "且首次提示时需信任对端指纹。");
            break;
        default:
            break;
        }
        note(QObject::tr("底层错误：%1").arg(socket->errorString()));
        fail(detail);
    }
}

void PmpSyncEngine::onTimeout()
{
    if (!m_done) {
        if (m_applied) {
            finishOk(QObject::tr("超时前同步已完成。"));
        } else {
            fail(QObject::tr("等待对端超时（监听/连接窗口结束仍未完成握手或交换）。"));
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
    // One-time removal of built-in empty templates an older build synced into root.
    m_orphanCleaned = cleanupOrphanTemplates();

    Group* root = m_db->rootGroup();
    const QList<Entry*> entries = root->entriesRecursive(false);
    for (Entry* e : entries) {
        // Plan A: the KDBX EntryTemplates group is a local authoring aid and is
        // never exchanged over the LAN.
        if (isInTemplatesGroup(e)) {
            continue;
        }
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

bool PmpSyncEngine::isInTemplatesGroup(const Entry* e) const
{
    if (!e || !m_db || !m_db->metadata()) {
        return false;
    }
    const Group* templatesGroup = m_db->metadata()->entryTemplatesGroup();
    if (!templatesGroup) {
        return false;
    }
    const Group* g = e->group();
    while (g) {
        if (g == templatesGroup) {
            return true;
        }
        g = g->parentGroup();
    }
    return false;
}

int PmpSyncEngine::cleanupOrphanTemplates()
{
    if (!m_db || !m_db->rootGroup() || !m_db->metadata()) {
        return 0;
    }
    CustomData* meta = m_db->metadata()->customData();
    if (meta->value(K_CLEANED) == QLatin1String("1")) {
        return 0;
    }

    Group* root = m_db->rootGroup();
    int removed = 0;
    // Only direct children of root are candidates: the sync merge always places
    // incoming entries in root, whereas a user's own "Notes"/"Email" entry would
    // normally live inside a named group. Combined with the origin marker and the
    // empty-credential requirement this is deliberately conservative.
    const QList<Entry*> direct = root->entries();
    for (Entry* e : direct) {
        if (!builtinTemplateTitles().contains(e->title().trimmed())) {
            continue;
        }
        if (e->customData()->value(K_ORIGIN).compare(QLatin1String("mobile"), Qt::CaseInsensitive) != 0) {
            continue;
        }
        if (!e->username().isEmpty() || !e->password().isEmpty() || !e->url().isEmpty()) {
            continue;
        }
        // No tombstone: the phone keeps these blueprints in its local templates
        // group, and both sides now exclude templates from the manifest, so a
        // local delete does not propagate and cannot delete the phone templates.
        root->removeEntry(e);
        ++removed;
    }

    meta->set(K_CLEANED, QStringLiteral("1"));
    m_db->markAsModified();
    if (removed > 0) {
        note(QObject::tr("已移除此前误同步到根分组的 %1 个内置空模板（模板仍保留在手机本地，不再参与同步）。")
                 .arg(removed));
        PmpFileLogger::log(QStringLiteral("cleanup"),
                          QStringLiteral("removed orphan templates: %1").arg(removed));
    }
    return removed;
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
        note(QObject::tr("对端已应用变更（更新 %1，删除 %2，冲突副本 %3）")
                 .arg(msg.value("upserted").toInt())
                 .arg(msg.value("deleted").toInt())
                 .arg(msg.value("copies").toInt()));
        if (m_applied) {
            QJsonObject bye;
            bye["type"] = MSG_BYE;
            sendJson(bye);
            finishOk(QObject::tr("双向同步完成。"));
        }
        return;
    }

    if (type == MSG_BYE) {
        if (m_applied) {
            finishOk(QObject::tr("双向同步完成。"));
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
            // Defensive: never accept built-in empty templates from a peer that
            // still runs an older build that synced them.
            if (snapshotIsEmptyTemplate(a.snap.fields)) {
                PmpFileLogger::log(QStringLiteral("skip"),
                                  QStringLiteral("reject incoming empty template"));
                continue;
            }
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
                title + QObject::tr("（冲突副本 %1）").arg(m_peerNode.left(6));
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

    if (deleted > 0 || upserted > 0 || copies > 0 || m_orphanCleaned > 0) {
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
                                    PmpAuditLog::TgtLanPeer,
                                    QStringLiteral("peer=%1 up=%2 del=%3 copies=%4")
                                        .arg(m_peerNode).arg(upserted).arg(deleted).arg(copies).toUtf8());

    QJsonObject applied;
    applied["type"] = MSG_APPLIED;
    applied["upserted"] = upserted;
    applied["deleted"] = deleted;
    applied["copies"] = copies;
    sendJson(applied);

    note(QObject::tr("本机已合并：更新 %1 条，删除 %2 条，冲突副本 %3 条。")
             .arg(upserted)
             .arg(deleted)
             .arg(copies));

    if (m_peerApplied) {
        QJsonObject bye;
        bye["type"] = MSG_BYE;
        sendJson(bye);
        finishOk(QObject::tr("双向同步完成。"));
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
    const QByteArray detail = (traceTail() + QStringLiteral(" || ") + message).toUtf8();
    PmpFileLogger::log(QStringLiteral("fail"), message);
    PmpAuditLog::instance()->record(PmpAuditLog::EvSyncFailed, PmpAuditLog::OcFailure, PmpAuditLog::FldNone,
                                    PmpAuditLog::TgtLanPeer, detail.left(600));
    m_report.ok = false;
    m_report.message = message;
    m_report.peerNode = m_peerNode;
    m_report.peerFingerprint = m_peerFingerprint;
    note(QObject::tr("同步失败：%1").arg(message));
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
    note(message);
    emit finished(m_report);
}
