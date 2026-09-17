/*
 * PmVault extensions - encrypted hash-chain audit log implementation.
 */

#include "PmpAuditLog.h"

#include "PmpCrypto.h"
#include "PmpPlatform.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QStringList>

#include <algorithm>

namespace
{
    const QByteArray ANCHOR_AAD = "PmVault/audit-anchor/v1";
    const int ARCHIVE_KEEP = 5;

    QByteArray zeroLink()
    {
        return QByteArray(32, '\0');
    }
} // namespace

PmpAuditLog* PmpAuditLog::instance()
{
    static PmpAuditLog s_inst;
    return &s_inst;
}

QString PmpAuditLog::idFor(const QString& databaseFilePath) const
{
    return PmpPlatform::dbId(databaseFilePath).left(16);
}

QString PmpAuditLog::logPathFor(const QString& id16) const
{
    return PmpPlatform::ensureSubDir("audit") + "/" + id16 + ".logx";
}

QString PmpAuditLog::anchorPathFor(const QString& id16) const
{
    return PmpPlatform::ensureSubDir("audit") + "/" + id16 + ".anchor";
}

QByteArray PmpAuditLog::logKey(const QString& id16) const
{
    return PmpPlatform::deriveKey(("audit-log:" + id16).toUtf8());
}

QByteArray PmpAuditLog::chainKey(const QString& id16) const
{
    return PmpPlatform::deriveKey(("audit-chain:" + id16).toUtf8());
}

QByteArray PmpAuditLog::genesisLink()
{
    return zeroLink();
}

QByteArray PmpAuditLog::sealRecord(const QByteArray& key, const QByteArray& plain, const QByteArray& prevLink)
{
    return PmpCrypto::aesGcmSeal(key, plain, prevLink);
}

bool PmpAuditLog::openRecord(const QByteArray& key, const QByteArray& frame, const QByteArray& prevLink,
                             QByteArray& plain)
{
    const QByteArray sealed = PmpCrypto::fromB64(QString::fromLatin1(frame.trimmed()));
    if (sealed.isEmpty()) {
        return false;
    }
    return PmpCrypto::aesGcmOpen(key, sealed, prevLink, plain);
}

QByteArray PmpAuditLog::encodePlain(const Record& r, const QString& id16, const QByteArray& prevAnchor)
{
    // Fixed, delimiter-separated, all-numeric/enumerated record. No free text.
    return QString("v1|%1|%2|%3|%4|%5|%6|%7|%8")
        .arg(r.seq)
        .arg(r.ts)
        .arg(r.event)
        .arg(r.outcome)
        .arg(r.field)
        .arg(r.target)
        .arg(id16)
        .arg(QString::fromLatin1(prevAnchor.toHex()))
        .toUtf8();
}

bool PmpAuditLog::decodePlain(const QByteArray& plain, Record& r, QString& id16, QByteArray& prevAnchor)
{
    const auto parts = QString::fromUtf8(plain).split('|');
    if (parts.size() < 9 || parts[0] != QLatin1String("v1")) {
        return false;
    }
    r.seq = parts[1].toULongLong();
    r.ts = parts[2].toULongLong();
    r.event = parts[3].toInt();
    r.outcome = parts[4].toInt();
    r.field = parts[5].toInt();
    r.target = parts[6].toInt();
    id16 = parts[7];
    r.dbId = id16;
    prevAnchor = QByteArray::fromHex(parts[8].toLatin1());
    return true;
}

PmpAuditLog::ChainState PmpAuditLog::replay(const QString& id16, int* readable) const
{
    ChainState st;
    st.link = genesisLink();
    int count = 0;

    QFile f(logPathFor(id16));
    if (f.open(QIODevice::ReadOnly)) {
        const QByteArray key = logKey(id16);
        const QByteArray ckey = chainKey(id16);
        while (!f.atEnd()) {
            const QByteArray line = f.readLine();
            if (line.trimmed().isEmpty()) {
                continue;
            }
            QByteArray plain;
            if (!openRecord(key, line, st.link, plain)) {
                break; // chain broken here; following records are untrusted
            }
            Record rec;
            QString rid;
            QByteArray prevAnchor;
            if (!decodePlain(plain, rec, rid, prevAnchor)) {
                break;
            }
            const QByteArray sealed = PmpCrypto::fromB64(QString::fromLatin1(line.trimmed()));
            st.link = PmpCrypto::hmacSha256(ckey, st.link + sealed);
            st.seq = rec.seq;
            ++count;
        }
    }
    if (readable) {
        *readable = count;
    }
    return st;
}

void PmpAuditLog::bindDatabase(const QString& databaseFilePath)
{
    QMutexLocker lock(&m_mutex);
    m_currentPath = databaseFilePath;
    m_currentId = idFor(databaseFilePath);
    m_loaded = true;
    const ChainState st = replay(m_currentId);
    m_lastSeq = st.seq;
    m_lastLink = st.link;
    pruneArchives(m_currentId);
}

void PmpAuditLog::closeDatabase()
{
    QMutexLocker lock(&m_mutex);
    m_currentPath.clear();
    m_currentId.clear();
    m_loaded = false;
    m_lastSeq = 0;
    m_lastLink = genesisLink();
}

void PmpAuditLog::setVerboseEnabled(bool enabled)
{
    QMutexLocker lock(&m_mutex);
    m_verbose = enabled;
}

void PmpAuditLog::setLimits(int retentionDays, qint64 maxBytes)
{
    QMutexLocker lock(&m_mutex);
    m_retentionDays = retentionDays > 0 ? retentionDays : 90;
    m_maxBytes = maxBytes > 0 ? maxBytes : 10LL * 1024 * 1024;
}

static bool isSecurityCritical(int event)
{
    switch (event) {
    case PmpAuditLog::EvUnlock:
    case PmpAuditLog::EvUnlockFailed:
    case PmpAuditLog::EvTwoFactor:
    case PmpAuditLog::EvTwoFactorFailed:
    case PmpAuditLog::EvTwoFactorEnroll:
    case PmpAuditLog::EvTwoFactorUnenroll:
    case PmpAuditLog::EvLock:
    case PmpAuditLog::EvPasswordChange:
    case PmpAuditLog::EvSync:
    case PmpAuditLog::EvSyncFailed:
    case PmpAuditLog::EvLogRotate:
        return true;
    default:
        return false;
    }
}

void PmpAuditLog::writeAnchor(const QString& id16, const ChainState& st) const
{
    const QByteArray plain = QString("%1|%2").arg(st.seq).arg(QString::fromLatin1(st.link.toHex())).toUtf8();
    const QByteArray sealed = PmpCrypto::aesGcmSeal(logKey(id16), plain, ANCHOR_AAD);

    QSaveFile f(anchorPathFor(id16));
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(sealed.toBase64());
        f.write("\n");
        f.commit();
    }
}

void PmpAuditLog::pruneArchives(const QString& id16) const
{
    QDir dir(PmpPlatform::ensureSubDir("audit"));
    const QString prefix = id16 + ".logx.";
    QFileInfoList archives;
    const auto entries = dir.entryInfoList(QDir::Files);
    for (const QFileInfo& fi : entries) {
        if (fi.fileName().startsWith(prefix)) {
            archives.append(fi);
        }
    }

    // Age-based retention.
    const QDateTime cutoff = QDateTime::currentDateTime().addDays(-m_retentionDays);
    for (const QFileInfo& fi : archives) {
        if (fi.lastModified() < cutoff) {
            QFile::remove(fi.absoluteFilePath());
        }
    }

    // Count-based cap: keep only the newest ARCHIVE_KEEP.
    archives = dir.entryInfoList(QDir::Files).mid(0); // refresh
    QFileInfoList kept;
    for (const QFileInfo& fi : dir.entryInfoList(QDir::Files)) {
        if (fi.fileName().startsWith(prefix)) {
            kept.append(fi);
        }
    }
    std::sort(kept.begin(), kept.end(), [](const QFileInfo& a, const QFileInfo& b) {
        return a.lastModified() > b.lastModified();
    });
    for (int i = ARCHIVE_KEEP; i < kept.size(); ++i) {
        QFile::remove(kept[i].absoluteFilePath());
    }
}

void PmpAuditLog::rotateIfNeeded(const QString& id16, const QByteArray& lastLink)
{
    const QString path = logPathFor(id16);
    QFileInfo fi(path);
    if (!fi.exists() || fi.size() < m_maxBytes) {
        return;
    }

    // Archive the current file, then start a new one with a rotate record whose
    // prevAnchor carries the previous file's final link (cross-file chain).
    const QString archive = path + "." + QString::number(QDateTime::currentMSecsSinceEpoch());
    QFile::rename(path, archive);
    pruneArchives(id16);

    Record rec;
    rec.seq = m_lastSeq + 1;
    rec.ts = QDateTime::currentMSecsSinceEpoch();
    rec.event = EvLogRotate;
    rec.outcome = OcInfo;

    const QByteArray plain = encodePlain(rec, id16, lastLink);
    const QByteArray sealed = sealRecord(logKey(id16), plain, lastLink);

    QFile out(path);
    if (out.open(QIODevice::WriteOnly | QIODevice::Append)) {
        out.write(sealed.toBase64());
        out.write("\n");
        out.flush();
    }
    m_lastLink = PmpCrypto::hmacSha256(chainKey(id16), lastLink + sealed);
    m_lastSeq = rec.seq;
    ChainState st;
    st.seq = m_lastSeq;
    st.link = m_lastLink;
    writeAnchor(id16, st);
}

void PmpAuditLog::record(Event event, Outcome outcome, Field field, Target target)
{
    QMutexLocker lock(&m_mutex);
    if (!m_loaded || m_currentId.isEmpty()) {
        return;
    }
    if (!m_verbose && !isSecurityCritical(event)) {
        return;
    }

    rotateIfNeeded(m_currentId, m_lastLink);

    Record rec;
    rec.seq = m_lastSeq + 1;
    rec.ts = QDateTime::currentMSecsSinceEpoch();
    rec.event = event;
    rec.outcome = outcome;
    rec.field = field;
    rec.target = target;
    rec.dbId = m_currentId;

    const QByteArray prevLink = m_lastLink;
    const QByteArray plain = encodePlain(rec, m_currentId, QByteArray());
    const QByteArray sealed = sealRecord(logKey(m_currentId), plain, prevLink);

    QFile out(logPathFor(m_currentId));
    if (!out.open(QIODevice::WriteOnly | QIODevice::Append)) {
        return;
    }
    out.write(sealed.toBase64());
    out.write("\n");
    out.flush();

    m_lastLink = PmpCrypto::hmacSha256(chainKey(m_currentId), prevLink + sealed);
    m_lastSeq = rec.seq;

    ChainState st;
    st.seq = m_lastSeq;
    st.link = m_lastLink;
    writeAnchor(m_currentId, st);
}

PmpAuditLog::VerifyResult PmpAuditLog::verify(const QString& databaseFilePath) const
{
    QMutexLocker lock(&m_mutex);
    const QString id16 = databaseFilePath.isEmpty() ? m_currentId : idFor(databaseFilePath);
    VerifyResult res;
    if (id16.isEmpty()) {
        res.message = QObject::tr("No database bound to the audit log.");
        return res;
    }

    int readable = 0;
    const ChainState st = replay(id16, &readable);
    res.readableCount = readable;
    res.lastSeq = st.seq;

    // Total physical lines.
    int total = 0;
    QFile f(logPathFor(id16));
    if (f.open(QIODevice::ReadOnly)) {
        while (!f.atEnd()) {
            if (!f.readLine().trimmed().isEmpty()) {
                ++total;
            }
        }
    }
    res.chainOk = (readable == total);

    // Anchor check.
    QFile af(anchorPathFor(id16));
    if (af.open(QIODevice::ReadOnly)) {
        const QByteArray sealed = QByteArray::fromBase64(af.readAll().trimmed());
        QByteArray plain;
        if (PmpCrypto::aesGcmOpen(logKey(id16), sealed, ANCHOR_AAD, plain)) {
            const auto parts = QString::fromUtf8(plain).split('|');
            if (parts.size() == 2) {
                const qulonglong anchorSeq = parts[0].toULongLong();
                const QByteArray anchorLink = QByteArray::fromHex(parts[1].toLatin1());
                res.anchorOk = (anchorSeq == st.seq && anchorLink == st.link);
            }
        }
    }
    res.truncated = res.chainOk && !res.anchorOk;

    if (res.chainOk && res.anchorOk) {
        res.message = QObject::tr("Audit chain intact: %n record(s).", nullptr, readable);
    } else if (!res.chainOk) {
        res.message = QObject::tr("Tampering detected: chain breaks at record %1 of %2.")
                          .arg(readable + 1)
                          .arg(total);
    } else {
        res.message = QObject::tr("Truncation detected: the log tail does not match the integrity anchor.");
    }
    return res;
}

QVector<PmpAuditLog::Record> PmpAuditLog::readAll(const QString& databaseFilePath, int maxRecords) const
{
    QMutexLocker lock(&m_mutex);
    const QString id16 = databaseFilePath.isEmpty() ? m_currentId : idFor(databaseFilePath);
    QVector<Record> out;
    if (id16.isEmpty()) {
        return out;
    }
    QByteArray link = genesisLink();
    QFile f(logPathFor(id16));
    if (!f.open(QIODevice::ReadOnly)) {
        return out;
    }
    const QByteArray key = logKey(id16);
    const QByteArray ckey = chainKey(id16);
    while (!f.atEnd() && out.size() < maxRecords) {
        const QByteArray line = f.readLine();
        if (line.trimmed().isEmpty()) {
            continue;
        }
        QByteArray plain;
        if (!openRecord(key, line, link, plain)) {
            break;
        }
        Record rec;
        QString rid;
        QByteArray prevAnchor;
        if (!decodePlain(plain, rec, rid, prevAnchor)) {
            break;
        }
        const QByteArray sealed = PmpCrypto::fromB64(QString::fromLatin1(line.trimmed()));
        link = PmpCrypto::hmacSha256(ckey, link + sealed);
        out.append(rec);
    }
    return out;
}

QString PmpAuditLog::eventName(int e)
{
    switch (e) {
    case EvUnlock:
        return QObject::tr("Unlock");
    case EvUnlockFailed:
        return QObject::tr("Unlock failed");
    case EvTwoFactor:
        return QObject::tr("Second factor");
    case EvTwoFactorFailed:
        return QObject::tr("Second factor failed");
    case EvTwoFactorEnroll:
        return QObject::tr("Second factor enrolled");
    case EvTwoFactorUnenroll:
        return QObject::tr("Second factor removed");
    case EvLock:
        return QObject::tr("Lock");
    case EvPasswordChange:
        return QObject::tr("Password changed");
    case EvCopy:
        return QObject::tr("Copy");
    case EvBrowserFill:
        return QObject::tr("Browser DOM fill");
    case EvAutoType:
        return QObject::tr("Auto-Type");
    case EvSync:
        return QObject::tr("LAN sync");
    case EvSyncFailed:
        return QObject::tr("LAN sync failed");
    case EvConfigChange:
        return QObject::tr("Configuration changed");
    case EvLogRotate:
        return QObject::tr("Log rotated");
    default:
        return QObject::tr("Unknown");
    }
}

QString PmpAuditLog::outcomeName(int o)
{
    switch (o) {
    case OcSuccess:
        return QObject::tr("Success");
    case OcFailure:
        return QObject::tr("Failure");
    case OcDenied:
        return QObject::tr("Denied");
    default:
        return QObject::tr("Info");
    }
}

QString PmpAuditLog::fieldName(int f)
{
    switch (f) {
    case FldUsername:
        return QObject::tr("username");
    case FldPassword:
        return QObject::tr("password");
    case FldTotp:
        return QObject::tr("TOTP");
    case FldUrl:
        return QObject::tr("URL");
    case FldNotes:
        return QObject::tr("notes");
    case FldOther:
        return QObject::tr("other");
    default:
        return QString();
    }
}

QString PmpAuditLog::targetName(int t)
{
    switch (t) {
    case TgtLocalDatabase:
        return QObject::tr("local database");
    case TgtBrowserDom:
        return QObject::tr("browser DOM");
    case TgtDesktopWindow:
        return QObject::tr("desktop window");
    case TgtLanPeer:
        return QObject::tr("LAN peer");
    default:
        return QString();
    }
}
