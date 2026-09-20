/*
 * PmVault extensions - TOTP second-factor unlock gate implementation.
 */

#include "PmpTwoFactor.h"

#include "PmpAuditLog.h"
#include "PmpCrypto.h"
#include "PmpPlatform.h"
#include "core/Base32.h"
#include "core/Totp.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QUrl>

namespace
{
    const QByteArray VAULT_AAD = "PmVault/twofa-vault/v1";

    QString normalizeCode(const QString& in)
    {
        QString out;
        for (const QChar ch : in) {
            if (ch.isDigit()) {
                out.append(ch);
            }
        }
        return out;
    }
} // namespace

PmpTwoFactor* PmpTwoFactor::instance()
{
    static PmpTwoFactor s_inst;
    return &s_inst;
}

QString PmpTwoFactor::idFor(const QString& databaseFilePath) const
{
    return PmpPlatform::dbId(databaseFilePath).left(16);
}

QString PmpTwoFactor::vaultPathFor(const QString& id16) const
{
    return PmpPlatform::ensureSubDir("twofa") + "/" + id16 + ".vault";
}

bool PmpTwoFactor::loadVault(const QString& id16, Vault& vault) const
{
    QFile f(vaultPathFor(id16));
    if (!f.open(QIODevice::ReadOnly)) {
        return false;
    }
    const QByteArray sealed = QByteArray::fromBase64(f.readAll().trimmed());
    const QByteArray key = PmpPlatform::deriveKey(("twofa:" + id16).toUtf8());
    QByteArray plain;
    if (!PmpCrypto::aesGcmOpen(key, sealed, VAULT_AAD, plain)) {
        return false;
    }
    const auto obj = QJsonDocument::fromJson(plain).object();
    vault.enabled = obj.value("enabled").toBool();
    vault.secretB32 = obj.value("secret").toString();
    vault.lastCounter = static_cast<qulonglong>(obj.value("lastCounter").toDouble());
    vault.failCount = obj.value("failCount").toInt();
    vault.lockUntilMs = static_cast<qlonglong>(obj.value("lockUntil").toDouble());
    vault.enrolledAtMs = static_cast<qlonglong>(obj.value("enrolledAt").toDouble());
    return vault.enabled && !vault.secretB32.isEmpty();
}

bool PmpTwoFactor::saveVault(const QString& id16, const Vault& vault) const
{
    QJsonObject obj;
    obj["enabled"] = vault.enabled;
    obj["secret"] = vault.secretB32;
    obj["lastCounter"] = static_cast<double>(vault.lastCounter);
    obj["failCount"] = vault.failCount;
    obj["lockUntil"] = static_cast<double>(vault.lockUntilMs);
    obj["enrolledAt"] = static_cast<double>(vault.enrolledAtMs);
    const QByteArray plain = QJsonDocument(obj).toJson(QJsonDocument::Compact);

    const QByteArray key = PmpPlatform::deriveKey(("twofa:" + id16).toUtf8());
    const QByteArray sealed = PmpCrypto::aesGcmSeal(key, plain, VAULT_AAD);

    QFile f(vaultPathFor(id16));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }
    f.write(sealed.toBase64());
    f.close();
    return true;
}

QString PmpTwoFactor::generateTotp(const QString& secretB32, qulonglong epochSeconds, bool* valid)
{
    auto settings = Totp::createSettings(secretB32, Digits, Step);
    return Totp::generateTotp(settings, valid, epochSeconds);
}

bool PmpTwoFactor::constantTimeEqual(const QString& a, const QString& b)
{
    const QByteArray ab = a.toUtf8();
    const QByteArray bb = b.toUtf8();
    const int n = ab.size();
    unsigned char diff = static_cast<unsigned char>(n ^ bb.size());
    for (int i = 0; i < n && i < bb.size(); ++i) {
        diff |= static_cast<unsigned char>(ab[i] ^ bb[i]);
    }
    return diff == 0 && ab.size() == bb.size();
}

bool PmpTwoFactor::isEnrolled(const QString& databaseFilePath) const
{
    Vault v;
    return loadVault(idFor(databaseFilePath), v);
}

PmpTwoFactor::EnrollStart PmpTwoFactor::beginEnroll(const QString& databaseFilePath, const QString& label)
{
    const QString id16 = idFor(databaseFilePath);
    // 160-bit seed, RFC 4648 base32 (A-Z 2-7), uppercase, no padding.
    const QByteArray raw = PmpCrypto::randomBytes(20);
    QString secret = QString::fromLatin1(Base32::encode(raw)).toUpper();
    secret.remove('=');

    const QString safeLabel = label.isEmpty() ? QStringLiteral("database") : label;
    const QString uri =
        QString("otpauth://totp/PmVault:%1?secret=%2&issuer=PmVault&algorithm=SHA1&digits=%3&period=%4")
            .arg(QString::fromLatin1(QUrl::toPercentEncoding(safeLabel)), secret)
            .arg(Digits)
            .arg(Step);

    EnrollStart start{secret, uri};
    m_pending.insert(id16, start);
    return start;
}

bool PmpTwoFactor::confirmEnroll(const QString& databaseFilePath, const QString& code, QString& error)
{
    const QString id16 = idFor(databaseFilePath);
    if (!m_pending.contains(id16)) {
        error = QObject::tr("当前没有进行中的启用流程，请重新开始启用。");
        return false;
    }
    const QString secret = m_pending.value(id16).secretB32;
    const QString entered = normalizeCode(code);
    const qulonglong nowSec = QDateTime::currentMSecsSinceEpoch() / 1000;

    bool matched = false;
    qulonglong matchedCounter = 0;
    for (int off = -1; off <= 1 && !matched; ++off) {
        const qlonglong c = static_cast<qlonglong>(nowSec / Step) + off;
        if (c < 0) {
            continue;
        }
        bool valid = false;
        const QString expected = generateTotp(secret, static_cast<qulonglong>(c) * Step, &valid);
        if (valid && constantTimeEqual(expected, entered)) {
            matched = true;
            matchedCounter = static_cast<qulonglong>(c);
        }
    }
    if (!matched) {
        error = QObject::tr("验证码不正确，请扫描二维码后重试。");
        return false;
    }

    Vault v;
    v.enabled = true;
    v.secretB32 = secret;
    v.lastCounter = matchedCounter;
    v.failCount = 0;
    v.lockUntilMs = 0;
    v.enrolledAtMs = QDateTime::currentMSecsSinceEpoch();
    if (!saveVault(id16, v)) {
        error = QObject::tr("无法写入本机第二因素保险库。");
        return false;
    }
    m_pending.remove(id16);
    PmpAuditLog::instance()->bindDatabase(databaseFilePath);
    PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactorEnroll, PmpAuditLog::OcSuccess,
                                    PmpAuditLog::FldNone, PmpAuditLog::TgtLocalDatabase);
    return true;
}

void PmpTwoFactor::removeEnrollment(const QString& databaseFilePath)
{
    const QString id16 = idFor(databaseFilePath);
    if (QFile::remove(vaultPathFor(id16))) {
        PmpAuditLog::instance()->bindDatabase(databaseFilePath);
        PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactorUnenroll, PmpAuditLog::OcSuccess,
                                        PmpAuditLog::FldNone, PmpAuditLog::TgtLocalDatabase);
    }
    m_pending.remove(id16);
}

PmpTwoFactor::VerifyResult PmpTwoFactor::verifyInteractive(const QString& databaseFilePath,
                                                           const QString& code, QString& error)
{
    const QString id16 = idFor(databaseFilePath);
    Vault v;
    if (!loadVault(id16, v)) {
        return NotEnrolled;
    }

    PmpAuditLog::instance()->bindDatabase(databaseFilePath);
    const qlonglong now = QDateTime::currentMSecsSinceEpoch();
    if (v.lockUntilMs > now) {
        const qint64 secs = (v.lockUntilMs - now + 999) / 1000;
        error = QObject::tr("失败次数过多，请在 %n 秒后再试。", nullptr, int(secs));
        PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactorFailed, PmpAuditLog::OcDenied,
                                        PmpAuditLog::FldTotp, PmpAuditLog::TgtLocalDatabase);
        return Locked;
    }

    const QString entered = normalizeCode(code);
    if (entered.size() != Digits) {
        error = QObject::tr("请输入 %1 位数字验证码。").arg(Digits);
        return Wrong;
    }

    const qulonglong nowSec = now / 1000;
    bool matched = false;
    qulonglong matchedCounter = 0;
    for (int off = -1; off <= 1 && !matched; ++off) {
        const qlonglong c = static_cast<qlonglong>(nowSec / Step) + off;
        if (c < 0) {
            continue;
        }
        bool valid = false;
        const QString expected = generateTotp(v.secretB32, static_cast<qulonglong>(c) * Step, &valid);
        if (valid && constantTimeEqual(expected, entered)) {
            matched = true;
            matchedCounter = static_cast<qulonglong>(c);
        }
    }

    if (matched && static_cast<qlonglong>(matchedCounter) <= static_cast<qlonglong>(v.lastCounter)) {
        error = QObject::tr("该验证码已被使用，请等待下一个验证码。");
        PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactorFailed, PmpAuditLog::OcDenied,
                                        PmpAuditLog::FldTotp, PmpAuditLog::TgtLocalDatabase);
        return Replay;
    }

    if (matched) {
        v.lastCounter = qMax(v.lastCounter, matchedCounter);
        v.failCount = 0;
        v.lockUntilMs = 0;
        saveVault(id16, v);
        PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactor, PmpAuditLog::OcSuccess,
                                        PmpAuditLog::FldTotp, PmpAuditLog::TgtLocalDatabase);
        return Ok;
    }

    // Wrong code: exponential back-off, then temporary hard lock.
    v.failCount += 1;
    if (v.failCount >= HardLockFailures) {
        v.lockUntilMs = now + 15 * 60 * 1000; // 15 minute hard lock
    } else {
        const int shift = qMin(v.failCount - 1, 5);
        const qlonglong delay = qMin<qlonglong>(2000LL * (1LL << shift), 60000LL);
        v.lockUntilMs = now + delay;
    }
    saveVault(id16, v);
    const qint64 secs = (v.lockUntilMs - now + 999) / 1000;
    error = QObject::tr("验证码不正确，距离更长时间锁定还剩 %1 次机会；请在 %2 秒后重试。")
                .arg(qMax(0, HardLockFailures - v.failCount))
                .arg(secs);
    PmpAuditLog::instance()->record(PmpAuditLog::EvTwoFactorFailed, PmpAuditLog::OcFailure,
                                    PmpAuditLog::FldTotp, PmpAuditLog::TgtLocalDatabase);
    return Wrong;
}

int PmpTwoFactor::failCount(const QString& databaseFilePath) const
{
    Vault v;
    return loadVault(idFor(databaseFilePath), v) ? v.failCount : 0;
}

qint64 PmpTwoFactor::lockedSecondsRemaining(const QString& databaseFilePath) const
{
    Vault v;
    if (!loadVault(idFor(databaseFilePath), v)) {
        return 0;
    }
    const qlonglong now = QDateTime::currentMSecsSinceEpoch();
    return v.lockUntilMs > now ? (v.lockUntilMs - now + 999) / 1000 : 0;
}
