/*
 * PmVault extensions - platform abstraction implementation.
 * See PmpPlatform.h for the security model.
 */

#include "PmpPlatform.h"

#include "PmpCrypto.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcessEnvironment>
#include <QStandardPaths>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wincrypt.h>

namespace
{
    // DPAPI blob wrapper. Returns an empty byte array on failure.
    QByteArray dpapi(const QByteArray& in, bool encrypt)
    {
        DATA_BLOB inBlob{static_cast<DWORD>(in.size()),
                         reinterpret_cast<BYTE*>(const_cast<char*>(in.constData()))};
        DATA_BLOB outBlob{};
        BOOL ok = encrypt
                      ? CryptProtectData(&inBlob, L"PmVaultDeviceKey", nullptr, nullptr, nullptr, 0, &outBlob)
                      : CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob);
        if (!ok) {
            return {};
        }
        QByteArray out(reinterpret_cast<const char*>(outBlob.pbData), static_cast<int>(outBlob.cbData));
        LocalFree(outBlob.pbData);
        return out;
    }
} // namespace
#endif

QString PmpPlatform::appDataDir()
{
    QString base;
#ifdef Q_OS_WIN
    base = QProcessEnvironment::systemEnvironment().value("APPDATA");
    if (base.isEmpty()) {
        base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    }
#else
    base = QDir::homePath() + "/.local/share";
#endif
    QString dir = base + "/PmVault";
    QDir().mkpath(dir);
    return dir;
}

QString PmpPlatform::ensureSubDir(const QString& name)
{
    QString dir = appDataDir() + "/" + name;
    QDir().mkpath(dir);
    return dir;
}

QByteArray PmpPlatform::deviceKey()
{
    const QString keyFile = appDataDir() + "/device.key";
    QFile f(keyFile);

#ifdef Q_OS_WIN
    if (f.open(QIODevice::ReadOnly)) {
        const QByteArray key = dpapi(f.readAll(), false);
        if (key.size() == KeySize) {
            return key;
        }
    }
    const QByteArray raw = PmpCrypto::randomBytes(KeySize);
    const QByteArray blob = dpapi(raw, true);
    if (!blob.isEmpty()) {
        QFile out(keyFile);
        if (out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            out.write(blob);
            out.close();
        }
    }
    return raw;
#else
    if (f.open(QIODevice::ReadOnly)) {
        const QByteArray key = f.readAll();
        if (key.size() == KeySize) {
            return key;
        }
    }
    const QByteArray raw = PmpCrypto::randomBytes(KeySize);
    QFile out(keyFile);
    if (out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        out.write(raw);
        out.close();
    }
    QFile::setPermissions(keyFile, QFile::ReadOwner | QFile::WriteOwner);
    return raw;
#endif
}

QByteArray PmpPlatform::deriveKey(const QByteArray& domain, int len)
{
    return PmpCrypto::hkdf(deviceKey(), QByteArrayLiteral("PmVault/v1"), domain, len);
}

QString PmpPlatform::dbId(const QString& databaseFilePath)
{
    // Normalise the absolute path so the identifier is stable, then hash it.
    const QString canonical = QFileInfo(databaseFilePath).absoluteFilePath();
    return PmpCrypto::toHex(PmpCrypto::sha256(("db:" + canonical).toUtf8())).left(32);
}
