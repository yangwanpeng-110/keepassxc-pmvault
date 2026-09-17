/*
 * PmVault extensions - per-device TLS identity implementation.
 */

#include "PmpIdentity.h"

#include "PmpCrypto.h"
#include "PmpPlatform.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <QSsl>

#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/exceptn.h>
#include <botan/pem.h>
#include <botan/pkcs8.h>
#include <botan/x509self.h>

namespace
{
    const QByteArray ID_AAD = "PmVault/sync-identity/v1";

    QString identityPath()
    {
        return PmpPlatform::ensureSubDir("sync") + "/identity.enc";
    }

    PmpIdentity generateIdentity()
    {
        PmpIdentity id;
        Botan::AutoSeeded_RNG rng;
        Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("secp256r1"));

        Botan::X509_Cert_Options opts("PmVault");
#if defined(BOTAN_VERSION_MAJOR) && BOTAN_VERSION_MAJOR >= 3
        // Botan 3 turns Key_Constraints into a class whose Bits enum is nested;
        // combine the bits through the uint32_t constructor. Botan 2 instead
        // exposes the shouting-case constants in the Botan namespace.
        const Botan::Key_Constraints constraints(
            static_cast<uint32_t>(Botan::Key_Constraints::DigitalSignature) |
            static_cast<uint32_t>(Botan::Key_Constraints::KeyAgreement));
        opts.add_constraints(constraints);
#else
        opts.add_constraints(Botan::Key_Constraints(Botan::DIGITAL_SIGNATURE | Botan::KEY_AGREEMENT));
#endif
        Botan::X509_Certificate cert = Botan::X509::create_self_signed_cert(opts, key, "SHA-256", rng);

        const std::string certDer = Botan::PEM_Code::encode(cert.BER_encode(), "CERTIFICATE");
        const std::string keyPem = Botan::PKCS8::PEM_encode(key);
        const std::string fp = cert.fingerprint("SHA-256"); // colon-separated hex

        id.certPem = QByteArray::fromStdString(certDer);
        id.keyPem = QByteArray::fromStdString(keyPem);
        id.nodeId = QString::fromStdString(fp).remove(':').toLower().left(16);
        id.certificate = QSslCertificate(id.certPem, QSsl::Pem);
        id.privateKey = QSslKey(id.keyPem, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);
        return id;
    }
} // namespace

PmpIdentity PmpIdentityStore::loadOrCreate()
{
    const QByteArray key = PmpPlatform::deriveKey("sync-identity");
    QFile f(identityPath());
    if (f.open(QIODevice::ReadOnly)) {
        const QByteArray sealed = QByteArray::fromBase64(f.readAll().trimmed());
        QByteArray plain;
        if (PmpCrypto::aesGcmOpen(key, sealed, ID_AAD, plain)) {
            const auto obj = QJsonDocument::fromJson(plain).object();
            PmpIdentity id;
            id.nodeId = obj.value("node").toString();
            id.certPem = obj.value("cert").toString().toUtf8();
            id.keyPem = obj.value("key").toString().toUtf8();
            id.certificate = QSslCertificate(id.certPem, QSsl::Pem);
            id.privateKey = QSslKey(id.keyPem, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);
            if (id.valid()) {
                return id;
            }
        }
    }

    PmpIdentity id = generateIdentity();
    if (!id.valid()) {
        return id;
    }
    QJsonObject obj;
    obj["node"] = id.nodeId;
    obj["cert"] = QString::fromUtf8(id.certPem);
    obj["key"] = QString::fromUtf8(id.keyPem);
    const QByteArray sealed = PmpCrypto::aesGcmSeal(key, QJsonDocument(obj).toJson(QJsonDocument::Compact), ID_AAD);
    if (QFile out(identityPath()); out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        out.write(sealed.toBase64());
        out.close();
    }
    return id;
}

QString PmpIdentityStore::fullFingerprint(const PmpIdentity& id)
{
    if (id.certificate.isNull()) {
        return {};
    }
    return QString::fromLatin1(id.certificate.digest(QCryptographicHash::Sha256).toHex()).toLower();
}
