/*
 * PmVault extensions - per-device TLS identity implementation.
 *
 * An RSA-2048 self-signed certificate is generated once. RSA is used (rather
 * than ECDSA) because it is available in every Botan build, which removes an
 * entire class of first-run failures on minimal crypto packages. Its SHA-256
 * fingerprint (first 16 hex chars) is the node id used in vector clocks and for
 * certificate pinning. The private key PEM is stored locally encrypted with the
 * device key (DPAPI-bound on Windows); it never enters the KDBX file.
 *
 * Every operation that touches the crypto or TLS stack is wrapped in
 * try/catch: a failure here must surface as an invalid identity (and a friendly
 * error in the UI), never as an uncaught exception terminating the program.
 */

#include "PmpIdentity.h"

#include "PmpCrypto.h"
#include "PmpPlatform.h"

#include <QFile>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <QSsl>
#include <QSslSocket>

#include <botan/auto_rng.h>
#include <botan/exceptn.h>
#include <botan/pem.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/x509self.h>

#include <exception>

namespace
{
    const QByteArray ID_AAD = "PmVault/sync-identity/v1";

    QString identityPath()
    {
        return PmpPlatform::ensureSubDir("sync") + "/identity.enc";
    }

    // Returns an invalid (empty) PmpIdentity on any failure; never throws.
    PmpIdentity generateIdentity()
    {
        PmpIdentity id;
        try {
            Botan::AutoSeeded_RNG rng;
            Botan::RSA_PrivateKey key(rng, 2048);

            Botan::X509_Cert_Options opts("PmVault");
#if defined(BOTAN_VERSION_MAJOR) && BOTAN_VERSION_MAJOR >= 3
            // Botan 3 turns Key_Constraints into a class whose Bits enum is
            // nested. DigitalSignature alone is sufficient for a TLS 1.3 client
            // certificate (the key only signs the handshake).
            const Botan::Key_Constraints constraints(
                static_cast<uint32_t>(Botan::Key_Constraints::DigitalSignature));
            opts.add_constraints(constraints);
#else
            opts.add_constraints(Botan::Key_Constraints(Botan::DIGITAL_SIGNATURE));
#endif
            Botan::X509_Certificate cert = Botan::X509::create_self_signed_cert(opts, key, "SHA-256", rng);

            const std::string certDer = Botan::PEM_Code::encode(cert.BER_encode(), "CERTIFICATE");
            const std::string keyPem = Botan::PKCS8::PEM_encode(key);
            const std::string fp = cert.fingerprint("SHA-256"); // colon-separated hex

            id.certPem = QByteArray::fromStdString(certDer);
            id.keyPem = QByteArray::fromStdString(keyPem);
            id.nodeId = QString::fromStdString(fp).remove(':').toLower().left(16);
            id.certificate = QSslCertificate(id.certPem, QSsl::Pem);
            id.privateKey = QSslKey(id.keyPem, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
        } catch (const std::exception& e) {
            qWarning("PmVault: failed to generate TLS identity: %s", e.what());
            return PmpIdentity();
        } catch (...) {
            qWarning("PmVault: unknown failure generating TLS identity");
            return PmpIdentity();
        }
        return id;
    }
} // namespace

PmpIdentity PmpIdentityStore::loadOrCreate()
{
    try {
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
                id.privateKey = QSslKey(id.keyPem, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
                if (id.valid()) {
                    return id;
                }
            }
            f.close();
        }

        PmpIdentity id = generateIdentity();
        if (!id.valid()) {
            return id;
        }
        QJsonObject obj;
        obj["node"] = id.nodeId;
        obj["cert"] = QString::fromUtf8(id.certPem);
        obj["key"] = QString::fromUtf8(id.keyPem);
        const QByteArray sealed =
            PmpCrypto::aesGcmSeal(key, QJsonDocument(obj).toJson(QJsonDocument::Compact), ID_AAD);
        if (QFile out(identityPath()); out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            out.write(sealed.toBase64());
            out.close();
        }
        return id;
    } catch (const std::exception& e) {
        qWarning("PmVault: identity load/create failed: %s", e.what());
        return PmpIdentity();
    } catch (...) {
        qWarning("PmVault: unknown identity load/create failure");
        return PmpIdentity();
    }
}

QString PmpIdentityStore::fullFingerprint(const PmpIdentity& id)
{
    if (id.certificate.isNull()) {
        return {};
    }
    return QString::fromLatin1(id.certificate.digest(QCryptographicHash::Sha256).toHex()).toLower();
}
