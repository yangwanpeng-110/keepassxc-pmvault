/*
 * PmVault extensions - per-device TLS identity for LAN sync.
 *
 * An ECDSA P-256 self-signed certificate is generated once. Its SHA-256
 * fingerprint (first 16 hex chars) is the node id used in vector clocks and
 * for certificate pinning. The private key PEM is stored locally encrypted
 * with the device key (DPAPI-bound on Windows); it never enters the KDBX file.
 */

#ifndef PMP_IDENTITY_H
#define PMP_IDENTITY_H

#include <QByteArray>
#include <QSslCertificate>
#include <QSslKey>
#include <QString>

struct PmpIdentity
{
    QString nodeId;        // first 16 hex chars of SHA-256(certificate)
    QByteArray certPem;
    QByteArray keyPem;
    QSslCertificate certificate;
    QSslKey privateKey;

    bool valid() const
    {
        return !nodeId.isEmpty() && !certificate.isNull() && !privateKey.isNull();
    }
};

class PmpIdentityStore
{
public:
    static PmpIdentity loadOrCreate();
    static QString fullFingerprint(const PmpIdentity& id);
};

#endif // PMP_IDENTITY_H
