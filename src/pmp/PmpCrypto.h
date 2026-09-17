/*
 * PmVault extensions - cryptographic primitives (header-only).
 *
 * Copyright (C) 2026 PmVault Project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PMP_CRYPTO_H
#define PMP_CRYPTO_H

#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>

#include <QByteArray>
#include <QString>

namespace PmpCrypto
{
    inline Botan::RandomNumberGenerator& rng()
    {
        static Botan::AutoSeeded_RNG instance;
        return instance;
    }

    inline QByteArray randomBytes(int n)
    {
        QByteArray b(n, '\0');
        rng().randomize(reinterpret_cast<Botan::uint8_t*>(b.data()), static_cast<size_t>(n));
        return b;
    }

    inline Botan::secure_vector<Botan::uint8_t> toSv(const QByteArray& a)
    {
        const auto* p = reinterpret_cast<const Botan::uint8_t*>(a.constData());
        return Botan::secure_vector<Botan::uint8_t>(p, p + a.size());
    }

    inline QByteArray fromSv(const Botan::secure_vector<Botan::uint8_t>& v)
    {
        return QByteArray(reinterpret_cast<const char*>(v.data()), static_cast<int>(v.size()));
    }

    inline QByteArray sha256(const QByteArray& msg)
    {
        auto h = Botan::HashFunction::create("SHA-256");
        h->update(toSv(msg));
        return fromSv(h->final());
    }

    inline QByteArray hmacSha256(const QByteArray& key, const QByteArray& msg)
    {
        auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        mac->set_key(toSv(key));
        mac->update(toSv(msg));
        return fromSv(mac->final());
    }

    // HKDF-SHA256. salt/label are domain-separation constants, never secrets.
    inline QByteArray hkdf(const QByteArray& secret, const QByteArray& salt, const QByteArray& label, int len)
    {
        auto kdf = Botan::KDF::create("HKDF(SHA-256)");
        const auto s = toSv(secret);
        const auto sa = toSv(salt);
        const auto lb = toSv(label);
        auto out = kdf->derive_key(static_cast<size_t>(len), s.data(), s.size(), sa.data(), sa.size(),
                                   lb.data(), lb.size());
        return fromSv(out);
    }

    // AES-256-GCM. Layout: nonce(12 bytes) || ciphertext || tag(16 bytes).
    inline QByteArray aesGcmSeal(const QByteArray& key32, const QByteArray& plain, const QByteArray& aad)
    {
        auto enc = Botan::AEAD_Mode::create("AES-256/GCM", Botan::ENCRYPTION);
        enc->set_key(toSv(key32));
        QByteArray nonce = randomBytes(12);
        enc->set_associated_data(reinterpret_cast<const Botan::uint8_t*>(aad.constData()),
                                 static_cast<size_t>(aad.size()));
        enc->start(reinterpret_cast<const Botan::uint8_t*>(nonce.constData()), 12);
        auto buf = toSv(plain);
        enc->finish(buf);
        return nonce + fromSv(buf);
    }

    // Returns false (never throws) on any decryption / authentication failure.
    inline bool aesGcmOpen(const QByteArray& key32, const QByteArray& sealed, const QByteArray& aad, QByteArray& plain)
    {
        if (sealed.size() < 12 + 16 || key32.size() != 32) {
            return false;
        }
        QByteArray nonce = sealed.left(12);
        auto buf = toSv(sealed.mid(12));
        try {
            auto dec = Botan::AEAD_Mode::create("AES-256/GCM", Botan::DECRYPTION);
            dec->set_key(toSv(key32));
            dec->set_associated_data(reinterpret_cast<const Botan::uint8_t*>(aad.constData()),
                                     static_cast<size_t>(aad.size()));
            dec->start(reinterpret_cast<const Botan::uint8_t*>(nonce.constData()), 12);
            dec->finish(buf); // throws Botan::Invalid_Authentication_Tag on tampering
            plain = fromSv(buf);
            return true;
        } catch (const Botan::Exception&) {
            return false;
        }
    }

    inline QString toHex(const QByteArray& b)
    {
        return QString::fromLatin1(b.toHex());
    }

    inline QByteArray fromHex(const QString& s)
    {
        return QByteArray::fromHex(s.toLatin1());
    }

    inline QString toB64(const QByteArray& b)
    {
        return QString::fromLatin1(b.toBase64(QByteArray::Base64Encoding | QByteArray::KeepTrailingEquals));
    }

    inline QByteArray fromB64(const QString& s)
    {
        return QByteArray::fromBase64(s.toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    }
} // namespace PmpCrypto

#endif // PMP_CRYPTO_H
