/*
 * PmVault extensions - plaintext diagnostic file logger (header-only).
 *
 * Writes LAN-sync troubleshooting traces to
 *   <appData>/PmVault/logs/pmsync-YYYYMMDD.log
 * (Windows: %APPDATA%/PmVault/logs). Rotates, keeping the newest files.
 *
 * SECURITY / PRIVACY CONTRACT
 * ---------------------------
 * This file is deliberately NOT the encrypted audit log. It exists only so the
 * user (and the developer) can diagnose LAN / TLS connection failures. Callers
 * MUST only ever pass non-sensitive, connection-level data:
 *   - phase / state names
 *   - local and peer IP address and port
 *   - TLS / Qt socket error enums and errorString()
 *   - OpenSSL / protocol build info and non-secret counters
 * It MUST NEVER contain entry titles, URLs paths, usernames, passwords, TOTP
 * seeds/codes, key material, fingerprints of secrets, or database contents.
 *
 * Copyright (C) 2026 PmVault Project
 * Licensed under the GPL-3.0-or-later.
 */
#ifndef PMPFILELOGGER_H
#define PMPFILELOGGER_H

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <QTextStream>

#include "PmpPlatform.h"

class PmpFileLogger
{
public:
    // Append one diagnostic line. Safe to call from any thread.
    static void log(const QString& phase, const QString& detail = QString())
    {
        static QMutex s_mutex;
        QMutexLocker locker(&s_mutex);

        const QString dirPath = PmpPlatform::ensureSubDir(QStringLiteral("logs"));
        const QString fileName =
            dirPath + QStringLiteral("/pmsync-")
            + QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd"))
            + QStringLiteral(".log");

        QFile f(fileName);
        if (!f.open(QIODevice::Append | QIODevice::Text)) {
            return;
        }
        QTextStream s(&f);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        s.setEncoding(QStringConverter::Utf8);
#else
        s.setCodec("UTF-8");
#endif
        QString line = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))
                       + QStringLiteral(" [") + phase + QStringLiteral("]");
        if (!detail.isEmpty()) {
            line += QStringLiteral(" ") + detail;
        }
        s << line << QStringLiteral("\n");
        s.flush();
        f.close();

        rotate(dirPath);
    }

private:
    // Keep at most 8 daily log files (QDir::Time = newest first).
    static void rotate(const QString& dirPath)
    {
        QDir dir(dirPath);
        const QStringList files =
            dir.entryList(QStringList() << QStringLiteral("pmsync-*.log"),
                          QDir::Files, QDir::Time);
        for (int i = KeepFiles; i < files.size(); ++i) {
            dir.remove(files.at(i));
        }
    }

    static constexpr int KeepFiles = 8;
};

#endif // PMPFILELOGGER_H
