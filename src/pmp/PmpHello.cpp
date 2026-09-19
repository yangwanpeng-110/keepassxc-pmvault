/*
 * PmVault extensions - Windows Hello quick unlock implementation (MinGW).
 * See PmpHello.h for the security model.
 */

#include "PmpHello.h"

#ifdef Q_OS_WIN

#include "PmpCrypto.h"
#include "PmpPlatform.h"

#include <QByteArray>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>

namespace
{
    const QByteArray HELLO_AAD = "PmVault/hello-quickunlock/v1";

    // PowerShell prelude that loads the WinRT UserConsentVerifier type and a
    // small helper to synchronously await IAsyncOperation<T>.
    const char* kPsPrelude =
        "$ErrorActionPreference='Stop'\n"
        "try{\n"
        " Add-Type -AssemblyName System.Runtime.WindowsRuntime\n"
        " $t=[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security,ContentType=WindowsRuntime]\n"
        " $asTask=([System.WindowsRuntimeSystemExtensions].GetMethods()|Where-Object{ $_.Name -eq 'AsTask' "
        "-and $_.GetParameters().Count -eq 1 -and "
        "$_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]\n"
        " function Await($op,$ty){ $g=$asTask.MakeGenericMethod($ty); $task=$g.Invoke($null,@($op)); "
        "$task.Wait(); $task.Result }\n";

    const char* kPsAvailability =
        " $a=Await ($t::CheckAvailabilityAsync()) "
        "([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])\n"
        " if([int]$a -eq 0){ exit 0 } else { exit 2 }\n"
        "}catch{ exit 1 }\n";

    const char* kPsVerify =
        " $a=Await ($t::CheckAvailabilityAsync()) "
        "([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])\n"
        " if([int]$a -ne 0){ exit 2 }\n"
        " $r=Await ($t::RequestVerificationAsync('PmVault')) "
        "([Windows.Security.Credentials.UI.UserConsentVerifierVerificationResult])\n"
        " if([int]$r -eq 0){ exit 0 } else { exit 3 }\n"
        "}catch{ exit 1 }\n";

    QString encodeScript(const char* body)
    {
        const QString script = QString::fromLatin1(body);
        const QByteArray utf16(reinterpret_cast<const char*>(script.utf16()), script.length() * 2);
        return QString::fromLatin1(utf16.toBase64());
    }
} // namespace

PmpHello* PmpHello::instance()
{
    static PmpHello s_inst;
    return &s_inst;
}

PmpHello::PmpHello(QObject* parent)
    : QObject(parent)
{
}

int PmpHello::runEncoded(const QString& encodedScript, int timeoutMs)
{
    QProcess proc;
    QString sysRoot =
        QProcessEnvironment::systemEnvironment().value(QStringLiteral("SystemRoot"), QStringLiteral("C:\\Windows"));
    QString powershell = sysRoot + QStringLiteral("\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    if (!QFileInfo::exists(powershell)) {
        powershell = QStringLiteral("powershell.exe");
    }

    QStringList args;
    args << QStringLiteral("-NoProfile") << QStringLiteral("-NonInteractive")
         << QStringLiteral("-ExecutionPolicy") << QStringLiteral("Bypass") << QStringLiteral("-WindowStyle")
         << QStringLiteral("Hidden") << QStringLiteral("-EncodedCommand") << encodedScript;

    proc.setProgram(powershell);
    proc.setArguments(args);
    proc.setProcessChannelMode(QProcess::MergedChannels);
    // CREATE_NO_WINDOW (0x08000000): never flash a console window.
    proc.setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments* a) { a->flags |= 0x08000000; });

    proc.start();
    if (!proc.waitForStarted(3000)) {
        proc.kill();
        return -1;
    }
    if (!proc.waitForFinished(timeoutMs)) {
        proc.kill();
        proc.waitForFinished(1000);
        return -1;
    }
    return proc.exitStatus() == QProcess::NormalExit ? proc.exitCode() : -1;
}

bool PmpHello::probeAvailability() const
{
    const int code = runEncoded(encodeScript(kPsPrelude) + encodeScript(kPsAvailability), 8000);
    if (code != 0) {
        m_error = QObject::tr("Windows Hello is not available on this device (code %1).").arg(code);
        return false;
    }
    return true;
}

bool PmpHello::requestVerification()
{
    // Allow up to 60 s for the user to complete the system PIN/biometric prompt.
    const int code = runEncoded(encodeScript(kPsPrelude) + encodeScript(kPsVerify), 60000);
    return code == 0;
}

bool PmpHello::isAvailable() const
{
    if (m_available < 0) {
        m_available = probeAvailability() ? 1 : 0;
    }
    return m_available == 1;
}

QString PmpHello::errorString() const
{
    return m_error;
}

QString PmpHello::blobPath(const QString& dbPath) const
{
    const QString id16 = PmpPlatform::dbId(dbPath).left(16);
    return PmpPlatform::ensureSubDir(QStringLiteral("hello")) + QStringLiteral("/") + id16 + QStringLiteral(".key");
}

bool PmpHello::hasKey(const QString& dbPath) const
{
    return QFileInfo::exists(blobPath(dbPath));
}

bool PmpHello::storeKey(const QString& dbPath, const QByteArray& key)
{
    if (!requestVerification()) {
        m_error = QObject::tr("Windows Hello verification was canceled or did not succeed.");
        return false;
    }
    const QString id16 = PmpPlatform::dbId(dbPath).left(16);
    const QByteArray derived = PmpPlatform::deriveKey(("hello:" + id16).toUtf8());
    const QByteArray sealed = PmpCrypto::aesGcmSeal(derived, key, HELLO_AAD);

    QFile f(blobPath(dbPath));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        m_error = QObject::tr("Could not write the Windows Hello credential file.");
        return false;
    }
    f.write(sealed.toBase64());
    f.close();
    return true;
}

bool PmpHello::getKey(const QString& dbPath, QByteArray& key)
{
    key.clear();
    if (!hasKey(dbPath)) {
        m_error = QObject::tr("No Windows Hello credential is stored for this database on this device.");
        return false;
    }
    if (!requestVerification()) {
        m_error = QObject::tr("Windows Hello verification was canceled or did not succeed.");
        return false;
    }

    QFile f(blobPath(dbPath));
    if (!f.open(QIODevice::ReadOnly)) {
        m_error = QObject::tr("Could not read the Windows Hello credential file.");
        return false;
    }
    const QByteArray sealed = QByteArray::fromBase64(f.readAll().trimmed());
    f.close();

    const QString id16 = PmpPlatform::dbId(dbPath).left(16);
    const QByteArray derived = PmpPlatform::deriveKey(("hello:" + id16).toUtf8());
    QByteArray plain;
    if (!PmpCrypto::aesGcmOpen(derived, sealed, HELLO_AAD, plain)) {
        m_error = QObject::tr("The stored Windows Hello credential could not be decrypted.");
        return false;
    }
    key = plain;
    return true;
}

void PmpHello::reset(const QString& dbPath)
{
    QFile::remove(blobPath(dbPath));
}

void PmpHello::reset()
{
    // Credentials live in per-database files; nothing is cached in memory.
}

#else // !Q_OS_WIN

PmpHello* PmpHello::instance()
{
    static PmpHello s_inst;
    return &s_inst;
}

PmpHello::PmpHello(QObject* parent)
    : QObject(parent)
{
}

bool PmpHello::isAvailable() const
{
    return false;
}
QString PmpHello::errorString() const
{
    return {};
}
void PmpHello::reset()
{
}
bool PmpHello::storeKey(const QString&, const QByteArray&)
{
    return false;
}
bool PmpHello::getKey(const QString&, QByteArray&)
{
    return false;
}
bool PmpHello::hasKey(const QString&) const
{
    return false;
}
void PmpHello::reset(const QString&)
{
}

#endif // Q_OS_WIN
