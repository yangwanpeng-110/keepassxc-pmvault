/*
 *  Copyright (C) 2010 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2020 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <QCommandLineParser>
#include <QDir>
#include <QFile>
#include <QThreadPool>
#include <QWindow>

#include "cli/Utils.h"
#include "config-keepassx.h"
#include "core/Tools.h"
#include "crypto/Crypto.h"
#include "gui/Application.h"
#include "gui/MainWindow.h"
#include "gui/MessageBox.h"
#include "gui/osutils/OSUtils.h"
#include "pmp/PmpManager.h"

#if defined(WITH_ASAN) && defined(WITH_LSAN)
#include <sanitizer/lsan_interface.h>
#endif

#ifdef QT_STATIC
#include <QtPlugin>

#if defined(Q_OS_WIN)
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)
#elif defined(Q_OS_UNIX) && !defined(Q_OS_MACOS)
Q_IMPORT_PLUGIN(QXcbIntegrationPlugin)
#endif
#endif

#ifdef Q_OS_WIN
#include <windows.h>
#endif

#ifdef Q_OS_WIN
// PmVault diagnostics: append-only shutdown breadcrumbs and a vectored exception
// handler. Used to localise the intermittent Windows exit crash (which happens too
// late in process teardown for WER/ProcDump to capture). Writes to %TEMP%\pmvault_crash.log.
#include <cstdio>
#include <cstdlib>
static void pmDiagWrite(const char* tag, const char* msg)
{
    char path[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableA("TEMP", path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return;
    }
    lstrcatA(path, "\\pmvault_crash.log");
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    char line[1024];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE, "[%lu] %s %s\n",
                          static_cast<unsigned long>(GetTickCount()), tag, msg ? msg : "");
    if (len > 0) {
        DWORD written = 0;
        WriteFile(h, line, static_cast<DWORD>(len), &written, nullptr);
    }
    CloseHandle(h);
}

extern "C" void pmStage(const char* stage)
{
    pmDiagWrite("STAGE", stage);
}

static LONG WINAPI pmVectoredExceptionHandler(PEXCEPTION_POINTERS ep)
{
    static volatile LONG s_logged = 0;
    if (!ep || !ep->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    // Access violation (and a few other fatal codes) only.
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_STACK_OVERFLOW
        && code != 0xC0000409u /*stack buffer overrun*/ && code != EXCEPTION_ILLEGAL_INSTRUCTION
        && code != EXCEPTION_PRIV_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (InterlockedExchange(&s_logged, 1) != 0) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    ULONG64 rip = 0;
    ULONG64 faultAddr = 0;
    ULONG accessKind = 0;
#if defined(_M_X64) || defined(__x86_64__)
    if (ep->ContextRecord) {
        rip = static_cast<ULONG64>(ep->ContextRecord->Rip);
    }
#elif defined(_M_IX86)
    if (ep->ContextRecord) {
        rip = static_cast<ULONG64>(ep->ContextRecord->Eip);
    }
#endif
    if (ep->ExceptionRecord->NumberParameters >= 2) {
        accessKind = static_cast<ULONG>(ep->ExceptionRecord->ExceptionInformation[0]);
        faultAddr = static_cast<ULONG64>(ep->ExceptionRecord->ExceptionInformation[1]);
    }

    char msg[900];
    const char* kind = (accessKind == 0) ? "read" : (accessKind == 1 ? "write" : (accessKind == 8 ? "exec" : "?"));
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                "code=0x%08lX %s addr=0x%p rip=0x%p exceptionAddress=0x%p",
                static_cast<unsigned long>(code), kind, reinterpret_cast<void*>(faultAddr),
                reinterpret_cast<void*>(rip), ep->ExceptionRecord->ExceptionAddress);
    pmDiagWrite("CRASH", msg);

    HMODULE mod = nullptr;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &mod)
        && mod) {
        wchar_t wpath[MAX_PATH] = {0};
        if (GetModuleFileNameW(mod, wpath, MAX_PATH) > 0) {
            char modPath[MAX_PATH * 2] = {0};
            WideCharToMultiByte(CP_UTF8, 0, wpath, -1, modPath, sizeof(modPath), nullptr, nullptr);
            ULONG64 base = reinterpret_cast<ULONG64>(mod);
            _snprintf_s(msg, sizeof(msg), _TRUNCATE, "module=%s base=0x%p offset=0x%llx",
                        modPath, reinterpret_cast<void*>(base),
                        static_cast<unsigned long long>(rip - base));
            pmDiagWrite("CRASH", msg);
        }
    } else {
        pmDiagWrite("CRASH", "module=<not in any loaded module>");
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

int main(int argc, char** argv)
{
    QT_REQUIRE_VERSION(argc, argv, QT_VERSION_STR)

#ifdef Q_OS_WIN
    AddVectoredExceptionHandler(1, pmVectoredExceptionHandler);
    pmStage("main:start");
    atexit([]() { pmStage("main:atexit"); });
#endif

#ifdef Q_OS_WIN
    // Set OPENSSL_* variables to an invalid location to prevent DLL injection via openssl.cnf.
    // vcpkg by default hard-codes this to its packages location, which may be user-writable.
    qputenv("OPENSSL_CONF", "::");
    qputenv("OPENSSL_MODULES", "::");
    qputenv("OPENSSL_ENGINES", "::");
#endif

    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QGuiApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0) && defined(Q_OS_WIN)
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
#endif
    Application app(argc, argv);
    // don't set organizationName as that changes the return value of
    // QStandardPaths::writableLocation(QDesktopServices::DataLocation)
    Application::setApplicationName("KeePassXC");
    Application::setApplicationVersion(KEEPASSXC_VERSION);
    app.setProperty("KPXC_QUALIFIED_APPNAME", "org.keepassxc.KeePassXC");

    // HACK: Prevent long-running threads from deadlocking the program with only 1 CPU
    // See https://github.com/keepassxreboot/keepassxc/issues/10391
    if (QThreadPool::globalInstance()->maxThreadCount() < 2) {
        QThreadPool::globalInstance()->setMaxThreadCount(2);
    }

    QCommandLineParser parser;
    parser.setApplicationDescription(QObject::tr("KeePassXC - cross-platform password manager"));
    parser.addPositionalArgument(
        "filename(s)", QObject::tr("filenames of the password databases to open (*.kdbx)"), "[filename(s)]");

    QCommandLineOption configOption("config", QObject::tr("path to a custom config file"), "config");
    QCommandLineOption localConfigOption(
        "localconfig", QObject::tr("path to a custom local config file"), "localconfig");
    QCommandLineOption lockOption("lock", QObject::tr("lock all open databases"));
    QCommandLineOption keyfileOption("keyfile", QObject::tr("key file of the database"), "keyfile");
    QCommandLineOption pwstdinOption("pw-stdin", QObject::tr("read password of the database from stdin"));
    QCommandLineOption allowScreenCaptureOption("allow-screencapture",
                                                QObject::tr("allow screenshots and app recording (Windows/macOS)"));
    QCommandLineOption startMinimized("minimized", QObject::tr("start minimized to the system tray"));

    QCommandLineOption helpOption = parser.addHelpOption();
    QCommandLineOption versionOption = parser.addVersionOption();
    QCommandLineOption debugInfoOption(QStringList() << "debug-info", QObject::tr("Displays debugging information."));
    parser.addOption(configOption);
    parser.addOption(localConfigOption);
    parser.addOption(lockOption);
    parser.addOption(keyfileOption);
    parser.addOption(pwstdinOption);
    parser.addOption(debugInfoOption);
    parser.addOption(allowScreenCaptureOption);
    parser.addOption(startMinimized);

    parser.process(app);

    // Exit early if we're only showing the help / version
    if (parser.isSet(versionOption) || parser.isSet(helpOption)) {
        return EXIT_SUCCESS;
    }

    // Show debug information and then exit
    if (parser.isSet(debugInfoOption)) {
        QTextStream out(stdout, QIODevice::WriteOnly);
        QString debugInfo = Tools::debugInfo().append("\n").append(Crypto::debugInfo());
        out << debugInfo << Qt::endl;
        return EXIT_SUCCESS;
    }

    // Process config file options early
    if (parser.isSet(configOption) || parser.isSet(localConfigOption)) {
        Config::createConfigFromFile(parser.value(configOption), parser.value(localConfigOption));
    }

    // Extract file names provided on the command line for opening
    QStringList fileNames;
#ifdef Q_OS_WIN
    // Get correct case for Windows filenames (fixes #7139)
    for (const auto& file : parser.positionalArguments()) {
        const auto fileInfo = QFileInfo(file);
        WIN32_FIND_DATAW findFileData;
        HANDLE hFind;
        const wchar_t* absolutePathWchar = reinterpret_cast<const wchar_t*>(fileInfo.absoluteFilePath().utf16());
        hFind = FindFirstFileW(absolutePathWchar, &findFileData);
        if (hFind != INVALID_HANDLE_VALUE) {
            fileNames << QString("%1/%2").arg(fileInfo.absolutePath(), QString::fromWCharArray(findFileData.cFileName));
            FindClose(hFind);
        }
    }
#else
    for (const auto& file : parser.positionalArguments()) {
        if (QFile::exists(file)) {
            fileNames << QDir::toNativeSeparators(file);
        }
    }
#endif

    // Process single instance and early exit if already running
    if (app.isAlreadyRunning()) {
        if (parser.isSet(lockOption)) {
            if (app.sendLockToInstance()) {
                qInfo() << QObject::tr("Databases have been locked.").toUtf8().constData();
            } else {
                qWarning() << QObject::tr("Database failed to lock.").toUtf8().constData();
                return EXIT_FAILURE;
            }
        } else {
            if (!fileNames.isEmpty()) {
                app.sendFileNamesToRunningInstance(fileNames);
            }

            qWarning() << QObject::tr("Another instance of KeePassXC is already running.").toUtf8().constData();
        }
        return EXIT_SUCCESS;
    }

    if (parser.isSet(lockOption)) {
        qWarning() << QObject::tr("KeePassXC is not running. No open database to lock").toUtf8().constData();

        // still return with EXIT_SUCCESS because when used within a script for ensuring that there is no unlocked
        // keepass database (e.g. screen locking) we can consider it as successful
        return EXIT_SUCCESS;
    }

    if (!Crypto::init()) {
        QString error = QObject::tr("Fatal error while testing the cryptographic functions.");
        error.append("\n");
        error.append(Crypto::errorString());
        MessageBox::critical(nullptr, QObject::tr("KeePassXC - Error"), error);
        return EXIT_FAILURE;
    }

    Utils::setDefaultTextStreams();

    // Apply the configured theme before creating any GUI elements
    app.applyTheme();

    QGuiApplication::setDesktopFileName(app.property("KPXC_QUALIFIED_APPNAME").toString() + QStringLiteral(".desktop"));

    Application::bootstrap(config()->get(Config::GUI_Language).toString());

#ifdef Q_OS_WIN
    QObject::connect(qApp, &QCoreApplication::aboutToQuit, qApp,
                     []() { pmStage("aboutToQuit"); });
#endif

    MainWindow mainWindow;
    PmpManager::instance()->install();
#ifdef Q_OS_WIN
    // Qt Hack - Prevent white flicker when showing window
    mainWindow.setProperty("windowOpacity", 0.0);
#endif

    // Disable screen capture if not explicitly allowed
    // This ensures any top-level windows (Main Window, Modal Dialogs, etc.) are excluded from screenshots
    mainWindow.setAllowScreenCapture(parser.isSet(allowScreenCaptureOption));

    const bool pwstdin = parser.isSet(pwstdinOption);
    for (const QString& filename : fileNames) {
        QString password;
        if (pwstdin) {
            // we always need consume a line of STDIN if --pw-stdin is set to clear out the
            // buffer for native messaging, even if the specified file does not exist
            QTextStream out(stdout, QIODevice::WriteOnly);
            out << QObject::tr("Database password: ") << Qt::flush;
            password = Utils::getPassword();
        }
        mainWindow.openDatabase(filename, password, parser.value(keyfileOption));
    }

    // start minimized if configured
    if (parser.isSet(startMinimized) || config()->get(Config::GUI_MinimizeOnStartup).toBool()) {
        mainWindow.hideWindow();
    } else {
        mainWindow.bringToFront();
        Application::processEvents();
    }

#ifdef Q_OS_WIN
    pmStage("main:beforeExec");
#endif
    int exitCode = Application::exec();
#ifdef Q_OS_WIN
    pmStage("main:afterExec");
#endif

    // Check if restart was requested
    if (exitCode == RESTART_EXITCODE) {
        QProcess::startDetached(QCoreApplication::applicationFilePath(), {});
    }

#if defined(WITH_ASAN) && defined(WITH_LSAN)
    // do leak check here to prevent massive tail of end-of-process leak errors from third-party libraries
    __lsan_do_leak_check();
    __lsan_disable();
#endif

    Utils::resetTextStreams();

#ifdef Q_OS_WIN
    pmStage("main:end");
#endif

    return exitCode;
}
