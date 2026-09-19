#!/usr/bin/env bash
#
# PmVault - Windows portable package builder (run inside an MSYS2 MINGW64 shell).
#
# KeePassXC (with the PmVault extensions) has already been built; this script
# gathers the executables and every runtime DLL into build/pmp-pkg, ready to zip.
#
# Robustness policy: this deliberately does NOT use "set -e" / pipefail. A
# successful build must never be turned into a red CI job by an optional copy or
# by a windeployqt quirk on some Qt patch release. Every fallible step is
# handled explicitly, Qt plugins are deployed by hand as a fallback, and only a
# missing hard requirement aborts packaging.

set -u

BUILD_DIR="build"
PKG_DIR="${BUILD_DIR}/pmp-pkg"

log() { echo "[pkg] $*"; }

# Candidate Qt plugin roots across MSYS2 environments / Qt layouts.
PLUG_ROOTS="/mingw64/share/qt5/plugins /mingw64/lib/qt5/plugins /mingw64/qt5/plugins /mingw64/plugins /ucrt64/share/qt5/plugins /clang64/share/qt5/plugins"

rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}"

# ---------------------------------------------------------------------------
# 1) Executables
# ---------------------------------------------------------------------------
copy_bin() {
    local src="$1"
    if [ -f "$src" ]; then
        cp -f "$src" "${PKG_DIR}/"
        log "binary: $(basename "$src")"
    else
        log "WARNING: binary not found: $src"
    fi
}

copy_bin "${BUILD_DIR}/src/keepassxc.exe"
copy_bin "${BUILD_DIR}/src/cli/keepassxc-cli.exe"
copy_bin "${BUILD_DIR}/src/proxy/keepassxc-proxy.exe"

if [ ! -f "${PKG_DIR}/keepassxc.exe" ]; then
    echo "FATAL: keepassxc.exe is missing; the build did not produce it."
    exit 1
fi

# ---------------------------------------------------------------------------
# 2) Locate the Qt plugin root (must contain platforms/qwindows.dll)
# ---------------------------------------------------------------------------
QT_PLUGINS=""
for r in ${PLUG_ROOTS}; do
    if [ -d "$r/platforms" ]; then
        QT_PLUGINS="$r"
        break
    fi
done
log "Qt plugin root: ${QT_PLUGINS:-<none found>}"

# ---------------------------------------------------------------------------
# 3) windeployqt - best effort. Manual deployment below covers every failure.
# ---------------------------------------------------------------------------
if command -v windeployqt >/dev/null 2>&1; then
    if windeployqt --release --no-translations --no-system-d3d-compiler \
                   --no-opengl-sw --no-quick-import \
                   "${PKG_DIR}/keepassxc.exe"; then
        log "windeployqt: completed"
    else
        rc=$?
        log "WARNING: windeployqt exited with ${rc}; falling back to manual plugin/DLL deployment"
    fi
else
    log "WARNING: windeployqt not found on PATH; deploying manually"
fi

# ---------------------------------------------------------------------------
# 4) Manual Qt plugin deployment (idempotent; also fills gaps windeployqt left)
# ---------------------------------------------------------------------------
deploy_plugins() {
    local sub="$1"
    if [ -n "${QT_PLUGINS}" ] && [ -d "${QT_PLUGINS}/${sub}" ]; then
        mkdir -p "${PKG_DIR}/${sub}"
        local cnt=0 f
        for f in "${QT_PLUGINS}/${sub}/"*.dll; do
            if [ -f "$f" ]; then
                cp -f "$f" "${PKG_DIR}/${sub}/"
                cnt=$((cnt + 1))
            fi
        done
        log "plugin ${sub}: ${cnt} dll"
    else
        log "WARNING: Qt plugin subdir '${sub}' not found"
    fi
}

deploy_plugins platforms    # qwindows.dll - hard requirement to launch the GUI
deploy_plugins tls          # qopensslbackend / qschannelbackend - mutual TLS 1.3
deploy_plugins imageformats # qjpeg / qgif / qico / qsvg ...
deploy_plugins iconengines  # qsvgicon
deploy_plugins styles       # qwindowsvistastyle

# ---------------------------------------------------------------------------
# 4b) TLS backend plugins - the fixed plugin roots above can miss the tls/
#     subdirectory on some Qt layouts, so locate the backends across the whole
#     MSYS2 installation as a fallback. These back QSslSocket's TLS 1.3.
# ---------------------------------------------------------------------------
mkdir -p "${PKG_DIR}/tls"
for backend in qopensslbackend qschannelbackend qcertonlybackend; do
    if [ ! -f "${PKG_DIR}/tls/${backend}.dll" ]; then
        found="$(find /mingw64 /ucrt64 /clang64 -type f -path '*tls*' -name "${backend}.dll" 2>/dev/null \
                     | head -n 1 || true)"
        if [ -n "${found}" ] && [ -f "${found}" ]; then
            cp -f "${found}" "${PKG_DIR}/tls/"
            log "tls backend: ${backend} <- ${found}"
        else
            log "NOTE: ${backend}.dll not found (this Qt build may link the backend statically)"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 4c) Application data under share/ (on Windows Resources resolves the data
#     path to <appdir>/share). Ship the Simplified-Chinese UI translation and
#     the diceware/password-generator word lists so the portable app is fully
#     localized and feature-complete on a clean machine.
# ---------------------------------------------------------------------------
mkdir -p "${PKG_DIR}/share/translations"
copied_qm=0
if [ -f "${BUILD_DIR}/share/translations/keepassxc_zh_CN.qm" ]; then
    cp -f "${BUILD_DIR}/share/translations/keepassxc_zh_CN.qm" "${PKG_DIR}/share/translations/"
    log "translation: keepassxc_zh_CN.qm"
    copied_qm=1
else
    log "WARNING: keepassxc_zh_CN.qm was not produced by the build; UI stays English"
fi
for qtroot in /mingw64/share/qt5/translations /mingw64/lib/qt5/translations \
              /mingw64/translations /ucrt64/share/qt5/translations /clang64/share/qt5/translations; do
    if [ -f "${qtroot}/qtbase_zh_CN.qm" ]; then
        cp -f "${qtroot}/qtbase_zh_CN.qm" "${PKG_DIR}/share/translations/"
        log "translation: qtbase_zh_CN.qm <- ${qtroot}"
        break
    fi
done
[ "${copied_qm}" -eq 1 ] || log "WARNING: application Chinese translation is missing"

if [ -d "${BUILD_DIR}/share/wordlists" ]; then
    mkdir -p "${PKG_DIR}/share/wordlists"
    cnt=0
    for wl in "${BUILD_DIR}/share/wordlists/"*.wordlist; do
        [ -f "$wl" ] && { cp -f "$wl" "${PKG_DIR}/share/wordlists/"; cnt=$((cnt + 1)); }
    done
    log "wordlists: ${cnt} file(s)"
fi

# qt.conf carries Windows platform tweaks (e.g. Qt dark-mode support).
if [ -f "share/windows/qt.conf" ]; then
    cp -f "share/windows/qt.conf" "${PKG_DIR}/qt.conf"
    log "qt.conf copied"
fi

# ---------------------------------------------------------------------------
# 5) Recursive ldd sweep: pull every MINGW runtime DLL the exe AND all deployed
#    plugins depend on (botan, argon2, minizip, qrencode, zlib, Qt5*, MinGW
#    runtime, ...). Repeated until no new DLL appears, so transitive deps of the
#    plugin subdirectories are captured too.
# ---------------------------------------------------------------------------
for _ in $(seq 1 12); do
    added=0
    while read -r dll; do
        [ -z "${dll:-}" ] && continue
        base="$(basename "$dll")"
        if [ ! -f "${PKG_DIR}/${base}" ] && [ -f "$dll" ]; then
            if cp -f "$dll" "${PKG_DIR}/"; then
                added=1
            fi
        fi
    done < <(find "${PKG_DIR}" -type f \( -name '*.exe' -o -name '*.dll' \) -print0 2>/dev/null \
              | xargs -0 -r ldd 2>/dev/null \
              | grep -oE '/(mingw64|ucrt64|clang64)/bin/[A-Za-z0-9._+-]+\.dll' \
              | sort -u || true)
    [ "$added" -eq 0 ] && break
done

# ---------------------------------------------------------------------------
# 6) OpenSSL is dlopen'd by QtNetwork at runtime (invisible to ldd). Copy both
#    the 1.1 and 3.x MinGW names, whichever this toolchain ships.
# ---------------------------------------------------------------------------
for f in /mingw64/bin/libssl-*.dll /mingw64/bin/libcrypto-*.dll \
         /ucrt64/bin/libssl-*.dll /ucrt64/bin/libcrypto-*.dll \
         /clang64/bin/libssl-*.dll /clang64/bin/libcrypto-*.dll; do
    [ -f "$f" ] && cp -f "$f" "${PKG_DIR}/" && log "openssl: $(basename "$f")"
done

# ---------------------------------------------------------------------------
# 7) License / readme
# ---------------------------------------------------------------------------
if [ -f LICENSE ]; then
    cp -f LICENSE "${PKG_DIR}/LICENSE-GPL.txt"
fi
cat > "${PKG_DIR}/README-PmVault.txt" <<'TXT'
PmVault (KeePassXC fork with PmVault extensions)
================================================
Run keepassxc.exe to start the Windows desktop application.

Included PmVault extensions (all data stays local, nothing is uploaded):
  * TOTP second factor for database unlock (manual code entry).
  * Local encrypted, tamper-evident audit log (outside the database).
  * LAN mutual-TLS-1.3 sync (disabled by default, port 19532).

Mature KeePassXC features (browser fill, Auto-Type, entry TOTP, ...) are
unchanged. This program is GPL software; see LICENSE-GPL.txt.
TXT

# ---------------------------------------------------------------------------
# 8) Self-check + listing
# ---------------------------------------------------------------------------
log "package root contents:"
ls -1 "${PKG_DIR}"

missing_hard=0
for must in keepassxc.exe keepassxc-cli.exe platforms/qwindows.dll; do
    if [ ! -e "${PKG_DIR}/${must}" ]; then
        echo "MISSING REQUIRED: ${must}"
        missing_hard=1
    fi
done

for soft in Qt5Core.dll Qt5Network.dll Qt5Widgets.dll share/translations/keepassxc_zh_CN.qm; do
    if ! ls "${PKG_DIR}/${soft}" >/dev/null 2>&1; then
        log "WARNING: expected file ${soft} is absent"
    fi
done

if [ "${missing_hard}" -ne 0 ]; then
    echo "FATAL: one or more hard requirements are missing; not uploading a broken package."
    exit 1
fi

log "portable package assembled successfully in ${PKG_DIR}"
