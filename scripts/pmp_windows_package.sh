#!/usr/bin/env bash
#
# PmVault - Windows portable package builder (run inside an MSYS2 MINGW64 shell).
# Builds KeePassXC (with the PmVault extensions) and gathers every runtime DLL
# with windeployqt + ldd, producing build/pmp-pkg ready to zip.
#
set -euo pipefail

BUILD_DIR="build"
PKG_DIR="${BUILD_DIR}/pmp-pkg"

rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}"

# Binaries
cp "${BUILD_DIR}/src/keepassxc.exe"        "${PKG_DIR}/"
cp "${BUILD_DIR}/src/cli/keepassxc-cli.exe" "${PKG_DIR}/"
cp "${BUILD_DIR}/src/proxy/keepassxc-proxy.exe" "${PKG_DIR}/"

# Qt deployment (plugins, platforms, TLS backend, compiler runtime).
# --tls makes windeployqt ship the TLS backend plugins (qopensslbackend, ...)
# needed by the mutual-TLS-1.3 LAN sync.
windeployqt --release --compiler-runtime --no-quick-import \
    --no-system-d3d-compiler --no-opengl-sw --tls \
    "${PKG_DIR}/keepassxc.exe"

# Pull every remaining MINGW64 runtime dependency (botan, argon2, minizip,
# qrencode, zlib, OpenSSL for TLS 1.3, libgcc/libstdc++/winpthread, ...).
for _ in 1 2 3 4 5 6 7 8; do
    added=0
    while read -r dll; do
        [ -z "${dll:-}" ] && continue
        base="$(basename "$dll")"
        if [ ! -f "${PKG_DIR}/${base}" ]; then
            cp "$dll" "${PKG_DIR}/"
            added=1
        fi
    done < <(ldd "${PKG_DIR}"/*.exe "${PKG_DIR}"/*.dll 2>/dev/null \
              | grep -oE '/(mingw64|ucrt64)/bin/[A-Za-z0-9._+-]+\.dll' | sort -u)
    [ "$added" -eq 0 ] && break
done

# QtNetwork loads OpenSSL lazily at runtime (it is dlopen'd, so ldd cannot see
# it). Copy it explicitly so mutual-TLS-1.3 sync works on a clean machine that
# does not have MSYS2/OpenSSL installed.
for _dll in libssl-3-x64.dll libcrypto-3-x64.dll; do
    if [ -f "/mingw64/bin/${_dll}" ]; then
        cp -f "/mingw64/bin/${_dll}" "${PKG_DIR}/"
    fi
done

# Licenses / readme
cp LICENSE "${PKG_DIR}/LICENSE-GPL.txt" 2>/dev/null || true
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

echo "Package contents:"
ls -1 "${PKG_DIR}"
