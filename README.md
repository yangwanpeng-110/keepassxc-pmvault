# PmVault（Windows / Linux 桌面端）

> PmVault 是在开源密码管理器 **KeePassXC** 基础上自研扩展的跨平台密码管理器桌面端。
> 本仓库为 KeePassXC 的下游 fork（GPL-2/GPL-3），**不直接复用任何第三方专有源代码**，
> 在完整保留 KeePassXC KDBX4 能力的前提下，新增了面向个人的第二因素、局域网端到端同步、
> 加密审计日志与浏览器桥接等能力。上游版权与许可证声明见文末及 `COPYING`。

## 与 KeePassXC 的关系

- 数据库格式：标准 **KDBX4**（兼容 KDBX3），与 KeePassXC / KeePassDX / KeeWeb 等互通。
- 所有 PmVault **自定义配置都保存在 KDBX 的 CustomData 扩展字段**中，随数据库一起加密、一起备份，**不上传任何云端**。
- 本项目为独立 fork，自有功能以 `src/pmp/` 等 `Pmp` 前缀模块组织；上游升级可继续合并。

## PmVault 新增能力

- **解锁方式**
  - 必须设置**主密码**；**密钥文件为辅助解锁**——使用密钥文件时仍需输入主密码，仅输入主密码也可单独解锁。
  - 可选 **第二因素（TOTP，兼容 Google Authenticator 风格，仅手动输入 6/8 位验证码，不读取任何验证器 App）**。
- **浏览器自动填充（Chromium 扩展，适配 Edge 与 Chrome）**
  - 自研 Manifest V3 扩展 `share/pmvault-browser-extension/`，通过随包构建的 `keepassxc-proxy.exe` 原生消息管道工作（本机 stdio，不开网络端口）。
  - 网页密码框悬浮条：搜索 / 复制用户名、密码 / 一键自动填写；填充失败自动降级为复制。
  - **类 Edge 密码更新提示**：提交表单时若该网址下已存在“相同用户名、不同密码”的条目，会主动询问**更新密码 / 新建条目 / 忽略**。
  - 安装与 Edge/Chrome 双浏览器注册见扩展目录 `README.md` 与 `host/install-host.bat`（同时写入 Chrome、Edge、Chromium 的 NativeMessagingHosts 注册表项）。
- **桌面 Auto-Type**：保留 KeePassXC 的键盘模拟自动输入，可设置全局快捷键呼出小面板。
- **局域网双向同步（mTLS 1.3）**
  - 手机端（PmVault Android，基于 KeePassDX 的姊妹仓库）与电脑端在同一局域网内双向合并。
  - 仅信任 **SHA-256 证书指纹**（不使用系统 CA），首次连接需两端核对并确认指纹；强制 TLS 1.3、双向客户端证书；仅允许局域网/回环地址，默认端口 19532。
  - 向量时钟合并、冲突默认双方保留（冲突副本挂根分组）、删除经墓碑（tombstone）传播。
  - **内置条目模板（Entry Templates）仅保留在本地、不参与同步**，避免把空模板同步成根分组空条目。
- **本地加密审计日志**：记录解锁、第二因素、密码变更、复制、填充、同步等行为；**只记事件与计数，绝不记录主密码、条目密码、TOTP、完整 URL 等明文敏感信息**，日志本身加密存于数据库 CustomData。
- **明文诊断日志（仅用于排错）**：局域网同步的连接阶段、TLS/套接字错误、OpenSSL 版本、IP 与端口等会写入
  `%APPDATA%\PmVault\logs\pmsync-YYYYMMDD.log`（按天轮转、保留少量文件）。该文件**同样不含任何密码或条目内容**，
  仅用于定位“连不上/握手失败”等网络问题。
- **其它**：数据库默认存放于用户 AppData；删除数据库会同时删除源文件；关闭/最小化与系统托盘行为在“通用设置”中
  按“点击关闭按钮（X）/ 最小化按钮（-）”分别说明；移除了回收站（删除即永久删除）。

## 构建

- 推荐使用仓库内 GitHub Actions 工作流（`.github/workflows/pmp-*.yml`）：Linux 作业作为 C++ 编译门，
  Windows（MSYS2 MINGW64，Qt + Botan + Argon2 + OpenSSL 等）作业产出便携版 zip（内含 `keepassxc.exe`、
  `keepassxc-proxy.exe`、OpenSSL 运行库、中文 `.qm` 与内置浏览器扩展）。
- 本地手动构建仍遵循上游 KeePassXC 的依赖与步骤，见 [INSTALL.md](./INSTALL.md)。

## 配套 Android 端

PmVault Android（基于 KeePassDX 的姊妹 fork）提供生物识别解锁、标准 Autofill、同网址密码变更更新提示，
以及与本桌面端一致的局域网 mTLS 同步能力。

---

# <img src="https://keepassxc.org/assets/img/keepassxc.svg" width="40" height="40"/> KeePassXC（上游项目）

[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/6326/badge)](https://bestpractices.coreinfrastructure.org/projects/6326)
[![TeamCity Build Status](https://ci.keepassxc.org/app/rest/builds/buildType:\(project:KeepassXC\)/statusIcon)](https://ci.keepassxc.org/?guest=1)
[![codecov](https://codecov.io/gh/keepassxreboot/keepassxc/branch/develop/graph/badge.svg)](https://codecov.io/gh/keepassxreboot/keepassxc)
[![GitHub release](https://img.shields.io/github/release/keepassxreboot/keepassxc)](https://github.com/keepassxreboot/keepassxc/releases/)

[![Matrix community channel](https://img.shields.io/matrix/keepassxc:matrix.org?label=Community%20channel)](https://app.element.io/#/room/#keepassxc:mozilla.org)
[![Matrix development channel](https://img.shields.io/matrix/keepassxc-dev:matrix.org?label=Development%20channel)](https://app.element.io/#/room/#keepassxc-dev:mozilla.org)

[KeePassXC](https://keepassxc.org) is a modern, secure, and open-source password manager that stores and manages your most sensitive information. You can run KeePassXC on Windows, macOS, and Linux systems. KeePassXC is for people with extremely high demands of secure personal data management. It saves many different types of information, such as usernames, passwords, URLs, attachments, and notes in an offline, encrypted file that can be stored in any location, including private and public cloud solutions. For easy identification and management, user-defined titles and icons can be specified for entries. In addition, entries are sorted into customizable groups. An integrated search function allows you to use advanced patterns to easily find any entry in your database. A customizable, fast, and easy-to-use password generator utility allows you to create passwords with any combination of characters or easy to remember passphrases.

## Quick Start
The [QuickStart Guide](https://keepassxc.org/docs/KeePassXC_GettingStarted.html) gets you started using KeePassXC on your Windows, macOS, or Linux computer using pre-compiled binaries from the [downloads page](https://keepassxc.org/download). Additionally, individual Linux distributions may ship their own versions, so please check your distribution's package list to see if KeePassXC is available. Detailed documentation is available in the [User Guide](https://keepassxc.org/docs/KeePassXC_UserGuide.html).

## Features List
KeePassXC has numerous features for novice and power users alike. Our goal is to create an application that can be used by anyone while still offering advanced features to those that need them.

### Basic
* Create, open, and save databases in the KDBX format (KeePass-compatible with KDBX4 and KDBX3)
* Store sensitive information in entries that are organized by groups
* Search for entries
* Password generator
* Auto-Type passwords into applications
* Browser integration with Google Chrome, Mozilla Firefox, Microsoft Edge, Chromium, Vivaldi, Brave, and Tor-Browser
* Support for passkeys using the browser integration
* Entry icon download
* Import databases from CSV, 1Password, Bitwarden, Proton Pass, and KeePass1 formats

### Advanced
* Database reports (password health, HIBP, and statistics)
* Database export to CSV, XML, and HTML formats
* TOTP storage and generation
* Field references between entries
* File attachments and custom attributes
* Entry history and data restoration
* YubiKey/OnlyKey challenge-response support
* Command line interface (keepassxc-cli)
* Auto-Open databases
* KeeShare shared databases (import, export, and synchronize)
* SSH Agent integration
* FreeDesktop.org Secret Service (replace Gnome keyring, etc.)
* Additional encryption choices: Twofish and ChaCha20

For a full list of changes, read the [CHANGELOG](CHANGELOG.md) document. \
For a full list of keyboard shortcuts, see [KeyboardShortcuts.adoc](./docs/topics/KeyboardShortcuts.adoc)

## Building KeePassXC

Detailed instructions are available in the [Build and Install](./INSTALL.md) page and in the [Wiki](https://github.com/keepassxreboot/keepassxc/wiki/Building-KeePassXC).

## Contributing

We are always looking for suggestions on how to improve KeePassXC. If you find any bugs or have an idea for a new feature, please let us know by opening a report in the [issue tracker](https://github.com/keepassxreboot/keepassxc/issues) on GitHub, or join us on [Matrix community channel](https://matrix.to/#/!zUxwGnFkUyycpxeHeM:matrix.org?via=matrix.org) or [Matrix development channel](https://matrix.to/#/!RhJPJPGwQIFVQeXqZa:matrix.org?via=matrix.org), or on IRC in [Libera.Chat](https://web.libera.chat/) channels #keepassxc and #keepassxc-dev.

You may directly contribute your own code by submitting a pull request. Please read the [CONTRIBUTING](.github/CONTRIBUTING.md) document for further information.

Contributors are required to adhere to the project's [Code of Conduct](CODE_OF_CONDUCT.md).

## License

KeePassXC code is licensed under GPL-2 or GPL-3. Additional licensing for third-party files is detailed in [COPYING](./COPYING).
