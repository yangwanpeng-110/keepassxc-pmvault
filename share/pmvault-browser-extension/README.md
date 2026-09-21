# PmVault Browser Bridge（浏览器扩展）

PmVault 桌面端的 Chromium 浏览器桥接扩展（Manifest V3），通过随桌面端一起构建的
`keepassxc-proxy.exe` 原生消息主机工作，协议与 KeePassXC-Browser 兼容（NaCl / curve25519
握手，AES-GCM 由 tweetnacl 的 secretbox/box 承载）。**所有密码只保存在本地 KDBX 数据库中，
扩展本身不存储任何凭据，也不经过任何网络服务器。**

## 功能

- 网页出现密码框时，右下角显示 PmVault 悬浮条：
  - **填充**：向桌面端查询匹配条目；数据库锁定时桌面端会弹出解锁窗口，解锁后选择条目自动填写用户名和密码（模拟真实 input/change 事件，兼容绝大多数网页）。
  - **保存**：提交登录表单后提示“保存该登录到 PmVault？”，一键写入数据库。
  - **更新密码（类 Edge）**：提交时若该网址下已存在**相同用户名、但密码不同**的条目，会主动提示
    “密码已更改，是否更新”，可选择**更新密码**（按条目 uuid 覆盖原条目）、**新建条目**或**忽略**；
    账号密码都没变则不打扰。数据库锁定时查询不到旧条目，会自动退回“保存新条目”，不影响保存。
- 工具栏弹窗：按网站地址搜索数据库条目，支持**自动填写到当前标签页**、**复制用户名 / 复制密码**。
- 多匹配时在悬浮条中列出候选；单匹配直接填写。

> 说明：KDBX 在锁定状态下无法读写，因此“保存新密码”同样需要桌面端处于已解锁状态
> （点击保存时桌面端会自动弹出解锁窗口，解锁后自动完成写入）。这是 KDBX 加密模型的固有限制，
> 扩展无法绕过。

## 一、加载扩展（Chrome / Edge）

1. 打开 `chrome://extensions`（Edge 为 `edge://extensions`）。
2. 右上角打开“开发者模式”。
3. 选择“加载已解压的扩展程序”，选择本目录 `pmvault-browser-extension`。
4. 加载后扩展 ID 固定为：`efcjblaacddijgiakoocgkhdmihlgpfp`
   （`manifest.json` 内置了固定公钥，因此 ID 不会变化，原生主机清单才能匹配）。

## 二、注册原生消息主机（Windows）

桌面端压缩包解压后，目录中包含 `keepassxc-proxy.exe`。

- 自动：双击 `host/install-host.bat`（若脚本与 `keepassxc-proxy.exe` 不在相邻目录，
  请在命令行执行）：

  ```bat
  install-host.bat "C:\完整路径\PmVault-windows-x64\keepassxc-proxy.exe"
  ```

  脚本会写入 `%LOCALAPPDATA%\PmVault\host\org.keepassxc.keepassxc_browser.json`，
  并为 **Chrome、Edge、Chromium** 注册当前用户的 NativeMessagingHosts 注册表项。
- 卸载：双击 `host/uninstall-host.bat`。

## 三、在桌面端启用浏览器集成

1. 运行 PmVault 桌面端并打开、解锁数据库。
2. 进入 **设置（Settings）→ 浏览器集成（Browser Integration）**，
   勾选 **Google Chrome / Microsoft Edge**（或“自定义浏览器配置/原生消息”）。
3. 首次在扩展里点“连接并关联桌面端”时，桌面端会弹出关联确认，选择允许并保存。

## 四、使用

- 打开任意登录页，点悬浮条的“填充”，或点工具栏图标搜索后“自动填写”。
- 登录提交后点“保存”即可把新账号写入数据库。

## 文件结构

```
pmvault-browser-extension/
├─ manifest.json
├─ background.js            # service worker：原生消息 + NaCl 加解密 + 路由
├─ vendor/
│  ├─ tweetnacl.js          # 第三方库 tweetnacl 1.0.3（本地内置，无远程脚本）
│  └─ nacl-util.js          # base64/UTF-8 工具
├─ content/                 # 网页悬浮条、表单检测与填写
├─ popup/                   # 工具栏弹窗：搜索 / 复制 / 自动填写
├─ options/                 # 连接状态与安装指引
├─ icons/                   # 16/48/128 图标
└─ host/                    # Windows 原生消息主机注册脚本与清单模板
```

## 安全说明

- 浏览器与 `keepassxc-proxy.exe` 之间是浏览器原生消息管道（本机 stdio），不监听 TCP 端口。
- 握手后所有业务消息均使用 nacl.box（X25519 + XSalsa20-Poly1305）端到端加密，
  浏览器侧仅信任桌面端返回的公钥，首次关联需用户在桌面端确认。
- MV3 不加载任何远程脚本，加密库已 vendor 到本目录。
