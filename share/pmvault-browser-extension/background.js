/*
 * PmVault Browser Bridge - MV3 background service worker.
 *
 * Speaks the KeePassXC-Browser native messaging protocol against the bundled
 * keepassxc-proxy.exe (host name org.keepassxc.keepassxc_browser):
 *   change-public-keys (plaintext) -> associate / test-associate / get-logins /
 *   set-login / generate-password (all NaCl box encrypted after the handshake).
 *
 * No credentials are ever stored in the extension: the desktop KDBX database is
 * the only source of truth. Filling always requires an unlocked database; the
 * desktop app raises its own unlock dialog when a request arrives.
 */

try {
  importScripts("vendor/tweetnacl.js", "vendor/nacl-util.js");
} catch (e) {
  // Surface load failures instead of failing silently.
  console.error("PmVault bridge failed to load crypto vendors:", e);
}

const HOST_NAME = "org.keepassxc.keepassxc_browser";
const STORE_KEYS = ["clientPublicKey", "clientSecretKey", "idKey", "clientID"];

const state = {
  port: null,
  connected: false, // native port open
  serverPublicKey: null, // Uint8Array
  keyPair: null, // {publicKey, secretKey} Uint8Array
  idKey: null,
  clientID: null,
  associated: false,
  pending: new Map(), // nonceB64 -> {resolve, reject}
  connecting: null // Promise for an in-flight port open
};

function log(...args) {
  // Keep logs terse; nothing sensitive (passwords) is logged.
  console.log("[PmVault]", ...args);
}

function b64ToU8(b) {
  return self.PmpUtil.base64ToBytes(b);
}
function u8ToB64(u) {
  return self.PmpUtil.bytesToBase64(u);
}

function loadKeys() {
  return chrome.storage.local.get(STORE_KEYS).then((s) => {
    if (s.clientPublicKey && s.clientSecretKey) {
      state.keyPair = {
        publicKey: b64ToU8(s.clientPublicKey),
        secretKey: b64ToU8(s.clientSecretKey)
      };
      state.idKey = s.idKey || null;
      state.clientID = s.clientID || self.PmpUtil.randomBase64(16);
    }
  });
}

function saveKeys() {
  return chrome.storage.local.set({
    clientPublicKey: u8ToB64(state.keyPair.publicKey),
    clientSecretKey: u8ToB64(state.keyPair.secretKey),
    idKey: state.idKey,
    clientID: state.clientID
  });
}

function ensureKeys() {
  if (!state.keyPair) {
    state.keyPair = nacl.box.keyPair();
  }
  if (!state.idKey) {
    // Stable identifier stored in the desktop database for this association.
    state.idKey = self.PmpUtil.randomBase64(16);
  }
  if (!state.clientID) {
    state.clientID = self.PmpUtil.randomBase64(16);
  }
}

function openPort() {
  if (state.connected) {
    return Promise.resolve();
  }
  if (state.connecting) {
    return state.connecting;
  }
  state.connecting = new Promise((resolve, reject) => {
    let port;
    try {
      port = chrome.runtime.connectNative(HOST_NAME);
    } catch (e) {
      state.connecting = null;
      reject(new Error("NATIVE_HOST_MISSING"));
      return;
    }
    state.port = port;

    const onMsg = (msg) => {
      try {
        handleNativeMessage(msg);
      } catch (e) {
        console.error("[PmVault] message handling error", e);
      }
    };
    const onDisconnect = () => {
      const err = chrome.runtime.lastError;
      log("native port disconnected", err && err.message);
      state.connected = false;
      state.serverPublicKey = null;
      state.associated = false;
      state.port = null;
      const pend = state.pending;
      state.pending = new Map();
      for (const p of pend.values()) {
        p.reject(new Error("NATIVE_DISCONNECTED"));
      }
    };
    port.onMessage.addListener(onMsg);
    port.onDisconnect.addListener(onDisconnect);

    // Give the host a moment to spin up.
    setTimeout(() => {
      state.connected = true;
      state.connecting = null;
      resolve();
    }, 150);
  });
  return state.connecting;
}

function postRaw(obj) {
  if (!state.port) {
    return Promise.reject(new Error("NOT_CONNECTED"));
  }
  state.port.postMessage(obj);
  return Promise.resolve();
}

// Wait for the response correlated by the nonce we sent.
function waitFor(nonceB64, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (state.pending.has(nonceB64)) {
        state.pending.delete(nonceB64);
        reject(new Error("TIMEOUT"));
      }
    }, timeoutMs);
    state.pending.set(nonceB64, {
      resolve: (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      reject: (e) => {
        clearTimeout(timer);
        reject(e);
      }
    });
  });
}

function decryptResponse(msg) {
  if (!msg || typeof msg.message !== "string" || !msg.nonce) {
    return msg && msg.message ? msg.message : msg;
  }
  const box = b64ToU8(msg.message);
  const nonce = b64ToU8(msg.nonce);
  const opened = nacl.box.open(box, nonce, state.serverPublicKey, state.keyPair.secretKey);
  if (!opened) {
    throw new Error("DECRYPT_FAILED");
  }
  return JSON.parse(self.PmpUtil.bytesToUtf8(opened));
}

function handleNativeMessage(msg) {
  // Plaintext handshake reply.
  if (msg.action === "change-public-keys" && msg.message && msg.message.publicKey) {
    state.serverPublicKey = b64ToU8(msg.message.publicKey);
    const nonce = msg.nonce;
    if (nonce && state.pending.has(nonce)) {
      state.pending.get(nonce).resolve(msg.message);
      state.pending.delete(nonce);
    }
    return;
  }
  // Database unlock request forwarded by the proxy (informational).
  if (msg.action === "request-unlock" || msg.action === "database-locked") {
    chrome.runtime.sendMessage({ type: "database-locked" }).catch(() => {});
  }
  if (msg.nonce && state.pending.has(msg.nonce)) {
    let parsed;
    try {
      parsed = decryptResponse(msg);
    } catch (e) {
      state.pending.get(msg.nonce).reject(e);
      state.pending.delete(msg.nonce);
      return;
    }
    state.pending.get(msg.nonce).resolve(parsed);
    state.pending.delete(msg.nonce);
  }
}

function encryptPayload(payloadObj) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const data = self.PmpUtil.utf8ToBytes(JSON.stringify(payloadObj));
  const box = nacl.box(data, nonce, state.serverPublicKey, state.keyPair.secretKey);
  return { nonceB64: u8ToB64(nonce), boxB64: u8ToB64(box) };
}

// Plaintext key exchange. Must complete before any encrypted request.
function changePublicKeys() {
  ensureKeys();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const nonceB64 = u8ToB64(nonce);
  const message = {
    action: "change-public-keys",
    publicKey: u8ToB64(state.keyPair.publicKey),
    nonce: nonceB64,
    clientID: state.clientID
  };
  const p = waitFor(nonceB64);
  return postRaw({ action: "change-public-keys", message })
    .then(() => p)
    .then((resp) => {
      if (!resp || !resp.publicKey) {
        throw new Error("HANDSHAKE_FAILED");
      }
      return true;
    });
}

function encryptedRequest(payloadObj, timeoutMs) {
  return openPort()
    .then(() => {
      if (!state.serverPublicKey) {
        return changePublicKeys();
      }
      return true;
    })
    .then(() => {
      const { nonceB64, boxB64 } = encryptPayload(payloadObj);
      const p = waitFor(nonceB64, timeoutMs);
      return postRaw({
        action: payloadObj.action,
        message: boxB64,
        nonce: nonceB64,
        clientID: state.clientID
      }).then(() => p);
    });
}

function associate() {
  ensureKeys();
  const payload = {
    action: "associate",
    key: u8ToB64(state.keyPair.publicKey),
    idKey: state.idKey
  };
  return encryptedRequest(payload, 20000)
    .then((resp) => {
      const ok = resp && (resp.success === true || resp.message === "associated" || resp.hash);
      if (!ok) {
        throw new Error((resp && resp.errorCode) || "ASSOCIATE_FAILED");
      }
      state.associated = true;
      return saveKeys().then(() => true);
    });
}

function testAssociate() {
  if (!state.keyPair || !state.idKey) {
    return Promise.resolve(false);
  }
  const payload = {
    action: "test-associate",
    idKey: state.idKey,
    key: u8ToB64(state.keyPair.publicKey)
  };
  return encryptedRequest(payload, 8000)
    .then((resp) => !!(resp && (resp.success === true || resp.hash)))
    .catch(() => false);
}

function ensureAssociated() {
  return openPort()
    .then(() => {
      if (!state.serverPublicKey) {
        return changePublicKeys();
      }
      return true;
    })
    .then(() => testAssociate())
    .then((ok) => {
      if (ok) {
        state.associated = true;
        return true;
      }
      return associate();
    });
}

function normalizeEntries(resp) {
  const list = (resp && resp.entries) || [];
  return list.map((e) => ({
    name: e.name || e.title || "",
    login: e.login || e.username || "",
    password: e.password || "",
    uuid: e.uuid || "",
    url: e.url || ""
  }));
}

function getLogins(url) {
  const payload = {
    action: "get-logins",
    url: url,
    submitUrl: url,
    httpAuth: false,
    searchInAllDatabases: true,
    keys: [{ idKey: state.idKey, key: u8ToB64(state.keyPair.publicKey) }]
  };
  return encryptedRequest(payload, 20000).then((resp) => {
    if (resp && resp.action === "error") {
      throw new Error(resp.errorCode || "GET_LOGINS_FAILED");
    }
    return normalizeEntries(resp);
  });
}

function setLogin(details) {
  const payload = {
    action: "set-login",
    url: details.url,
    submitUrl: details.submitUrl || details.url,
    uuid: details.uuid || "",
    groupUuid: "",
    downloadFavicon: false,
    username: details.username || "",
    password: details.password || "",
    title: details.title || "",
    httpRealm: "",
    notes: "Saved by PmVault Browser Bridge"
  };
  return encryptedRequest(payload, 20000).then((resp) => {
    if (resp && resp.action === "error" && resp.errorCode) {
      throw new Error(resp.errorCode);
    }
    return resp;
  });
}

function generatePassword() {
  return encryptedRequest({ action: "generate-password" }, 10000).then((resp) => resp.password || "");
}

function status() {
  return {
    nativeConnected: state.connected,
    associated: state.associated,
    hasKeys: !!state.keyPair,
    host: HOST_NAME
  };
}

// ---- message routing from popup / content scripts ----
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tab = sender.tab;
  const reply = (obj) => {
    try {
      sendResponse(obj);
    } catch (e) {
      /* port already closed */
    }
  };

  (async () => {
    try {
      switch (msg.type) {
        case "status":
          reply({ ok: true, ...status() });
          break;

        case "associate":
          await ensureAssociated();
          reply({ ok: true, ...status() });
          break;

        case "query": {
          await ensureAssociated();
          const url = msg.url || (tab && tab.url) || "";
          const entries = await getLogins(url);
          reply({ ok: true, entries });
          break;
        }

        case "fill-tab": {
          // Popup asks us to push a chosen entry into a specific tab.
          const targetId = msg.tabId;
          await chrome.tabs.sendMessage(targetId, { type: "do-fill", entry: msg.entry });
          reply({ ok: true });
          break;
        }

        case "save": {
          await ensureAssociated();
          const url = msg.url || (tab && tab.url) || "";
          const title = msg.title || (tab && tab.title) || "";
          await setLogin({
            url,
            title,
            username: msg.username,
            password: msg.password,
            uuid: msg.uuid || ""
          });
          reply({ ok: true });
          break;
        }

        case "generate": {
          await ensureAssociated();
          const password = await generatePassword();
          reply({ ok: true, password });
          break;
        }

        case "active-tab": {
          const [active] = await chrome.tabs.query({ active: true, currentWindow: true });
          reply({ ok: true, tab: active ? { id: active.id, url: active.url, title: active.title } : null });
          break;
        }

        default:
          reply({ ok: false, error: "UNKNOWN_REQUEST" });
      }
    } catch (e) {
      reply({ ok: false, error: friendlyError(e) });
    }
  })();

  return true; // keep the message channel open for the async response
});

function friendlyError(e) {
  const code = (e && e.message) || String(e);
  if (code === "NATIVE_HOST_MISSING" || code === "NATIVE_DISCONNECTED") {
    return "未找到/未连接 PmVault 本地代理。请确认桌面端已运行、已在“浏览器集成”中启用，并已安装本机原生消息主机（见扩展安装说明）。";
  }
  if (code === "DATABASE_NOT_OPENED" || code === "DATABASE_NOT_UNLOCKED" || code === "KEEPASS_DATABASE_NOT_OPENED") {
    return "请先在 PmVault 桌面端打开并解锁数据库。";
  }
  if (code === "TIMEOUT") {
    return "桌面端无响应：请确认已解锁数据库并在弹窗中允许本扩展关联。";
  }
  if (code === "ASSOCIATE_FAILED") {
    return "关联失败：请在桌面端弹出的确认框中选择允许，然后重试。";
  }
  return code;
}

// Re-establish keys on worker start.
loadKeys();
