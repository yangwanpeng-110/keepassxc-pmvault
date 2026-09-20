/* PmVault Browser Bridge - options page */
(function () {
  "use strict";

  function send(msg) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(msg, (resp) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(resp || { ok: false, error: "NO_RESPONSE" });
        }
      });
    });
  }

  function setStatus(text, cls) {
    const el = document.getElementById("status");
    el.textContent = text;
    el.className = cls;
  }

  async function refresh() {
    const r = await send({ type: "status" });
    if (!r.ok) {
      setStatus("后台未就绪", "status-err");
    } else if (r.associated) {
      setStatus("已连接并关联", "status-ok");
    } else if (r.nativeConnected) {
      setStatus("已连接，待关联", "status-warn");
    } else {
      setStatus("未连接到桌面端", "status-warn");
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const idEl = document.getElementById("extid");
    idEl.textContent = chrome.runtime.id || "(加载后生成)";
    refresh();
    document.getElementById("connect").addEventListener("click", async () => {
      document.getElementById("msg").textContent = "正在连接，请在桌面端弹窗中选择允许…";
      const r = await send({ type: "associate" });
      if (r.ok) {
        document.getElementById("msg").textContent = "关联成功。";
      } else {
        document.getElementById("msg").textContent = r.error || "关联失败。";
      }
      refresh();
    });
  });
})();
