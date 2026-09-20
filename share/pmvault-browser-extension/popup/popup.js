/* PmVault Browser Bridge - popup logic */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  let activeTab = null;

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
    const el = $("status");
    el.textContent = text;
    el.className = "status " + cls;
  }

  function normalizeUrl(raw) {
    let s = (raw || "").trim();
    if (!s) {
      return "";
    }
    if (!/^https?:\/\//i.test(s)) {
      s = "https://" + s;
    }
    return s;
  }

  function copy(text) {
    navigator.clipboard.writeText(text).catch(() => {});
  }

  function renderError(container, text) {
    container.innerHTML = "";
    const d = document.createElement("div");
    d.className = "error";
    d.textContent = text;
    container.appendChild(d);
  }

  function renderEntries(entries) {
    const box = $("results");
    box.innerHTML = "";
    if (!entries || !entries.length) {
      const d = document.createElement("div");
      d.className = "empty";
      d.textContent = "没有匹配条目。确认桌面端已解锁，或换一个网站地址搜索。";
      box.appendChild(d);
      return;
    }
    entries.forEach((entry) => {
      const card = document.createElement("div");
      card.className = "entry";

      const name = document.createElement("div");
      name.className = "name";
      name.textContent = entry.name || entry.login || "(未命名)";
      const login = document.createElement("div");
      login.className = "login";
      login.textContent = entry.login || "";
      card.appendChild(name);
      card.appendChild(login);

      const actions = document.createElement("div");
      actions.className = "actions";

      const fill = document.createElement("button");
      fill.className = "primary";
      fill.textContent = "自动填写";
      fill.addEventListener("click", async () => {
        if (!activeTab) {
          return;
        }
        const r = await send({ type: "fill-tab", tabId: activeTab.id, entry });
        if (!r.ok) {
          renderError(box, r.error);
        } else {
          window.close();
        }
      });

      const copyUser = document.createElement("button");
      copyUser.textContent = "复制用户名";
      copyUser.addEventListener("click", () => copy(entry.login || ""));

      const copyPw = document.createElement("button");
      copyPw.textContent = "复制密码";
      copyPw.addEventListener("click", () => copy(entry.password || ""));

      actions.appendChild(fill);
      actions.appendChild(copyUser);
      actions.appendChild(copyPw);
      card.appendChild(actions);
      box.appendChild(card);
    });
  }

  async function doSearch() {
    const url = normalizeUrl($("q").value) || (activeTab && activeTab.url) || "";
    if (!url) {
      renderError($("results"), "请输入网站地址。");
      return;
    }
    $("results").innerHTML = '<div class="empty">查询中…</div>';
    const r = await send({ type: "query", url });
    if (!r.ok) {
      renderError($("results"), r.error);
      setStatus("需要连接/解锁", "status-err");
      return;
    }
    setStatus("已连接", "status-ok");
    renderEntries(r.entries);
  }

  async function refreshStatus() {
    const r = await send({ type: "status" });
    if (r.ok && r.associated) {
      setStatus("已连接", "status-ok");
    } else if (r.ok && r.nativeConnected) {
      setStatus("待关联", "status-warn");
    } else {
      setStatus("未连接", "status-warn");
    }
  }

  async function init() {
    const t = await send({ type: "active-tab" });
    if (t.ok && t.tab && /^https?:/i.test(t.tab.url || "")) {
      activeTab = t.tab;
      try {
        const u = new URL(activeTab.url);
        $("q").value = u.hostname;
        $("urlHint").textContent = "当前页面：" + u.hostname;
      } catch (e) {
        $("q").value = activeTab.url || "";
      }
    }
    await refreshStatus();
    // Auto-query the active tab once; if the database is locked the desktop app
    // raises its unlock dialog and the user can press Search again.
    if (activeTab) {
      doSearch();
    }

    $("searchBtn").addEventListener("click", doSearch);
    $("q").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        doSearch();
      }
    });
    $("associateBtn").addEventListener("click", async () => {
      setStatus("连接中…", "status-warn");
      const r = await send({ type: "associate" });
      if (r.ok) {
        setStatus("已连接", "status-ok");
        doSearch();
      } else {
        renderError($("results"), r.error);
        setStatus("连接失败", "status-err");
      }
    });
    $("optionsBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());
  }

  document.addEventListener("DOMContentLoaded", init);
})();
