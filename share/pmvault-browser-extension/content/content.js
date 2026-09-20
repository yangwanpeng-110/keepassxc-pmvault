/*
 * PmVault Browser Bridge - content script.
 * Shows a small, non-intrusive bar on pages with password fields:
 *   - "Fill": query the desktop database (raises the desktop unlock dialog if
 *     locked), then fill username + password with native input events.
 *   - "Save": after a login form is submitted, offer to store the typed
 *     credentials in the database.
 * All secrets come from / go to the background worker; nothing is persisted here.
 */
(function () {
  "use strict";

  if (window.__pmvaultInjected) {
    return;
  }
  window.__pmvaultInjected = true;

  function send(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (resp) => {
          if (chrome.runtime.lastError) {
            resolve({ ok: false, error: chrome.runtime.lastError.message });
          } else {
            resolve(resp || { ok: false, error: "NO_RESPONSE" });
          }
        });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      }
    });
  }

  function passwordInputs() {
    return Array.from(document.querySelectorAll('input[type="password"]')).filter(
      (el) => el && el.offsetParent !== null && !el.disabled && !el.readOnly
    );
  }

  function guessUsernameInput(pw) {
    const form = pw.form;
    const scope = form ? form : document;
    const candidates = Array.from(
      scope.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])')
    ).filter((el) => el.offsetParent !== null && !el.disabled && !el.readOnly);

    const autocomp = candidates.find((el) => {
      const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
      return ac.includes("username") || ac.includes("email");
    });
    if (autocomp) {
      return autocomp;
    }
    const named = candidates.find((el) => {
      const n = ((el.name || "") + " " + (el.id || "")).toLowerCase();
      return /user|name|email|account|login|uid/.test(n);
    });
    if (named) {
      return named;
    }
    // Nearest visible text input above the password field.
    const visibleBefore = candidates.filter((el) => {
      const r = el.getBoundingClientRect();
      const pr = pw.getBoundingClientRect();
      return r.top <= pr.top + 4 && Math.abs(r.left - pr.left) < pr.width;
    });
    return visibleBefore[visibleBefore.length - 1] || null;
  }

  function setNativeValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value");
    if (setter && setter.set) {
      setter.set.call(el, value);
    } else {
      el.value = value;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fillEntry(entry) {
    const pws = passwordInputs();
    if (!pws.length) {
      return false;
    }
    // Prefer a visible password field that is not a "new password" confirmation.
    const pw =
      pws.find((el) => {
        const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
        return ac.includes("current-password");
      }) || pws[0];
    const user = guessUsernameInput(pw);
    if (entry.login && user) {
      setNativeValue(user, entry.login);
    }
    setNativeValue(pw, entry.password);
    // Fill any other current-password fields (some pages split the form).
    pws.forEach((el) => {
      if (el !== pw) {
        const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
        if (!ac.includes("new-password")) {
          setNativeValue(el, entry.password);
        }
      }
    });
    pw.focus();
    return true;
  }

  function removeBar() {
    const b = document.getElementById("pmvault-bar");
    if (b) {
      b.remove();
    }
    const p = document.getElementById("pmvault-panel");
    if (p) {
      p.remove();
    }
  }

  function showBar(html, actions) {
    removeBar();
    const bar = document.createElement("div");
    bar.id = "pmvault-bar";
    bar.innerHTML =
      '<span class="pmvault-logo">P</span><span class="pmvault-text"></span>' + html;
    bar.querySelector(".pmvault-text").textContent = "";
    document.documentElement.appendChild(bar);
    actions(bar);
    return bar;
  }

  function showPanel() {
    let panel = document.getElementById("pmvault-panel");
    if (panel) {
      panel.remove();
      return;
    }
    panel = document.createElement("div");
    panel.id = "pmvault-panel";
    document.documentElement.appendChild(panel);
    return panel;
  }

  function showFillBar() {
    const bar = showBar("", (b) => {
      b.querySelector(".pmvault-text").textContent = "PmVault";
      const fill = document.createElement("button");
      fill.className = "pmvault-primary";
      fill.textContent = "填充";
      const close = document.createElement("span");
      close.className = "pmvault-x";
      close.textContent = "×";
      b.appendChild(fill);
      b.appendChild(close);
      fill.addEventListener("click", onFillClick);
      close.addEventListener("click", removeBar);
    });
    return bar;
  }

  async function onFillClick() {
    const panel = showPanel();
    panel.innerHTML = '<div class="pmvault-empty">正在查询数据库…</div>';
    const resp = await send({ type: "query", url: location.href });
    if (!resp.ok) {
      panel.innerHTML = "";
      const err = document.createElement("div");
      err.className = "pmvault-err";
      err.textContent = resp.error || "查询失败";
      panel.appendChild(err);
      return;
    }
    const entries = resp.entries || [];
    if (!entries.length) {
      panel.innerHTML = '<div class="pmvault-empty">未找到匹配的条目，可在扩展弹窗中按网址搜索。</div>';
      return;
    }
    if (entries.length === 1) {
      fillEntry(entries[0]);
      removeBar();
      return;
    }
    panel.innerHTML = "";
    entries.forEach((entry) => {
      const row = document.createElement("a");
      row.className = "pmvault-row";
      const name = document.createElement("b");
      name.textContent = entry.name || entry.login || "(未命名)";
      const login = document.createElement("span");
      login.textContent = entry.login || "";
      row.appendChild(name);
      row.appendChild(login);
      row.addEventListener("click", () => {
        fillEntry(entry);
        removeBar();
      });
      panel.appendChild(row);
    });
  }

  function showSaveBar(username, password) {
    // Avoid duplicate bars.
    if (document.getElementById("pmvault-bar") && document.getElementById("pmvault-bar").dataset.mode === "save") {
      return;
    }
    const bar = showBar("", (b) => {
      b.dataset.mode = "save";
      b.querySelector(".pmvault-text").textContent = "保存该登录到 PmVault？";
      const save = document.createElement("button");
      save.className = "pmvault-primary";
      save.textContent = "保存";
      const ignore = document.createElement("button");
      ignore.className = "pmvault-ghost";
      ignore.textContent = "忽略";
      b.appendChild(save);
      b.appendChild(ignore);
      save.addEventListener("click", async () => {
        save.disabled = true;
        save.textContent = "保存中…";
        const resp = await send({
          type: "save",
          url: location.href,
          title: document.title,
          username,
          password
        });
        if (resp.ok) {
          removeBar();
        } else {
          save.disabled = false;
          save.textContent = "保存";
          b.querySelector(".pmvault-text").textContent = resp.error || "保存失败";
        }
      });
      ignore.addEventListener("click", removeBar);
    });
  }

  // Capture credentials when a login form is submitted.
  document.addEventListener(
    "submit",
    (ev) => {
      const form = ev.target;
      if (!form || !form.querySelectorAll) {
        return;
      }
      const pws = Array.from(form.querySelectorAll('input[type="password"]')).filter(
        (el) => el.offsetParent !== null
      );
      if (!pws.length) {
        return;
      }
      // Ignore sign-up / change-password forms with two different new passwords.
      if (pws.length >= 2 && pws[0].value && pws[1].value && pws[0].value !== pws[1].value) {
        return;
      }
      const pw = pws[0];
      const userEl = guessUsernameInput(pw);
      const username = userEl ? userEl.value : "";
      const password = pw.value;
      if (!password) {
        return;
      }
      setTimeout(() => showSaveBar(username, password), 400);
    },
    true
  );

  // Fill requests coming from the popup.
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "do-fill" && msg.entry) {
      fillEntry(msg.entry);
    }
  });

  // Show the fill bar when the page has a password field.
  function maybeShow() {
    if (passwordInputs().length && !document.getElementById("pmvault-bar")) {
      showFillBar();
    }
  }
  if (document.readyState === "complete" || document.readyState === "interactive") {
    setTimeout(maybeShow, 300);
  } else {
    window.addEventListener("DOMContentLoaded", () => setTimeout(maybeShow, 300));
  }
})();
