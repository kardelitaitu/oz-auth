import { invoke } from "@tauri-apps/api/core";
import { startCamera, stopCamera, scanImage } from "./js/qr-scanner.js";

// ── DOM refs ──────────────────────────────────────────────
const titleText = document.getElementById("title-text");
const btnPin = document.getElementById("btn-pin");
const btnMin = document.getElementById("btn-minimize");
const btnClose = document.getElementById("btn-close");
const accountList = document.getElementById("account-list");
const searchInput = document.getElementById("search");
const btnAdd = document.getElementById("btn-add");
const btnTheme = document.getElementById("btn-theme");
const btnSettings = document.getElementById("btn-settings");
const lockOverlay = document.getElementById("lock-overlay");
const lockInput = document.getElementById("lock-input");
const lockSubmit = document.getElementById("lock-submit");
const lockError = document.getElementById("lock-error");
const toastBar = document.getElementById("toast-bar");
const dialog = document.getElementById("account-dialog");
const dialogTitle = document.getElementById("dialog-title");
const dialogIssuer = document.getElementById("dialog-issuer");
const dialogLabel = document.getElementById("dialog-label");
const dialogSecret = document.getElementById("dialog-secret");
const dialogAlgorithm = document.getElementById("dialog-algorithm");
const dialogDigits = document.getElementById("dialog-digits");
const dialogPeriod = document.getElementById("dialog-period");
const dialogSubmit = document.getElementById("dialog-submit");
const dialogCancel = document.getElementById("dialog-cancel");
const dialogScan = document.getElementById("dialog-scan");
const qrOverlay = document.getElementById("qr-overlay");
const qrCancel = document.getElementById("qr-cancel");
const settingsOverlay = document.getElementById("settings-overlay");
const settingsTitle = document.getElementById("settings-title");
const settingsBody = document.getElementById("settings-body");
const settingsCancel = document.getElementById("settings-cancel");
const contextMenu = document.getElementById("context-menu");

// ── State ──────────────────────────────────────────────────
let accounts = [];
let locked = false;
let countdownInterval = null;
let clipboardTimer = null;
let autoLockTimer = null;
let lastActivity = Date.now();
let contextAccountId = null;
let lockTimeoutMinutes = 5;
let passwordProtected = false;

// ── Toast ──────────────────────────────────────────────────
function toast(msg, isError = false) {
  toastBar.textContent = msg;
  toastBar.className = isError ? "error" : "";
  toastBar.classList.remove("hidden");
  setTimeout(() => toastBar.classList.add("hidden"), 3000);
}

// ── Lock overlay ───────────────────────────────────────────
async function checkLock() {
  try {
    locked = await invoke("is_locked");
    if (locked) showLock();
  } catch (e) {
    console.error("is_locked error:", e);
  }
}

function showLock() {
  lockOverlay.classList.remove("hidden");
  lockError.classList.add("hidden");
  lockInput.value = "";
  stopAutoLock();
  setTimeout(() => lockInput.focus(), 100);
}

function hideLock() {
  lockOverlay.classList.add("hidden");
  startAutoLock();
}

lockSubmit.addEventListener("click", async () => {
  const pin = lockInput.value;
  if (!pin) return;
  lockSubmit.disabled = true;
  try {
    const ok = await invoke("unlock", { pin });
    if (ok) {
      locked = false;
      hideLock();
      await loadAccounts();
      startCountdown();
      resetActivity();
    } else {
      lockError.classList.remove("hidden");
      lockInput.value = "";
      lockInput.focus();
    }
  } catch (e) {
    lockError.textContent = typeof e === "string" ? e : "Wrong PIN.";
    lockError.classList.remove("hidden");
  } finally {
    lockSubmit.disabled = false;
  }
});

lockInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") lockSubmit.click();
});

// ── Auto-lock on inactivity ────────────────────────────────
function resetActivity() {
  lastActivity = Date.now();
}

function startAutoLock() {
  stopAutoLock();
  if (!passwordProtected || !lockTimeoutMinutes || lockTimeoutMinutes <= 0) return;
  autoLockTimer = setInterval(async () => {
    if (locked) return;
    const idle = (Date.now() - lastActivity) / 1000 / 60;
    if (idle >= lockTimeoutMinutes) {
      try {
        await invoke("lock");
        locked = true;
        stopCountdown();
        showLock();
      } catch (_) {}
    }
  }, 15000);
}

function stopAutoLock() {
  if (autoLockTimer) {
    clearInterval(autoLockTimer);
    autoLockTimer = null;
  }
}

// Track all user activity
["mousemove", "keydown", "mousedown", "wheel", "touchstart", "contextmenu"].forEach((evt) => {
  document.addEventListener(evt, resetActivity, { passive: true });
});

// ── Account loading ────────────────────────────────────────
async function loadAccounts(query = "") {
  if (locked) return;
  try {
    accounts = await invoke("list_accounts", { searchQuery: query || null });
    renderAccounts();
  } catch (e) {
    console.error("list_accounts error:", e);
  }
}

// ── Render ─────────────────────────────────────────────────
function renderAccounts() {
  accountList.innerHTML = "";
  if (accounts.length === 0) {
    accountList.innerHTML = '<div class="empty-state">No accounts yet.<br>Click + to add one.</div>';
    return;
  }
  accounts.forEach((a) => {
    const card = document.createElement("div");
    card.className = "account-card";
    card.dataset.id = a.id;
    card.innerHTML = `
      <div class="card-header">
        <span class="card-issuer">${escapeHtml(a.issuer)}</span>
        <div class="card-header-buttons">
          <button class="card-edit" title="Edit" data-id="${a.id}">✎</button>
          <button class="card-delete" title="Delete">×</button>
        </div>
      </div>
      <div class="card-label">${escapeHtml(a.label)}</div>
      <div class="card-code" data-id="${a.id}">------</div>
      <div class="card-bar"><div class="card-bar-fill" data-id="${a.id}"></div></div>
      <div class="card-timer" data-id="${a.id}">--s</div>
    `;
    // Copy code on click
    card.querySelector(".card-code").addEventListener("click", () => copyCode(a.id));
    // Edit button
    card.querySelector(".card-edit").addEventListener("click", (e) => {
      e.stopPropagation();
      openEditDialog(a.id);
    });
    // Delete button
    card.querySelector(".card-delete").addEventListener("click", (e) => {
      e.stopPropagation();
      deleteAccount(a.id);
    });
    // Right-click context menu
    card.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      showContextMenu(e.clientX, e.clientY, a.id);
    });
    accountList.appendChild(card);
  });
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

// ── Context menu ───────────────────────────────────────────
function showContextMenu(x, y, accountId) {
  contextAccountId = accountId;
  // Show first so we can measure
  contextMenu.classList.remove("hidden");
  const rect = contextMenu.getBoundingClientRect();
  const clampedX = Math.min(x, window.innerWidth - rect.width - 4);
  const clampedY = Math.min(y, window.innerHeight - rect.height - 4);
  contextMenu.style.left = `${Math.max(4, clampedX)}px`;
  contextMenu.style.top = `${Math.max(4, clampedY)}px`;
}

function hideContextMenu() {
  contextMenu.classList.add("hidden");
  contextAccountId = null;
}

document.addEventListener("click", (e) => {
  if (!contextMenu.contains(e.target)) hideContextMenu();
});

contextMenu.querySelector('[data-action="edit"]').addEventListener("click", () => {
  if (contextAccountId) openEditDialog(contextAccountId);
  hideContextMenu();
});

contextMenu.querySelector('[data-action="delete"]').addEventListener("click", () => {
  if (contextAccountId) deleteAccount(contextAccountId);
  hideContextMenu();
});

// ── Countdown / TOTP refresh ───────────────────────────────
let secondsRemaining = {};

async function refreshCodes() {
  if (locked) return;
  try {
    const codes = await invoke("generate_all_codes");
    codes.forEach(([id, code, remaining]) => {
      secondsRemaining[id] = remaining;
      const codeEl = document.querySelector(`.card-code[data-id="${id}"]`);
      if (codeEl) codeEl.textContent = formatCode(code);
    });
    updateBars();
  } catch (e) {
    console.error("generate_all_codes error:", e);
  }
}

function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

function startCountdown() {
  stopCountdown();
  refreshCodes();
  countdownInterval = setInterval(() => {
    let needsRefresh = true;
    let totalPct = 0;
    let count = 0;
    for (const id in secondsRemaining) {
      secondsRemaining[id]--;
      if (secondsRemaining[id] <= 0) {
        delete secondsRemaining[id];
        needsRefresh = true;
      }
      const a = accounts.find((a) => a.id === id);
      if (a && secondsRemaining[id] !== undefined) {
        totalPct += ((a.period - secondsRemaining[id]) / a.period) * 100;
        count++;
      }
    }
    updateBars();
    if (count > 0) {
      invoke("update_tray_icon", { pct: totalPct / count }).catch(() => {});
    }
    if (needsRefresh) refreshCodes();
  }, 1000);
}

function stopCountdown() {
  if (countdownInterval) {
    clearInterval(countdownInterval);
    countdownInterval = null;
  }
}

function updateBars() {
  accounts.forEach((a) => {
    const remaining = secondsRemaining[a.id] || a.period;
    const pct = ((a.period - remaining) / a.period) * 100;
    const fill = document.querySelector(`.card-bar-fill[data-id="${a.id}"]`);
    const timer = document.querySelector(`.card-timer[data-id="${a.id}"]`);
    if (fill) fill.style.width = `${pct}%`;
    if (timer) timer.textContent = `${Math.max(0, remaining)}s`;
  });
}

// ── Copy ───────────────────────────────────────────────────
async function copyCode(id) {
  const el = document.querySelector(`.card-code[data-id="${id}"]`);
  if (!el) return;
  const code = el.textContent.replace(/\s/g, "");
  try {
    await navigator.clipboard.writeText(code);
    toast("Code copied — auto-clears in 30s");
    if (clipboardTimer) clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(async () => {
      try {
        await navigator.clipboard.writeText("");
        toast("Clipboard cleared");
      } catch (_) {}
    }, 30000);
  } catch (e) {
    toast("Copy failed", true);
  }
}

// ── Delete ─────────────────────────────────────────────────
async function deleteAccount(id) {
  if (locked) return;
  try {
    await invoke("remove_account", { accountId: id });
    toast("Account deleted");
    hideContextMenu();
    await loadAccounts();
    refreshCodes();
  } catch (e) {
    toast("Delete failed", true);
  }
}

// ── Add / Edit Account dialog ──────────────────────────────
let editId = null;

function openEditDialog(id) {
  const account = accounts.find((a) => a.id === id);
  if (!account) return;
  editId = id;
  dialogTitle.textContent = "Edit Account";
  dialogIssuer.value = account.issuer;
  dialogLabel.value = account.label;
  dialogSecret.value = "";
  dialogSecret.style.display = "none";
  dialogAlgorithm.parentElement.style.display = "none";
  dialogDigits.parentElement.style.display = "none";
  dialogPeriod.parentElement.style.display = "none";
  dialogSubmit.textContent = "Save";
  dialogScan.style.display = "none";
  dialog.classList.remove("hidden");
  dialogIssuer.focus();
}

btnAdd.addEventListener("click", () => {
  editId = null;
  dialogTitle.textContent = "Add Account";
  dialogIssuer.value = "";
  dialogLabel.value = "";
  dialogSecret.value = "";
  dialogSecret.placeholder = "Secret key";
  dialogSecret.style.display = "";
  dialogAlgorithm.parentElement.style.display = "";
  dialogDigits.parentElement.style.display = "";
  dialogPeriod.parentElement.style.display = "";
  dialogAlgorithm.value = "SHA1";
  dialogDigits.value = "6";
  dialogPeriod.value = "30";
  dialogSubmit.textContent = "Add";
  dialogScan.style.display = "";
  dialog.classList.remove("hidden");
  dialogIssuer.focus();
});

dialogCancel.addEventListener("click", () => {
  dialog.classList.add("hidden");
});

dialogSubmit.addEventListener("click", async () => {
  const issuer = dialogIssuer.value.trim();
  const label = dialogLabel.value.trim();
  const secret = dialogSecret.value.trim();

  if (editId) {
    // Edit mode — only require issuer + label; secret is optional
    if (!issuer || !label) {
      toast("Issuer and label are required", true);
      return;
    }
    try {
      await invoke("update_account", {
        accountId: editId,
        issuer: issuer || null,
        label: label || null,
        sortOrder: null,
      });
      toast("Account updated");
      editId = null;
      dialog.classList.add("hidden");
      await loadAccounts();
      refreshCodes();
    } catch (e) {
      toast(typeof e === "string" ? e : "Failed to update account", true);
    }
  } else {
    // Add mode — all fields required
    if (!issuer || !label || !secret) {
      toast("All fields required", true);
      return;
    }
    try {
      await invoke("add_account", {
        issuer,
        label,
        secret,
        algorithm: dialogAlgorithm.value,
        digits: parseInt(dialogDigits.value),
        period: parseInt(dialogPeriod.value),
      });
      toast("Account added");
      dialog.classList.add("hidden");
      await loadAccounts();
      refreshCodes();
    } catch (e) {
      toast(typeof e === "string" ? e : "Failed to add account", true);
    }
  }
});

// ── QR Scanner ─────────────────────────────────────────────
dialogScan.addEventListener("click", async () => {
  qrOverlay.classList.remove("hidden");
  try {
    await startCamera(async (uri) => {
      qrOverlay.classList.add("hidden");
      try {
        const account = await invoke("add_account_from_uri", { otpauthUri: uri });
        toast("Account added from QR");
        dialog.classList.add("hidden");
        await loadAccounts();
        refreshCodes();
      } catch (e) {
        toast(typeof e === "string" ? e : "Failed to add from QR", true);
      }
    });
  } catch (e) {
    qrOverlay.classList.add("hidden");
    toast(typeof e === "string" ? e : "Camera access denied", true);
  }
});

qrCancel.addEventListener("click", () => {
  stopCamera();
  qrOverlay.classList.add("hidden");
});

document.addEventListener("paste", async (e) => {
  if (qrOverlay.classList.contains("hidden")) return;
  const items = e.clipboardData?.items;
  if (!items) return;
  for (const item of items) {
    if (item.type.startsWith("image/")) {
      e.preventDefault();
      try {
        const uri = await scanImage(item.getAsFile());
        qrOverlay.classList.add("hidden");
        stopCamera();
        const account = await invoke("add_account_from_uri", { otpauthUri: uri });
        toast("Account added from QR");
        dialog.classList.add("hidden");
        await loadAccounts();
        refreshCodes();
      } catch (err) {
        toast("No QR code found in image", true);
      }
    }
  }
});

// ── Search ─────────────────────────────────────────────────
let searchTimer;
searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadAccounts(searchInput.value.trim()), 200);
});

// ── Theme toggle ───────────────────────────────────────────
function applyTheme(theme) {
  document.body.className = theme === "light" ? "theme-light" : "theme-dark";
  btnTheme.textContent = theme === "light" ? "☀️" : "🌙";
}

function detectSystemTheme() {
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

btnTheme.addEventListener("click", async () => {
  const cfg = await invoke("load_config");
  cfg.theme = cfg.theme === "light" ? "dark" : "light";
  await invoke("save_config", { cfg });
  applyTheme(cfg.theme);
  toast(cfg.theme === "light" ? "Light theme" : "Dark theme");
});

// ── Settings / PIN dialog ──────────────────────────────────
btnSettings.addEventListener("click", async () => {
  try {
    const cfg = await invoke("load_config");
    const hasPin = cfg.password_protected;

    settingsTitle.textContent = "Settings";
    let html = "";

    if (hasPin) {
      html += `
        <div class="settings-section">
          <h3>Change PIN</h3>
          <input type="password" id="pin-old" placeholder="Current PIN" spellcheck="false" autocomplete="off" />
          <input type="password" id="pin-new" placeholder="New PIN" spellcheck="false" autocomplete="off" />
          <input type="password" id="pin-confirm" placeholder="Confirm new PIN" spellcheck="false" autocomplete="off" />
          <div class="settings-error hidden" id="pin-error"></div>
          <button class="settings-btn primary" id="pin-change-btn">Change PIN</button>
        </div>
        <div class="settings-section">
          <h3>Security</h3>
          <button class="settings-btn danger" id="pin-lock-now">Lock Now</button>
        </div>
      `;
    } else {
      html += `
        <div class="settings-section">
          <h3>Set PIN</h3>
          <input type="password" id="pin-new" placeholder="New PIN" spellcheck="false" autocomplete="off" />
          <input type="password" id="pin-confirm" placeholder="Confirm new PIN" spellcheck="false" autocomplete="off" />
          <div class="settings-error hidden" id="pin-error"></div>
          <button class="settings-btn primary" id="pin-set-btn">Set PIN</button>
        </div>
      `;
    }

    html += `
      <div class="settings-section">
        <h3>Backup</h3>
        <p style="font-size:12px;color:var(--btn-color);margin-bottom:4px;">Find <code>.auth</code> file next to the app .exe</p>
        <p style="font-size:11px;color:var(--btn-color);line-height:1.4;">To export: copy the <code>.auth</code> file to a safe location.<br>To import: replace the <code>.auth</code> file and restart.</p>
      </div>
      <div class="settings-section">
        <h3>Auto-Lock</h3>
        <p style="font-size:12px;color:var(--btn-color);margin-bottom:4px;">Lock after ${lockTimeoutMinutes} min of inactivity</p>
      </div>
    `;

    settingsBody.innerHTML = html;
    settingsOverlay.classList.remove("hidden");

    // Pin the event handlers
    const pinError = document.getElementById("pin-error");

    if (hasPin) {
      document.getElementById("pin-change-btn").addEventListener("click", async () => {
        const oldPin = document.getElementById("pin-old").value;
        const newPin = document.getElementById("pin-new").value;
        const confirm = document.getElementById("pin-confirm").value;
        if (!oldPin || !newPin || !confirm) {
          pinError.textContent = "All fields required";
          pinError.classList.remove("hidden");
          return;
        }
        if (newPin !== confirm) {
          pinError.textContent = "New PINs don't match";
          pinError.classList.remove("hidden");
          return;
        }
        try {
          await invoke("change_pin", { oldPin, newPin });
          toast("PIN changed");
          settingsOverlay.classList.add("hidden");
        } catch (e) {
          pinError.textContent = typeof e === "string" ? e : "Failed to change PIN";
          pinError.classList.remove("hidden");
        }
      });

      document.getElementById("pin-lock-now").addEventListener("click", async () => {
        try {
          await invoke("lock");
          locked = true;
          stopCountdown();
          stopAutoLock();
          settingsOverlay.classList.add("hidden");
          showLock();
        } catch (e) {
          toast("Lock failed", true);
        }
      });
    } else {
      document.getElementById("pin-set-btn").addEventListener("click", async () => {
        const newPin = document.getElementById("pin-new").value;
        const confirm = document.getElementById("pin-confirm").value;
        if (!newPin || !confirm) {
          pinError.textContent = "All fields required";
          pinError.classList.remove("hidden");
          return;
        }
        if (newPin !== confirm) {
          pinError.textContent = "PINs don't match";
          pinError.classList.remove("hidden");
          return;
        }
        try {
          await invoke("set_lock", { pin: newPin });
          passwordProtected = true;
          toast("PIN set — app is now protected");
          settingsOverlay.classList.add("hidden");
          startAutoLock();
        } catch (e) {
          pinError.textContent = typeof e === "string" ? e : "Failed to set PIN";
          pinError.classList.remove("hidden");
        }
      });
    }

    // Backup — manual instructions shown in the HTML, no buttons needed
  } catch (e) {
    toast("Failed to load settings", true);
  }
});

settingsCancel.addEventListener("click", () => {
  settingsOverlay.classList.add("hidden");
});

// ── Titlebar buttons ───────────────────────────────────────
btnClose.addEventListener("click", async () => {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  await getCurrentWindow().close();
});

btnMin.addEventListener("click", async () => {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  await getCurrentWindow().minimize();
});

btnPin.addEventListener("click", async () => {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  const cfg = await invoke("load_config");
  cfg.always_on_top = !cfg.always_on_top;
  await invoke("save_config", { cfg });
  await getCurrentWindow().setAlwaysOnTop(cfg.always_on_top);
  btnPin.classList.toggle("active", cfg.always_on_top);
  toast(cfg.always_on_top ? "Always on top" : "Not on top");
});

// ── Window tracking ────────────────────────────────────────
async function trackWindow() {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  const win = getCurrentWindow();

  let resizeTimer;
  await win.onResized(async () => {
    const size = await win.outerSize();
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(async () => {
      const cfg = await invoke("load_config");
      cfg.width = size.width;
      cfg.height = size.height;
      await invoke("save_config", { cfg });
    }, 500);
  });

  let moveTimer;
  await win.onMoved(async () => {
    const pos = await win.outerPosition();
    if (pos.x < 0 || pos.y < 0) return;
    clearTimeout(moveTimer);
    moveTimer = setTimeout(async () => {
      const cfg = await invoke("load_config");
      cfg.left = pos.x;
      cfg.top = pos.y;
      await invoke("save_config", { cfg });
    }, 500);
  });
}

// ── Keyboard shortcuts ─────────────────────────────────────
document.addEventListener("keydown", async (e) => {
  if (e.target.tagName === "INPUT" && e.target.id !== "search") return;
  if (e.target.tagName === "SELECT") return;

  if (e.key === "Escape") {
    dialog.classList.add("hidden");
    qrOverlay.classList.add("hidden");
    settingsOverlay.classList.add("hidden");
    hideContextMenu();
    stopCamera();
    searchInput.blur();
  }
  if (e.ctrlKey && e.key === "n") {
    e.preventDefault();
    if (dialog.classList.contains("hidden")) btnAdd.click();
  } else if (e.ctrlKey && e.key === "f") {
    e.preventDefault();
    searchInput.focus();
    searchInput.select();
  } else if (e.ctrlKey && e.key === "l") {
    e.preventDefault();
    if (!locked) {
      try {
        await invoke("lock");
        locked = true;
        stopCountdown();
        stopAutoLock();
        showLock();
      } catch (_) {}
    }
  }
});

// ── Init ───────────────────────────────────────────────────
(async () => {
  try {
    const name = await invoke("get_app_name");
    titleText.textContent = name;
    document.title = name;

    const cfg = await invoke("load_config");
    btnPin.classList.toggle("active", cfg.always_on_top);
    applyTheme(cfg.theme || detectSystemTheme());
    lockTimeoutMinutes = cfg.lock_timeout_minutes || 5;
    passwordProtected = cfg.password_protected;

    await checkLock();
    if (!locked) {
      await loadAccounts();
      startCountdown();
      startAutoLock();
    }

    window.addEventListener("beforeunload", async () => {
      try {
        const cfg = await invoke("load_config");
        await invoke("save_config", { cfg });
      } catch (_) {}
    });

    await trackWindow();
  } catch (e) {
    console.error("init error:", e);
  }
})();
