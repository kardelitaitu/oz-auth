import { invoke } from "@tauri-apps/api/core";
import { startCamera, stopCamera, scanImage } from "./js/qr-scanner.js";
import { refreshCodes, updateBars, startCountdown, stopCountdown } from "./js/totp.js";
import { renderAccounts, setupAccountDialog } from "./js/accounts.js";
import { createClipboardManager } from "./js/clipboard.js";
import { createLockManager } from "./js/lock.js";
import { openSettings } from "./js/settings.js";
import { setupDragDrop } from "./js/dragdrop.js";

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

// ── Shared state ───────────────────────────────────────────
const accounts = [];
const secondsRemaining = {};
let lockTimeoutMinutes = 5;
let passwordProtected = false;

// ── Tray icon update helper ────────────────────────────────
function updateTrayIcon(pct) {
  invoke("update_tray_icon", { pct }).catch(() => {});
}

// ── Toast ──────────────────────────────────────────────────
function toast(msg, isError = false) {
  toastBar.textContent = msg;
  toastBar.className = isError ? "error" : "";
  toastBar.classList.remove("hidden");
  setTimeout(() => toastBar.classList.add("hidden"), 3000);
}

// ── Clipboard ──────────────────────────────────────────────
const clipboard = createClipboardManager(toast);

// ── Account operations ─────────────────────────────────────
async function loadAccounts(query = "") {
  if (lock.getLocked()) return;
  try {
    const result = await invoke("list_accounts", { searchQuery: query || null });
    accounts.length = 0;
    accounts.push(...result);
    renderAccounts(accounts, accountList, {
      onCopy: (id) => clipboard.copy(id),
      onEdit: (id) => accountDialog.openEdit(id),
      onDelete: (id) => deleteAccount(id),
      onContextMenu: showContextMenu,
    });
  } catch (e) {
    console.error("list_accounts error:", e);
  }
}

async function deleteAccount(id) {
  if (lock.getLocked()) return;
  try {
    await invoke("remove_account", { accountId: id });
    toast("Account deleted");
    hideContextMenu();
    await loadAccounts();
    refreshCodes(invoke, lock.getLocked(), secondsRemaining, () => updateBars(accounts, secondsRemaining));
  } catch (e) {
    toast("Delete failed", true);
  }
}

function reloadAccountsAndCodes() {
  loadAccounts().then(() => {
    refreshCodes(invoke, lock.getLocked(), secondsRemaining, () => updateBars(accounts, secondsRemaining));
  });
}

// ── Account dialog ─────────────────────────────────────────
const accountDialog = setupAccountDialog({
  invoke,
  dialog,
  dialogTitle,
  dialogIssuer,
  dialogLabel,
  dialogSecret,
  dialogAlgorithm,
  dialogDigits,
  dialogPeriod,
  dialogSubmit,
  dialogCancel,
  dialogScan,
  btnAdd,
  toast,
  getAccounts: () => accounts,
  onAccountsChanged: reloadAccountsAndCodes,
});

// ── Context menu ───────────────────────────────────────────
let contextAccountId = null;

function showContextMenu(x, y, accountId) {
  contextAccountId = accountId;
  contextMenu.classList.remove("hidden");
  const rect = contextMenu.getBoundingClientRect();
  contextMenu.style.left = `${Math.max(4, Math.min(x, window.innerWidth - rect.width - 4))}px`;
  contextMenu.style.top = `${Math.max(4, Math.min(y, window.innerHeight - rect.height - 4))}px`;
}

function hideContextMenu() {
  contextMenu.classList.add("hidden");
  contextAccountId = null;
}

document.addEventListener("click", (e) => {
  if (!contextMenu.contains(e.target)) hideContextMenu();
});

contextMenu.querySelector('[data-action="edit"]').addEventListener("click", () => {
  if (contextAccountId) accountDialog.openEdit(contextAccountId);
  hideContextMenu();
});

contextMenu.querySelector('[data-action="delete"]').addEventListener("click", () => {
  if (contextAccountId) deleteAccount(contextAccountId);
  hideContextMenu();
});

// ── Drag & drop ────────────────────────────────────────────
async function onReorder(srcId, targetId) {
  const srcIdx = accounts.findIndex((a) => a.id === srcId);
  const tgtIdx = accounts.findIndex((a) => a.id === targetId);
  if (srcIdx === -1 || tgtIdx === -1 || srcIdx === tgtIdx) return;

  const [moved] = accounts.splice(srcIdx, 1);
  accounts.splice(tgtIdx, 0, moved);

  const updates = accounts.map((a, i) =>
    invoke("update_account", { accountId: a.id, sortOrder: i, issuer: null, label: null })
  );
  try {
    await Promise.all(updates);
    toast("Reordered");
  } catch (e) {
    toast("Reorder failed — reloading", true);
    await loadAccounts();
    return;
  }

  renderAccounts(accounts, accountList, {
    onCopy: (id) => clipboard.copy(id),
    onEdit: (id) => accountDialog.openEdit(id),
    onDelete: (id) => deleteAccount(id),
    onContextMenu: showContextMenu,
  });
  refreshCodes(invoke, lock.getLocked(), secondsRemaining, () => updateBars(accounts, secondsRemaining));
}

setupDragDrop(accountList, accountList, onReorder);

// ── Lock manager ───────────────────────────────────────────
const lock = createLockManager({
  invoke,
  lockOverlay,
  lockInput,
  lockSubmit,
  lockError,
  onUnlock: async () => {
    await loadAccounts();
    startCountdown(invoke, () => accounts, lock.getLocked, () => secondsRemaining, updateTrayIcon);
    resetActivity();
  },
  onLockStart: () => stopAutoLock(),
  onLockEnd: () => startAutoLock(),
});

// ── Auto-lock on inactivity ────────────────────────────────
let autoLockTimer = null;
let lastActivity = Date.now();

function resetActivity() {
  lastActivity = Date.now();
}

function startAutoLock() {
  stopAutoLock();
  if (!passwordProtected || !lockTimeoutMinutes || lockTimeoutMinutes <= 0) return;
  autoLockTimer = setInterval(async () => {
    if (lock.getLocked()) return;
    const idle = (Date.now() - lastActivity) / 1000 / 60;
    if (idle >= lockTimeoutMinutes) {
      try {
        await invoke("lock");
        lock.setLocked(true);
        stopCountdown();
        lock.show();
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

["mousemove", "keydown", "mousedown", "wheel", "touchstart", "contextmenu"].forEach((evt) => {
  document.addEventListener(evt, resetActivity, { passive: true });
});

// ── QR Scanner ─────────────────────────────────────────────
dialogScan.addEventListener("click", async () => {
  qrOverlay.classList.remove("hidden");
  try {
    await startCamera(async (uri) => {
      qrOverlay.classList.add("hidden");
      try {
        await invoke("add_account_from_uri", { otpauthUri: uri });
        toast("Account added from QR");
        dialog.classList.add("hidden");
        reloadAccountsAndCodes();
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
        await invoke("add_account_from_uri", { otpauthUri: uri });
        toast("Account added from QR");
        dialog.classList.add("hidden");
        reloadAccountsAndCodes();
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

// ── Settings ───────────────────────────────────────────────
btnSettings.addEventListener("click", () => {
  openSettings({
    invoke,
    toast,
    onPinSet: () => {
      passwordProtected = true;
      startAutoLock();
    },
    onLockNow: async () => {
      try {
        await invoke("lock");
        lock.setLocked(true);
        stopCountdown();
        lock.show();
      } catch (e) {
        toast("Lock failed", true);
      }
    },
    lockTimeoutMinutes,
    settingsOverlay,
    settingsTitle,
    settingsBody,
    settingsCancel,
  });
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
    if (!lock.getLocked()) {
      try {
        await invoke("lock");
        lock.setLocked(true);
        stopCountdown();
        lock.show();
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

    const isLocked = await lock.checkLock();
    if (!isLocked) {
      await loadAccounts();
      startCountdown(invoke, () => accounts, lock.getLocked, () => secondsRemaining, updateTrayIcon);
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
