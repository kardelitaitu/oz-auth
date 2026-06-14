import { invoke } from "@tauri-apps/api/core";
import QRCode from "qrcode";
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
const lockClose = document.getElementById("lock-close");
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

const settingsOverlay = document.getElementById("settings-overlay");
const settingsTitle = document.getElementById("settings-title");
const settingsBody = document.getElementById("settings-body");
const settingsCloseBtn = document.getElementById("settings-close-btn");
const contextMenu = document.getElementById("context-menu");
const deleteConfirmOverlay = document.getElementById("delete-confirm-overlay");
const deleteConfirmMsg = document.getElementById("delete-confirm-msg");
const deleteConfirmSubmit = document.getElementById("delete-confirm-submit");
const deleteConfirmCancel = document.getElementById("delete-confirm-cancel");
const qrPopup = document.getElementById("qr-popup");
const qrCanvas = document.getElementById("qr-canvas");
const qrTitle = document.getElementById("qr-title");
const qrCloseBtn = document.getElementById("qr-close-btn");
const backupConfirmOverlay = document.getElementById("backup-confirm-overlay");
const backupPinInput = document.getElementById("backup-pin-input");
const backupConfirmSubmit = document.getElementById("backup-confirm-submit");
const backupConfirmCancel = document.getElementById("backup-confirm-cancel");
const backupConfirmError = document.getElementById("backup-confirm-error");

// ── Shared state ───────────────────────────────────────────
const accounts = [];
const secondsRemaining = {};
let lockTimeoutSeconds = 300;
let clipboardClearSeconds = 30;
let passwordProtected = false;
let lockOnFocusLoss = false;
let appName = "oz-auth";
let appVersion = "0.1.0";

// ── Config save queue (prevents race conditions) ──────────
let pendingConfig = null;
let configSaveTimer = null;

function saveConfigBatch() {
  if (!pendingConfig) return;
  if (configSaveTimer) clearTimeout(configSaveTimer);
  configSaveTimer = setTimeout(async () => {
    const cfg = pendingConfig;
    pendingConfig = null;
    try {
      await invoke("save_config", { cfg });
    } catch { /* noop */ }
  }, 300);
}

function updateConfig(mutator) {
  if (!pendingConfig) {
    // Load current config on first mutation
    invoke("load_config").then((cfg) => {
      pendingConfig = cfg;
      mutator(pendingConfig);
      saveConfigBatch();
    }).catch(() => {});
  } else {
    mutator(pendingConfig);
    saveConfigBatch();
  }
}

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
const clipboard = createClipboardManager(toast, clipboardClearSeconds, invoke);

// ── Account operations ─────────────────────────────────────
async function loadAccounts(query = "") {
  if (lock.getLocked()) return;
  try {
    const result = await invoke("list_accounts", { searchQuery: query || null });
    accounts.length = 0;
    accounts.push(...result);
    renderAccounts(accounts, accountList, {
      onCopy: (id) => clipboard.copy(id),
      onContextMenu: showContextMenu,
    });
  } catch (e) {
    console.error("list_accounts error:", e);
  }
}

let pendingDeleteId = null;

async function deleteAccount(id) {
  if (lock.getLocked()) {
    toast("App is locked", true);
    return;
  }
  try {
    await invoke("remove_account", { accountId: id });
    toast("Account deleted");
    hideContextMenu();
    await loadAccounts();
    refreshCodes(invoke, lock.getLocked(), secondsRemaining, () => updateBars(accounts, secondsRemaining), toast);
  } catch {
    toast("Delete failed", true);
  }
}

function confirmDeleteAccount(id) {
  const account = accounts.find((a) => a.id === id);
  if (!account) return;
  pendingDeleteId = id;
  deleteConfirmMsg.textContent = `\u201c${account.issuer} \u2014 ${account.label}\u201d will be permanently removed.`;
  deleteConfirmOverlay.classList.remove("hidden");
  deleteConfirmSubmit.focus();
}

deleteConfirmSubmit.addEventListener("click", async () => {
  deleteConfirmOverlay.classList.add("hidden");
  if (pendingDeleteId) {
    await deleteAccount(pendingDeleteId);
    pendingDeleteId = null;
  }
});

deleteConfirmCancel.addEventListener("click", () => {
  deleteConfirmOverlay.classList.add("hidden");
  pendingDeleteId = null;
});

function reloadAccountsAndCodes() {
  loadAccounts().then(() => {
    refreshCodes(invoke, lock.getLocked(), secondsRemaining, () => updateBars(accounts, secondsRemaining), toast);
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
  btnAdd,
  toast,
  getAccounts: () => accounts,
  isLocked: () => lock.getLocked(),
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

contextMenu.querySelector('[data-action="qr"]').addEventListener("click", async () => {
  if (!contextAccountId) return;
  if (lock.getLocked()) {
    toast("App is locked", true);
    hideContextMenu();
    return;
  }
  const accountId = contextAccountId;
  const account = accounts.find((a) => a.id === accountId);
  hideContextMenu();
  if (!account) return;
  try {
    const uri = await invoke("get_otpauth_uri", { accountId });
    qrTitle.textContent = `${account.issuer} — ${account.label}`;
    // Generate QR code on canvas
    QRCode.toCanvas(qrCanvas, uri, {
      width: 200,
      margin: 1,
      color: { dark: "#1e1e1e", light: "#ffffff" },
    });
    qrPopup.classList.remove("hidden");
    qrCloseBtn.focus();
  } catch (e) {
    toast(typeof e === "string" ? e : "Failed to generate QR code", true);
  }
});

qrCloseBtn.addEventListener("click", () => {
  const ctx = qrCanvas.getContext("2d");
  ctx.clearRect(0, 0, qrCanvas.width, qrCanvas.height);
  qrPopup.classList.add("hidden");
});

contextMenu.querySelector('[data-action="delete"]').addEventListener("click", () => {
  if (contextAccountId) confirmDeleteAccount(contextAccountId);
  hideContextMenu();
});

// ── Drag & drop ────────────────────────────────────────────
async function onReorder(srcId, targetId) {
  if (lock.getLocked()) return;
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
  } catch {
    toast("Reorder failed — reloading", true);
    await loadAccounts();
    refreshCodes(invoke, lock.getLocked(), secondsRemaining, () => updateBars(accounts, secondsRemaining), toast);
    return;
  }

  renderAccounts(accounts, accountList, {
    onCopy: (id) => clipboard.copy(id),
    onContextMenu: showContextMenu,
  });
  refreshCodes(invoke, lock.getLocked(), secondsRemaining, () => updateBars(accounts, secondsRemaining), toast);
}

setupDragDrop(accountList, accountList, onReorder);

// ── Lock manager ───────────────────────────────────────────
const lock = createLockManager({
  invoke,
  lockOverlay,
  lockInput,
  lockSubmit,
  lockError,
  lockClose,
  onClose: async () => {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow().close();
  },
  onUnlock: async () => {
    await loadAccounts();      startCountdown(invoke, () => accounts, lock.getLocked, () => secondsRemaining, updateTrayIcon, toast);
      resetActivity();
    },
    onLockStart: () => {
      stopAutoLock();
      clipboard.clearOnLock();
    },
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
  if (!passwordProtected || !lockTimeoutSeconds || lockTimeoutSeconds <= 0) return;
  autoLockTimer = setInterval(async () => {
    if (lock.getLocked()) return;
    const idle = (Date.now() - lastActivity) / 1000;
    if (idle >= lockTimeoutSeconds) {
      try {
        await invoke("lock");
        lock.setLocked(true);
        stopCountdown();
        lock.show();
      } catch { /* noop */ }
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

// ── Search ─────────────────────────────────────────────────
let searchTimer;
searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadAccounts(searchInput.value.trim()), 200);
});

// ── Theme toggle ───────────────────────────────────────────
function applyTheme(theme) {
  document.body.className = theme === "light" ? "theme-light" : "theme-dark";
  // SVG icon is in the HTML — no need to set textContent
}

function detectSystemTheme() {
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

btnTheme.addEventListener("click", async () => {
  updateConfig((cfg) => {
    cfg.theme = cfg.theme === "light" ? "dark" : "light";
    applyTheme(cfg.theme);
    toast(cfg.theme === "light" ? "Light theme" : "Dark theme");
  });
});

// ── Settings ───────────────────────────────────────────────
btnSettings.addEventListener("click", () => {
  openSettings({
    invoke,
    toast,
    isLocked: () => lock.getLocked(),
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
      } catch {
        toast("Lock failed", true);
      }
    },
    onClipboardClearSecondsChanged: (seconds) => {
      clipboardClearSeconds = seconds;
      clipboard.setClearSeconds(seconds);
    },
    onLockTimeoutChanged: (seconds) => {
      lockTimeoutSeconds = seconds;
      startAutoLock();
    },
    onFocusLossChanged: (enabled) => {
      lockOnFocusLoss = enabled;
    },
    lockTimeoutSeconds,
    clipboardClearSeconds,
    appName,
    appVersion,
    settingsOverlay,
    settingsTitle,
    settingsBody,
    settingsCloseBtn,
    backupConfirmOverlay,
    backupPinInput,
    backupConfirmSubmit,
    backupConfirmCancel,
    backupConfirmError,
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
  const win = getCurrentWindow();
  updateConfig((cfg) => {
    cfg.always_on_top = !cfg.always_on_top;
    win.setAlwaysOnTop(cfg.always_on_top);
    btnPin.classList.toggle("active", cfg.always_on_top);
    toast(cfg.always_on_top ? "Always on top" : "Not on top");
  });
});

// ── Window tracking ────────────────────────────────────────
async function trackWindow() {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  const win = getCurrentWindow();

  let resizeTimer;
  await win.onResized(async () => {
    const size = await win.outerSize();
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      updateConfig((cfg) => {
        cfg.width = size.width;
        cfg.height = size.height;
      });
    }, 500);
  });

  let moveTimer;
  await win.onMoved(async () => {
    const pos = await win.outerPosition();
    if (pos.x < 0 || pos.y < 0) return;
    clearTimeout(moveTimer);
    moveTimer = setTimeout(() => {
      updateConfig((cfg) => {
        cfg.left = pos.x;
        cfg.top = pos.y;
      });
    }, 500);
  });
}

// ── Keyboard shortcuts ─────────────────────────────────────
document.addEventListener("keydown", async (e) => {
  // Close the window if the lock screen is showing
  if (e.key === "Escape" && !lockOverlay.classList.contains("hidden")) {
    lockClose.click();
    return;
  }

  if (e.target.tagName === "INPUT" && e.target.id !== "search") return;
  if (e.target.tagName === "SELECT") return;

  if (e.key === "Escape") {
    dialog.classList.add("hidden");
    settingsOverlay.classList.add("hidden");
    deleteConfirmOverlay.classList.add("hidden");
    qrPopup.classList.add("hidden");
    backupConfirmOverlay.classList.add("hidden");
    pendingDeleteId = null;
    hideContextMenu();
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
      } catch { /* noop */ }
    }
  }
});

// ── Init ───────────────────────────────────────────────────
(async () => {
  try {
    const name = await invoke("get_app_name");
    titleText.textContent = name;
    document.title = name;
    appName = name;

    try {
      appVersion = await invoke("get_app_version");
    } catch {
      appVersion = "0.1.0";
    }

    const cfg = await invoke("load_config");
    btnPin.classList.toggle("active", cfg.always_on_top);
    applyTheme(cfg.theme || detectSystemTheme());
    lockTimeoutSeconds = cfg.lock_timeout_seconds || 300;
    clipboardClearSeconds = cfg.clipboard_clear_seconds || 30;
    clipboard.setClearSeconds(clipboardClearSeconds);
    passwordProtected = cfg.password_protected;
    lockOnFocusLoss = cfg.lock_on_focus_loss ?? false;

    const isLocked = await lock.checkLock();
    if (!isLocked) {
      await loadAccounts();
      startCountdown(invoke, () => accounts, lock.getLocked, () => secondsRemaining, updateTrayIcon, toast);
      startAutoLock();
    }

    window.addEventListener("beforeunload", async () => {
      try {
        if (configSaveTimer) {
          clearTimeout(configSaveTimer);
          configSaveTimer = null;
        }
        if (pendingConfig) {
          await invoke("save_config", { cfg: pendingConfig });
          pendingConfig = null;
        }
      } catch { /* noop */ }
    });

    await trackWindow();

    // Auto-lock on focus loss (if enabled)
    const { getCurrentWindow: getWin } = await import("@tauri-apps/api/window");
    const mainWindow = getWin();
    mainWindow.onFocusChanged(async ({ payload: focused }) => {
      if (!focused && lockOnFocusLoss && passwordProtected && !lock.getLocked()) {
        try {
          await invoke("lock");
          lock.setLocked(true);
          stopCountdown();
          lock.show();
        } catch { /* noop */ }
      }
    });
  } catch (e) {
    console.error("init error:", e);
  }
})();
