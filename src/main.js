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

// ── State ──────────────────────────────────────────────────
let accounts = [];
let locked = false;
let countdownInterval = null;

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
  setTimeout(() => lockInput.focus(), 100);
}

function hideLock() {
  lockOverlay.classList.add("hidden");
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
        <button class="card-delete" title="Delete">×</button>
      </div>
      <div class="card-label">${escapeHtml(a.label)}</div>
      <div class="card-code" data-id="${a.id}">------</div>
      <div class="card-bar"><div class="card-bar-fill" data-id="${a.id}"></div></div>
      <div class="card-timer" data-id="${a.id}">--s</div>
    `;
    card.querySelector(".card-code").addEventListener("click", () => copyCode(a.id));
    card.querySelector(".card-delete").addEventListener("click", (e) => {
      e.stopPropagation();
      deleteAccount(a.id);
    });
    accountList.appendChild(card);
  });
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

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
    // Update tray icon with average countdown progress
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
    toast("Code copied");
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
    await loadAccounts();
    refreshCodes();
  } catch (e) {
    toast("Delete failed", true);
  }
}

// ── Add Account dialog ─────────────────────────────────────
let editId = null;

btnAdd.addEventListener("click", () => {
  editId = null;
  dialogTitle.textContent = "Add Account";
  dialogIssuer.value = "";
  dialogLabel.value = "";
  dialogSecret.value = "";
  dialogAlgorithm.value = "SHA1";
  dialogDigits.value = "6";
  dialogPeriod.value = "30";
  dialogSubmit.textContent = "Add";
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

// Paste QR image handler
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

// ── Init ───────────────────────────────────────────────────
(async () => {
  try {
    const name = await invoke("get_app_name");
    titleText.textContent = name;
    document.title = name;

    const cfg = await invoke("load_config");
    btnPin.classList.toggle("active", cfg.always_on_top);

    await checkLock();
    if (!locked) {
      await loadAccounts();
      startCountdown();
    }
    // Save config on close
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
