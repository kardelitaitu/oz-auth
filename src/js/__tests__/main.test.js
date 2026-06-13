//! Integration tests for the main.js entry point.
//! Uses vi.mock to intercept Tauri invoke calls (mockIPC requires a WebView).
//! main.js has a self-executing async IIFE — we use dynamic import to control timing.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the Tauri core and window APIs before any imports
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    close: vi.fn().mockResolvedValue(),
    minimize: vi.fn().mockResolvedValue(),
    setAlwaysOnTop: vi.fn().mockResolvedValue(),
    onResized: vi.fn(),
    onMoved: vi.fn(),
    onFocusChanged: vi.fn(),
    outerSize: vi.fn().mockResolvedValue({ width: 400, height: 600 }),
    outerPosition: vi.fn().mockResolvedValue({ x: 100, y: 100 }),
  }),
}));

// Import the mocked invoke so we can control it per-test
import { invoke } from "@tauri-apps/api/core";

/** Build the full DOM matching index.html so all getElementById calls in main.js succeed. */
function createFullDom() {
  document.body.innerHTML = `
    <div id="app">
      <div id="titlebar" data-tauri-drag-region>
        <span id="title-text">oz-auth</span>
        <div id="titlebar-buttons">
          <button id="btn-pin" title="Always on top">
            <svg><path d="M15.9894 4.9502..." fill="currentColor"/></svg>
          </button>
          <button id="btn-minimize" title="Minimize">
            <svg><path d="M2 5h6" stroke="currentColor"/></svg>
          </button>
          <button id="btn-close" title="Close">
            <svg><path d="M1 1l8 8M9 1l-8 8" stroke="currentColor"/></svg>
          </button>
        </div>
      </div>
      <div id="toolbar">
        <div class="search-wrapper">
          <svg class="search-icon"><path d="M264,138.586..."/></svg>
          <input type="text" id="search" />
        </div>
        <button id="btn-theme" title="Toggle theme">
          <svg class="theme-icon-sun"><circle cx="10" cy="10" r="4"/></svg>
          <svg class="theme-icon-moon"><path d="M15 10.5..."/></svg>
        </button>
        <button id="btn-add" title="Add Account (Ctrl+N)">
          <svg><path d="M10 3v14M3 10h14"/></svg>
        </button>
        <button id="btn-settings" title="Settings">
          <svg><path d="M478.409,116.617..."/></svg>
        </button>
      </div>
      <div id="account-list"></div>
      <div id="lock-overlay" class="hidden">
        <button id="lock-close" title="Close"><svg><path d="M2 2l12 12M14 2l-12 12"/></svg></button>
        <div id="lock-card">
          <h2 id="lock-title">oz-auth is locked</h2>
          <input type="password" id="lock-input" />
          <button id="lock-submit">Unlock</button>
          <div id="lock-error" class="hidden">Wrong PIN. Try again.</div>
        </div>
      </div>
      <div id="account-dialog" class="hidden">
        <div id="dialog-card">
          <h2 id="dialog-title">Add Account</h2>
          <input type="text" id="dialog-issuer" />
          <input type="text" id="dialog-label" />
          <input type="text" id="dialog-secret" />
          <div class="dialog-row"><label>Algorithm</label><select id="dialog-algorithm"><option value="SHA1">SHA1</option><option value="SHA256">SHA256</option><option value="SHA512">SHA512</option></select></div>
          <div class="dialog-row"><label>Digits</label><select id="dialog-digits"><option value="6">6</option><option value="8">8</option></select></div>
          <div class="dialog-row"><label>Period</label><select id="dialog-period"><option value="30">30s</option><option value="60">60s</option></select></div>
          <div class="dialog-actions">
            <button id="dialog-cancel">Cancel</button>
            <button id="dialog-submit">Add</button>
          </div>
        </div>
      </div>
      <div id="settings-overlay" class="hidden">
        <div id="settings-card">
          <div class="settings-header">
            <h2 id="settings-title">Settings</h2>
            <button id="settings-close-btn"><svg><path d="M2 2l12 12M14 2l-12 12"/></svg></button>
          </div>
          <div id="settings-body"></div>
        </div>
      </div>
      <div id="context-menu" class="hidden">
        <div class="ctx-item" data-action="edit">Edit</div>
        <div class="ctx-item" data-action="qr">QR Code</div>
        <div class="ctx-item ctx-delete" data-action="delete">Delete</div>
      </div>
      <div id="delete-confirm-overlay" class="hidden">
        <div id="delete-confirm-card">
          <h2 id="delete-confirm-title">Delete account?</h2>
          <p id="delete-confirm-msg"></p>
          <button id="delete-confirm-submit">Delete</button>
          <button id="delete-confirm-cancel">Cancel</button>
        </div>
      </div>
      <div id="qr-popup" class="hidden">
        <div id="qr-card">
          <h2 id="qr-title">QR Code</h2>
          <canvas id="qr-canvas"></canvas>
          <button id="qr-close-btn">Close</button>
        </div>
      </div>
      <div id="backup-confirm-overlay" class="hidden">
        <div id="backup-confirm-card">
          <h2 id="backup-confirm-title">Export all keys?</h2>
          <p id="backup-confirm-msg"></p>
          <input type="password" id="backup-pin-input" />
          <div id="backup-confirm-error" class="hidden"></div>
          <button id="backup-confirm-submit">Confirm</button>
          <button id="backup-confirm-cancel">Cancel</button>
        </div>
      </div>
      <div id="toast-bar" class="hidden"></div>
    </div>
  `;
}

/** Track invoke calls for assertions. */
let callLog = {};

function defaultInvokeMock(cmd, args) {
  switch (cmd) {
    case "get_app_name":
      return "TestApp";
    case "get_app_version":
      return "9.9.9";
    case "load_config":
      return {
        theme: "dark",
        always_on_top: false,
        lock_timeout_seconds: 300,
        clipboard_clear_seconds: 30,
        password_protected: false,
        lock_on_focus_loss: false,
        width: 400,
        height: 600,
      };
    case "list_accounts":
      return [];
    case "generate_all_codes":
      return [];
    case "is_locked":
      return false;
    case "save_config":
      return null;
    case "unlock":
      return true;
    case "remove_account":
      return null;
    case "update_tray_icon":
      return null;
    case "lock":
      return null;
    default:
      return null;
  }
}

/** Set up invoke mock with optional overrides. Record all calls in callLog. */
function setupInvoke(overrides = {}) {
  callLog = {};
  invoke.mockImplementation((cmd, args) => {
    if (!callLog[cmd]) callLog[cmd] = { count: 0, args: [] };
    callLog[cmd].count++;
    callLog[cmd].args.push(args || {});

    // Check for a per-command override — wrap in Promise.resolve
    if (overrides[cmd] !== undefined) {
      const val = overrides[cmd];
      return Promise.resolve(typeof val === "function" ? val(args) : val);
    }

    // Fall through to default — wrap in Promise.resolve for real invoke behavior
    return Promise.resolve(defaultInvokeMock(cmd, args));
  });
}

describe("main.js integration", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    createFullDom();
    setupInvoke();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  async function loadMain() {
    // Clear module cache so the IIFE re-executes with the current mock setup
    vi.resetModules();
    await import("../../main.js");
    // Flush microtasks from the async IIFE
    await new Promise(process.nextTick);
    await new Promise(process.nextTick);
  }

  // ── Init flow ────────────────────────────────────────

  it("sets title text from get_app_name", async () => {
    await loadMain();
    expect(document.getElementById("title-text").textContent).toBe("TestApp");
    expect(document.title).toBe("TestApp");
  });

  it("applies theme from config on init", async () => {
    setupInvoke({
      load_config: {
        theme: "light",
        always_on_top: false,
        lock_timeout_seconds: 300,
        clipboard_clear_seconds: 30,
        password_protected: false,
        lock_on_focus_loss: false,
        width: 400,
        height: 600,
      },
    });
    await loadMain();
    expect(document.body.className).toBe("theme-light");
    expect(callLog.load_config.count).toBeGreaterThanOrEqual(1);
  });

  it("calls list_accounts and generate_all_codes on init when unlocked", async () => {
    await loadMain();
    expect(callLog.list_accounts.count).toBeGreaterThanOrEqual(1);
    expect(callLog.generate_all_codes.count).toBeGreaterThanOrEqual(1);
  });

  it("does not load accounts when locked on init", async () => {
    setupInvoke({ is_locked: true });
    await loadMain();
    expect(callLog.list_accounts).toBeUndefined();
  });

  it("pin button reflects config.always_on_top", async () => {
    setupInvoke({
      load_config: {
        theme: "dark",
        always_on_top: true,
        lock_timeout_seconds: 300,
        clipboard_clear_seconds: 30,
        password_protected: false,
        lock_on_focus_loss: false,
        width: 400,
        height: 600,
      },
    });
    await loadMain();
    const btnPin = document.getElementById("btn-pin");
    expect(btnPin.classList.contains("active")).toBe(true);
  });

  // ── Theme toggle ────────────────────────────────────

  it("theme button toggles theme and saves config", async () => {
    await loadMain();
    const btnTheme = document.getElementById("btn-theme");
    expect(document.body.className).toBe("theme-dark");

    btnTheme.click();
    await new Promise(process.nextTick);

    const saveCall = (callLog.save_config?.args || []).find(
      (a) => a.cfg && a.cfg.theme === "light"
    );
    expect(saveCall).toBeDefined();
    expect(document.body.className).toBe("theme-light");
  });

  // ── Pin button (always on top) ───────────────────────

  it("pin button toggles always_on_top", async () => {
    await loadMain();
    const btnPin = document.getElementById("btn-pin");

    btnPin.click();
    await new Promise(process.nextTick);

    const saveCall = (callLog.save_config?.args || []).find(
      (a) => a.cfg && a.cfg.always_on_top === true
    );
    expect(saveCall).toBeDefined();
    expect(btnPin.classList.contains("active")).toBe(true);
  });

  // ── Keyboard shortcuts ──────────────────────────────

  it("Ctrl+N opens account dialog", async () => {
    await loadMain();
    const dialog = document.getElementById("account-dialog");
    dialog.classList.add("hidden");

    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "n", ctrlKey: true, bubbles: true })
    );

    expect(dialog.classList.contains("hidden")).toBe(false);
    expect(document.getElementById("dialog-title").textContent).toBe("Add Account");
  });

  it("Ctrl+F focuses search input", async () => {
    await loadMain();
    const search = document.getElementById("search");
    const focusSpy = vi.spyOn(search, "focus");
    const selectSpy = vi.spyOn(search, "select");

    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "f", ctrlKey: true, bubbles: true })
    );

    expect(focusSpy).toHaveBeenCalled();
    expect(selectSpy).toHaveBeenCalled();
  });

  it("Ctrl+L locks the app", async () => {
    await loadMain();

    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "l", ctrlKey: true, bubbles: true })
    );
    await new Promise(process.nextTick);

    expect(callLog.lock.count).toBeGreaterThanOrEqual(1);
    const lockOverlay = document.getElementById("lock-overlay");
    expect(lockOverlay.classList.contains("hidden")).toBe(false);
  });

  it("Escape triggers lock close when locked", async () => {
    await loadMain();
    const lockOverlay = document.getElementById("lock-overlay");
    lockOverlay.classList.remove("hidden");

    const lockClose = document.getElementById("lock-close");
    const clickSpy = vi.spyOn(lockClose, "click");

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

    expect(clickSpy).toHaveBeenCalled();
  });

  it("Escape closes open overlays", async () => {
    await loadMain();
    const dialog = document.getElementById("account-dialog");
    const settings = document.getElementById("settings-overlay");
    const delConfirm = document.getElementById("delete-confirm-overlay");

    dialog.classList.remove("hidden");
    settings.classList.remove("hidden");
    delConfirm.classList.remove("hidden");

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

    expect(dialog.classList.contains("hidden")).toBe(true);
    expect(settings.classList.contains("hidden")).toBe(true);
    expect(delConfirm.classList.contains("hidden")).toBe(true);
  });

  // ── Search ──────────────────────────────────────────

  it("search input debounces loadAccounts call", async () => {
    await loadMain();
    const search = document.getElementById("search");
    search.value = "test";

    search.dispatchEvent(new Event("input", { bubbles: true }));
    expect(callLog.list_accounts.count).toBe(1);

    vi.advanceTimersByTime(250);
    await new Promise(process.nextTick);

    expect(callLog.list_accounts.count).toBe(2);
    const lastArgs = callLog.list_accounts.args[callLog.list_accounts.args.length - 1];
    expect(lastArgs.searchQuery).toBe("test");
  });

  // ── Delete flow ─────────────────────────────────────

  it("delete confirm flow: submit deletes account and reloads", async () => {
    setupInvoke({
      list_accounts: [{ id: "del1", issuer: "DeleteCo", label: "del@co.com" }],
    });
    await loadMain();

    const card = document.querySelector(".account-card");
    expect(card).not.toBeNull();
    card.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 10, clientY: 10 }));

    document.querySelector('[data-action="delete"]').click();

    const delConfirm = document.getElementById("delete-confirm-overlay");
    expect(delConfirm.classList.contains("hidden")).toBe(false);
    expect(document.getElementById("delete-confirm-msg").textContent).toContain("DeleteCo");

    document.getElementById("delete-confirm-submit").click();
    await new Promise(process.nextTick);

    expect(callLog.remove_account.count).toBeGreaterThanOrEqual(1);
    expect(delConfirm.classList.contains("hidden")).toBe(true);
  });

  it("delete confirm cancel hides overlay", async () => {
    setupInvoke({
      list_accounts: [{ id: "c1", issuer: "Co", label: "co@co.com" }],
    });
    await loadMain();

    const card = document.querySelector(".account-card");
    card.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 10, clientY: 10 }));

    document.querySelector('[data-action="delete"]').click();

    const delConfirm = document.getElementById("delete-confirm-overlay");
    expect(delConfirm.classList.contains("hidden")).toBe(false);

    document.getElementById("delete-confirm-cancel").click();
    expect(delConfirm.classList.contains("hidden")).toBe(true);
  });

  // ── Settings button ────────────────────────────────

  it("settings button opens settings overlay", async () => {
    await loadMain();

    document.getElementById("btn-settings").click();
    await new Promise(process.nextTick);

    const overlay = document.getElementById("settings-overlay");
    expect(overlay.classList.contains("hidden")).toBe(false);
    expect(document.getElementById("settings-body").innerHTML.length).toBeGreaterThan(0);
  });

  // ── Toast ───────────────────────────────────────────

  it("toast bar shows and hides messages", async () => {
    await loadMain();
    const toastBar = document.getElementById("toast-bar");
    expect(toastBar.classList.contains("hidden")).toBe(true);

    document.getElementById("btn-theme").click();
    await new Promise(process.nextTick);

    expect(toastBar.classList.contains("hidden")).toBe(false);
    expect(toastBar.textContent).toBe("Light theme");

    vi.advanceTimersByTime(3000);
    expect(toastBar.classList.contains("hidden")).toBe(true);
  });
});
