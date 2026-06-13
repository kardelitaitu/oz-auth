//! Integration tests for the settings module using Tauri mock IPC.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { openSettings } from "../settings.js";
import { defaultMockHandler, ensureSettingsDom } from "./setup.js";

beforeEach(() => {
  document.body.innerHTML = "";
  ensureSettingsDom();
});

// ── openSettings ─────────────────────────────────────────

describe("openSettings", () => {
  function createSettingsConfig(overrides = {}) {
    return {
      invoke: vi.fn().mockImplementation((cmd) => {
        return Promise.resolve(defaultMockHandler(cmd));
      }),
      toast: vi.fn(),
      isLocked: () => false,
      onPinSet: vi.fn(),
      onLockNow: vi.fn(),
      onClipboardClearSecondsChanged: vi.fn(),
      onLockTimeoutChanged: vi.fn(),
      onFocusLossChanged: vi.fn(),
      lockTimeoutSeconds: 300,
      clipboardClearSeconds: 30,
      appName: "oz-auth",
      appVersion: "0.1.4",
      settingsOverlay: document.getElementById("settings-overlay"),
      settingsTitle: document.getElementById("settings-title"),
      settingsBody: document.getElementById("settings-body"),
      settingsCloseBtn: document.getElementById("settings-close-btn"),
      backupConfirmOverlay: document.getElementById("backup-confirm-overlay"),
      backupPinInput: document.getElementById("backup-pin-input"),
      backupConfirmSubmit: document.getElementById("backup-confirm-submit"),
      backupConfirmCancel: document.getElementById("backup-confirm-cancel"),
      backupConfirmError: document.getElementById("backup-confirm-error"),
      ...overrides,
    };
  }

  it("shows settings overlay and populates body", async () => {
    const cfg = createSettingsConfig();
    openSettings(cfg);

    // Allow the async load_config to resolve
    await new Promise(process.nextTick);

    expect(cfg.settingsOverlay.classList.contains("hidden")).toBe(false);
    expect(cfg.settingsTitle.textContent).toBe("Settings");
    expect(cfg.settingsBody.innerHTML.length).toBeGreaterThan(0);
  });

  it("shows 'Set PIN' section when no password configured", async () => {
    const invoke = vi.fn().mockResolvedValue({
      theme: "dark", password_protected: false,
    });
    const cfg = createSettingsConfig({ invoke });
    openSettings(cfg);

    await new Promise(process.nextTick);

    expect(cfg.settingsBody.innerHTML).toContain("Set PIN");
    expect(cfg.settingsBody.innerHTML).not.toContain("Change PIN");
  });

  it("shows 'Change PIN' section when password is set", async () => {
    const invoke = vi.fn().mockResolvedValue({
      theme: "dark", password_protected: true,
    });
    const cfg = createSettingsConfig({ invoke });
    openSettings(cfg);

    await new Promise(process.nextTick);

    expect(cfg.settingsBody.innerHTML).toContain("Change PIN");
    expect(cfg.settingsBody.innerHTML).toContain("Lock Now");
  });

  it("shows backup section, audit log section, and about area", async () => {
    const cfg = createSettingsConfig();
    openSettings(cfg);

    await new Promise(process.nextTick);

    expect(cfg.settingsBody.innerHTML).toContain("Backup");
    expect(cfg.settingsBody.innerHTML).toContain("Audit Log");
    // The about section has the app name (no literal "About" text label)
    expect(cfg.settingsBody.innerHTML).toContain("oz-auth");
    expect(cfg.settingsBody.innerHTML).toContain("0.1.4");
  });

  it("displays app name and version", async () => {
    const cfg = createSettingsConfig();
    openSettings(cfg);

    await new Promise(process.nextTick);

    expect(cfg.settingsBody.innerHTML).toContain("oz-auth");
    expect(cfg.settingsBody.innerHTML).toContain("0.1.4");
  });

  it("close button hides overlay", async () => {
    const cfg = createSettingsConfig();
    openSettings(cfg);

    await new Promise(process.nextTick);
    cfg.settingsCloseBtn.click();
    expect(cfg.settingsOverlay.classList.contains("hidden")).toBe(true);
  });

  it("backup confirm opens and PIN input hidden when no PIN set", async () => {
    const invoke = vi.fn().mockResolvedValue({
      theme: "dark", password_protected: false,
    });
    const cfg = createSettingsConfig({ invoke });
    openSettings(cfg);

    await new Promise(process.nextTick);

    // Click backup button
    const backupBtn = document.getElementById("backup-keys-btn");
    backupBtn.click();

    expect(cfg.backupConfirmOverlay.classList.contains("hidden")).toBe(false);
    expect(cfg.backupPinInput.style.display).toBe("none");
  });

  it("backup confirm shows PIN input when PIN is set", async () => {
    const invoke = vi.fn().mockResolvedValue({
      theme: "dark", password_protected: true,
    });
    const cfg = createSettingsConfig({ invoke });
    openSettings(cfg);

    await new Promise(process.nextTick);

    const backupBtn = document.getElementById("backup-keys-btn");
    backupBtn.click();

    expect(cfg.backupPinInput.style.display).not.toBe("none");
  });

  it("backup confirm cancel hides the overlay", async () => {
    const cfg = createSettingsConfig();
    openSettings(cfg);

    await new Promise(process.nextTick);

    const backupBtn = document.getElementById("backup-keys-btn");
    backupBtn.click();
    cfg.backupConfirmCancel.click();

    expect(cfg.backupConfirmOverlay.classList.contains("hidden")).toBe(true);
  });

  it("backup confirm submit calls invoke('save_backup_file')", async () => {
    const invoke = vi.fn().mockImplementation((cmd) => {
      if (cmd === "load_config") return Promise.resolve({ theme: "dark", password_protected: false });
      if (cmd === "save_backup_file") return Promise.resolve("/tmp/backup.auth");
      return defaultMockHandler(cmd);
    });
    const toast = vi.fn();
    const cfg = createSettingsConfig({ invoke, toast });
    openSettings(cfg);

    await new Promise(process.nextTick);

    const backupBtn = document.getElementById("backup-keys-btn");
    backupBtn.click();
    cfg.backupConfirmSubmit.click();

    await new Promise(process.nextTick);

    expect(invoke).toHaveBeenCalledWith("save_backup_file");
    expect(toast).toHaveBeenCalledWith("Backup saved — /tmp/backup.auth");
  });

  it("PIN set flow: sets PIN via invoke('set_lock')", async () => {
    const invoke = vi.fn().mockImplementation((cmd) => {
      if (cmd === "load_config") return Promise.resolve({ theme: "dark", password_protected: false });
      if (cmd === "set_lock") return Promise.resolve(true);
      return defaultMockHandler(cmd);
    });
    const onPinSet = vi.fn();
    const cfg = createSettingsConfig({ invoke, onPinSet });
    openSettings(cfg);

    await new Promise(process.nextTick);

    // Fill in PIN fields
    const pinNew = document.getElementById("pin-new");
    const pinConfirm = document.getElementById("pin-confirm");
    const pinSetBtn = document.getElementById("pin-set-btn");
    pinNew.value = "1234";
    pinConfirm.value = "1234";
    pinSetBtn.click();

    await new Promise(process.nextTick);

    expect(invoke).toHaveBeenCalledWith("set_lock", { pin: "1234" });
    expect(onPinSet).toHaveBeenCalled();
  });

  it("PIN set validates matching fields", async () => {
    const toast = vi.fn();
    const cfg = createSettingsConfig({ toast });
    openSettings(cfg);

    await new Promise(process.nextTick);

    const pinNew = document.getElementById("pin-new");
    const pinConfirm = document.getElementById("pin-confirm");
    const pinSetBtn = document.getElementById("pin-set-btn");
    pinNew.value = "1234";
    pinConfirm.value = "5678";
    pinSetBtn.click();

    // Source code shows error in pinError element, not via toast
    const pinError = document.getElementById("pin-error");
    expect(pinError.textContent).toBe("PINs don't match");
    expect(pinError.classList.contains("hidden")).toBe(false);
    // set_lock should not have been called
    expect(cfg.invoke).not.toHaveBeenCalledWith("set_lock", expect.anything());
  });

  it("Lock Now button calls onLockNow and closes settings", async () => {
    const invoke = vi.fn().mockResolvedValue({ theme: "dark", password_protected: true });
    const onLockNow = vi.fn();
    const cfg = createSettingsConfig({ invoke, onLockNow });
    openSettings(cfg);

    await new Promise(process.nextTick);

    const lockNowBtn = document.getElementById("pin-lock-now");
    lockNowBtn.click();

    expect(onLockNow).toHaveBeenCalled();
    expect(cfg.settingsOverlay.classList.contains("hidden")).toBe(true);
  });

  it("auto-saves lock_timeout on input change", async () => {
    vi.useFakeTimers();
    try {
      let config = { theme: "dark", lock_timeout_seconds: 300 };
      const invoke = vi.fn().mockImplementation((cmd, args) => {
        if (cmd === "load_config") return Promise.resolve(config);
        if (cmd === "save_config") {
          config = args.cfg;
          return Promise.resolve();
        }
        return defaultMockHandler(cmd);
      });
      const onLockTimeoutChanged = vi.fn();
      const cfg = createSettingsConfig({ invoke, onLockTimeoutChanged });
      openSettings(cfg);

      await new Promise(process.nextTick);

      const timeoutInput = document.getElementById("lock-timeout");
      timeoutInput.value = "120";
      timeoutInput.dispatchEvent(new Event("input", { bubbles: true }));

      // Advance past the 400ms debounce
      vi.advanceTimersByTime(450);
      await new Promise(process.nextTick);

      expect(invoke).toHaveBeenCalledWith("save_config", { cfg: expect.objectContaining({ lock_timeout_seconds: 120 }) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows audit log entries when toggle is expanded", async () => {
    const invoke = vi.fn().mockImplementation((cmd) => {
      if (cmd === "load_config") return Promise.resolve({ theme: "dark", password_protected: false });
      if (cmd === "get_audit_log") return Promise.resolve([
        { seq: 1, ts: 1700000000, cat: "startup", msg: "App started" },
        { seq: 2, ts: 1700000100, cat: "account", msg: "Account added" },
      ]);
      return defaultMockHandler(cmd);
    });
    const cfg = createSettingsConfig({ invoke });
    openSettings(cfg);

    await new Promise(process.nextTick);

    const toggleBtn = document.getElementById("audit-log-toggle");
    expect(toggleBtn).not.toBeNull();
    expect(toggleBtn.textContent).toBe("Show");
    toggleBtn.click();

    // Allow the async get_audit_log call to complete
    await new Promise(process.nextTick);

    const auditBody = document.getElementById("audit-log-body");
    expect(auditBody.innerHTML).toContain("App started");
    expect(auditBody.innerHTML).toContain("Account added");
    expect(auditBody.innerHTML).toContain("startup");
    expect(auditBody.innerHTML).toContain("account");
    expect(toggleBtn.textContent).toBe("Hide");
  });

  it("audit log hide/show toggle does not re-fetch entries", async () => {
    let fetchCount = 0;
    const invoke = vi.fn().mockImplementation((cmd) => {
      if (cmd === "load_config") return Promise.resolve({ theme: "dark", password_protected: false });
      if (cmd === "get_audit_log") {
        fetchCount++;
        return Promise.resolve([{ seq: 1, ts: 1700000000, cat: "startup", msg: "App started" }]);
      }
      return defaultMockHandler(cmd);
    });
    const cfg = createSettingsConfig({ invoke });
    openSettings(cfg);

    await new Promise(process.nextTick);

    const toggleBtn = document.getElementById("audit-log-toggle");
    const auditContainer = document.getElementById("audit-log-container");

    // Show
    toggleBtn.click();
    await new Promise(process.nextTick);
    expect(fetchCount).toBe(1);

    // Hide
    toggleBtn.click();
    expect(auditContainer.classList.contains("hidden")).toBe(true);
    expect(toggleBtn.textContent).toBe("Show");

    // Show again — should NOT re-fetch
    toggleBtn.click();
    await new Promise(process.nextTick);
    expect(fetchCount).toBe(1);
    expect(auditContainer.classList.contains("hidden")).toBe(false);
    expect(toggleBtn.textContent).toBe("Hide");
  });

  it("shows toast on load_config failure", async () => {
    const invoke = vi.fn().mockRejectedValue(new Error("config error"));
    const toast = vi.fn();
    const cfg = createSettingsConfig({ invoke, toast });
    openSettings(cfg);

    await new Promise(process.nextTick);

    expect(toast).toHaveBeenCalledWith("Failed to load settings", true);
  });
});
