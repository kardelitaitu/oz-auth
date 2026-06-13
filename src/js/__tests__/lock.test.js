//! Integration tests for the lock module using Tauri mock IPC.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createLockManager } from "../lock.js";
beforeEach(() => {
  document.body.innerHTML = `
    <div id="lock-overlay" class="hidden">
      <div id="lock-card">
        <h2 id="lock-title">locked</h2>
        <input type="password" id="lock-input" />
        <button id="lock-submit">Unlock</button>
        <div id="lock-error" class="hidden">Wrong PIN</div>
        <button id="lock-close">Close</button>
      </div>
    </div>
  `;
});

// ── createLockManager ──────────────────────────────────────

describe("createLockManager", () => {
  function createConfig(overrides = {}) {
    return {
      invoke: vi.fn(),
      lockOverlay: document.getElementById("lock-overlay"),
      lockInput: document.getElementById("lock-input"),
      lockSubmit: document.getElementById("lock-submit"),
      lockError: document.getElementById("lock-error"),
      lockClose: document.getElementById("lock-close"),
      onClose: vi.fn(),
      onUnlock: vi.fn(),
      onLockStart: vi.fn(),
      onLockEnd: vi.fn(),
      ...overrides,
    };
  }

  it("returns checkLock, show, hide, getLocked, setLocked", () => {
    const lock = createLockManager(createConfig());
    expect(lock).toHaveProperty("checkLock");
    expect(lock).toHaveProperty("show");
    expect(lock).toHaveProperty("hide");
    expect(lock).toHaveProperty("getLocked");
    expect(lock).toHaveProperty("setLocked");
  });

  it("starts unlocked", () => {
    const lock = createLockManager(createConfig());
    expect(lock.getLocked()).toBe(false);
  });

  it("checkLock calls invoke('is_locked') and shows overlay if locked", async () => {
    const invoke = vi.fn().mockResolvedValue(true);
    const config = createConfig({ invoke });
    const lock = createLockManager(config);

    await lock.checkLock();

    expect(invoke).toHaveBeenCalledWith("is_locked");
    expect(lock.getLocked()).toBe(true);
    expect(config.lockOverlay.classList.contains("hidden")).toBe(false);
  });

  it("checkLock does not show overlay if not locked", async () => {
    const invoke = vi.fn().mockResolvedValue(false);
    const config = createConfig({ invoke });
    const lock = createLockManager(config);

    await lock.checkLock();

    expect(lock.getLocked()).toBe(false);
    expect(config.lockOverlay.classList.contains("hidden")).toBe(true);
  });

  it("checkLock handles errors gracefully", async () => {
    const invoke = vi.fn().mockRejectedValue(new Error("IPC error"));
    const config = createConfig({ invoke });
    const lock = createLockManager(config);

    await lock.checkLock();

    // Should not crash, locked should remain false
    expect(lock.getLocked()).toBe(false);
  });

  it("show displays overlay and calls onLockStart", () => {
    const config = createConfig();
    const lock = createLockManager(config);

    lock.show();

    expect(config.lockOverlay.classList.contains("hidden")).toBe(false);
    expect(config.lockError.classList.contains("hidden")).toBe(true);
    expect(config.lockInput.value).toBe("");
    expect(config.onLockStart).toHaveBeenCalled();
  });

  it("hide hides overlay and calls onLockEnd", () => {
    const config = createConfig();
    const lock = createLockManager(config);

    config.lockOverlay.classList.remove("hidden"); // simulate shown
    lock.hide();

    expect(config.lockOverlay.classList.contains("hidden")).toBe(true);
    expect(config.onLockEnd).toHaveBeenCalled();
  });

  it("setLocked updates locked state", () => {
    const lock = createLockManager(createConfig());
    lock.setLocked(true);
    expect(lock.getLocked()).toBe(true);
    lock.setLocked(false);
    expect(lock.getLocked()).toBe(false);
  });

  it("submit with correct PIN unlocks and calls onUnlock", async () => {
    const invoke = vi.fn().mockResolvedValue(true);
    const onUnlock = vi.fn();
    const config = createConfig({ invoke, onUnlock });
    const lock = createLockManager(config);

    lock.show();
    config.lockInput.value = "1234";
    config.lockSubmit.click();

    await new Promise(process.nextTick);

    expect(invoke).toHaveBeenCalledWith("unlock", { pin: "1234" });
    expect(lock.getLocked()).toBe(false);
    expect(config.lockOverlay.classList.contains("hidden")).toBe(true);
    expect(onUnlock).toHaveBeenCalled();
  });

  it("submit with wrong PIN shows error and stays locked", async () => {
    const invoke = vi.fn().mockResolvedValue(false);
    const config = createConfig({ invoke });
    const lock = createLockManager(config);

    lock.setLocked(true);
    lock.show();
    config.lockInput.value = "wrong";
    config.lockSubmit.click();

    await new Promise(process.nextTick);

    // locked should remain true after failed unlock
    expect(lock.getLocked()).toBe(true);
    expect(config.lockOverlay.classList.contains("hidden")).toBe(false);
    expect(config.lockError.classList.contains("hidden")).toBe(false);
  });

  it("submit with rejected invoke shows error message", async () => {
    const invoke = vi.fn().mockRejectedValue("PIN required");
    const config = createConfig({ invoke });
    const lock = createLockManager(config);

    lock.setLocked(true);
    lock.show();
    config.lockInput.value = "1234";
    config.lockSubmit.click();

    await new Promise(process.nextTick);

    // Error message from the backend rejection should be displayed
    expect(config.lockError.textContent).toBe("PIN required");
    expect(config.lockError.classList.contains("hidden")).toBe(false);
  });

  it("Enter key triggers submit click", () => {
    const config = createConfig();
    createLockManager(config);

    const clickSpy = vi.spyOn(config.lockSubmit, "click");
    const event = new KeyboardEvent("keydown", { key: "Enter", bubbles: true });
    config.lockInput.dispatchEvent(event);

    expect(clickSpy).toHaveBeenCalled();
  });

  it("lock close button calls onClose", () => {
    const onClose = vi.fn();
    const config = createConfig({ onClose });
    createLockManager(config);

    config.lockClose.click();
    expect(onClose).toHaveBeenCalled();
  });

  it("submit disables button during async and re-enables after", async () => {
    let resolveInvoke;
    const invokePromise = new Promise((resolve) => { resolveInvoke = resolve; });
    const invoke = vi.fn().mockReturnValue(invokePromise);
    const config = createConfig({ invoke });
    const lock = createLockManager(config);

    lock.show();
    config.lockInput.value = "1234";
    config.lockSubmit.click();

    // Button should be disabled while awaiting
    expect(config.lockSubmit.disabled).toBe(true);

    resolveInvoke(true);
    await new Promise(process.nextTick);

    expect(config.lockSubmit.disabled).toBe(false);
  });
});
