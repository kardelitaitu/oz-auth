//! Integration tests for the clipboard module.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createClipboardManager } from "../clipboard.js";

beforeEach(() => {
  vi.useFakeTimers();
  // Mock clipboard API — navigator.clipboard is read-only in happy-dom,
  // so we use vi.stubGlobal to replace the entire navigator
  vi.stubGlobal("navigator", {
    clipboard: {
      writeText: vi.fn().mockResolvedValue(undefined),
    },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.useRealTimers();
});

// ── createClipboardManager ─────────────────────────────────

describe("createClipboardManager", () => {
  it("returns copy, clear, setClearSeconds, clearOnLock", () => {
    const mgr = createClipboardManager(vi.fn(), 30);
    expect(mgr).toHaveProperty("copy");
    expect(mgr).toHaveProperty("clear");
    expect(mgr).toHaveProperty("setClearSeconds");
    expect(mgr).toHaveProperty("clearOnLock");
  });

  it("copy does nothing if invoke fails", async () => {
    const toast = vi.fn();
    const mockInvoke = vi.fn().mockRejectedValue(new Error("no account"));
    const mgr = createClipboardManager(toast, 30, mockInvoke);
    await mgr.copy("nonexistent");
    expect(navigator.clipboard.writeText).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith("Copy failed", true);
  });

  it("copy writes code to clipboard and shows toast", async () => {
    const toast = vi.fn();
    const mockInvoke = vi.fn().mockResolvedValue(["123456"]);
    const mgr = createClipboardManager(toast, 30, mockInvoke);

    await mgr.copy("1");

    expect(mockInvoke).toHaveBeenCalledWith("generate_code", { accountId: "1" });
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("123456");
    expect(toast).toHaveBeenCalledWith("Code copied — auto-clears in 30s");
  });

  it("copy with timeout=0 copies without auto-clear timer", async () => {
    const toast = vi.fn();
    const mockInvoke = vi.fn().mockResolvedValue(["654321"]);
    const mgr = createClipboardManager(toast, 0, mockInvoke);

    await mgr.copy("1");

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("654321");
    expect(toast).toHaveBeenCalledWith("Code copied");
    expect(toast).not.toHaveBeenCalledWith("Clipboard cleared");
  });

  it("auto-clears clipboard after timeout seconds", async () => {
    const toast = vi.fn();
    const mockInvoke = vi.fn().mockResolvedValue(["000111"]);
    const mgr = createClipboardManager(toast, 5, mockInvoke);

    await mgr.copy("1");
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("000111");

    vi.advanceTimersByTime(5001);
    await new Promise(process.nextTick);

    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2);
    const secondCall = navigator.clipboard.writeText.mock.calls[1][0];
    expect(secondCall).not.toBe("");
    expect(secondCall).not.toBe("000111");
    expect(secondCall.length).toBeGreaterThan(0);
  });

  it("successive copy cancels previous auto-clear timer", async () => {
    const toast = vi.fn();
    let callCount = 0;
    const mockInvoke = vi.fn().mockImplementation(() => {
      callCount++;
      return Promise.resolve([callCount === 1 ? "111111" : "222222"]);
    });
    const mgr = createClipboardManager(toast, 10, mockInvoke);

    await mgr.copy("1");
    await mgr.copy("2");

    vi.advanceTimersByTime(10001);
    await new Promise(process.nextTick);

    expect(navigator.clipboard.writeText.mock.calls.length).toBe(3);
  });

  it("clearOnLock cancels timer and writes random data", async () => {
    const toast = vi.fn();
    const mockInvoke = vi.fn().mockResolvedValue(["999999"]);
    const mgr = createClipboardManager(toast, 30, mockInvoke);

    await mgr.copy("1");

    await mgr.clearOnLock();

    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2);
    const clearCall = navigator.clipboard.writeText.mock.calls[1][0];
    expect(clearCall).not.toBe("");
    expect(clearCall).not.toBe("999999");

    vi.advanceTimersByTime(30001);
    await new Promise(process.nextTick);
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2);
  });

  it("setClearSeconds changes timeout for next copy", async () => {
    const toast = vi.fn();
    const mockInvoke = vi.fn().mockResolvedValue(["555555"]);
    const mgr = createClipboardManager(toast, 30, mockInvoke);

    mgr.setClearSeconds(3);
    await mgr.copy("1");

    vi.advanceTimersByTime(3001);
    await new Promise(process.nextTick);

    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2);
  });

  it("handles clipboard write failure gracefully", async () => {
    navigator.clipboard.writeText = vi.fn().mockRejectedValue(new Error("permission denied"));

    const toast = vi.fn();
    const mockInvoke = vi.fn().mockResolvedValue(["123456"]);
    const mgr = createClipboardManager(toast, 30, mockInvoke);

    await mgr.copy("1");
    expect(toast).toHaveBeenCalledWith("Copy failed", true);
  });

  it("clear() cancels pending timer without writing", async () => {
    const toast = vi.fn();
    const mockInvoke = vi.fn().mockResolvedValue(["777777"]);
    const mgr = createClipboardManager(toast, 30, mockInvoke);

    await mgr.copy("1");
    mgr.clear();

    vi.advanceTimersByTime(30001);
    await new Promise(process.nextTick);

    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(1);
  });
});
