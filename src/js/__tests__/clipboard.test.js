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

  it("copy does nothing if element not found", async () => {
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 30);
    await mgr.copy("nonexistent");
    expect(navigator.clipboard.writeText).not.toHaveBeenCalled();
  });

  it("copy writes code to clipboard and shows toast", async () => {
    document.body.innerHTML = '<span class="card-code" data-id="1">123 456</span>';
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 30);

    await mgr.copy("1");

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("123456");
    expect(toast).toHaveBeenCalledWith("Code copied — auto-clears in 30s");
  });

  it("copy with timeout=0 copies without auto-clear timer", async () => {
    document.body.innerHTML = '<span class="card-code" data-id="1">654321</span>';
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 0);

    await mgr.copy("1");

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("654321");
    expect(toast).toHaveBeenCalledWith("Code copied");
    // No timer should be set
    expect(toast).not.toHaveBeenCalledWith("Clipboard cleared");
  });

  it("auto-clears clipboard after timeout seconds", async () => {
    document.body.innerHTML = '<span class="card-code" data-id="1">000111</span>';
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 5);

    await mgr.copy("1");
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("000111");

    // Advance past the 5-second timer
    vi.advanceTimersByTime(5001);
    // Wait for the async timeout callback
    await new Promise(process.nextTick);

    // writeText should have been called again to clear (with random data)
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2);
    const secondCall = navigator.clipboard.writeText.mock.calls[1][0];
    // The second write should be random data (non-empty, different from the code)
    expect(secondCall).not.toBe("");
    expect(secondCall).not.toBe("000111");
    expect(secondCall.length).toBeGreaterThan(0);
  });

  it("successive copy cancels previous auto-clear timer", async () => {
    document.body.innerHTML = `
      <span class="card-code" data-id="1">111111</span>
      <span class="card-code" data-id="2">222222</span>
    `;
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 10);

    await mgr.copy("1");
    await mgr.copy("2");

    // Advance 10 seconds — only one auto-clear should fire
    vi.advanceTimersByTime(10001);
    await new Promise(process.nextTick);

    // 2 writes for copy + 1 for auto-clear = 3 total (the first timer was cancelled)
    expect(navigator.clipboard.writeText.mock.calls.length).toBe(3);
  });

  it("clearOnLock cancels timer and writes random data", async () => {
    document.body.innerHTML = '<span class="card-code" data-id="1">999999</span>';
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 30);

    await mgr.copy("1");

    // Clear on lock
    await mgr.clearOnLock();

    // Should have written random data
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2);
    const clearCall = navigator.clipboard.writeText.mock.calls[1][0];
    expect(clearCall).not.toBe("");
    expect(clearCall).not.toBe("999999");

    // Auto-clear timer (from copy) should have been cancelled
    vi.advanceTimersByTime(30001);
    await new Promise(process.nextTick);
    // Still only 2 writes (copy + clearOnLock)
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2);
  });

  it("setClearSeconds changes timeout for next copy", async () => {
    document.body.innerHTML = '<span class="card-code" data-id="1">555555</span>';
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 30);

    mgr.setClearSeconds(3);
    await mgr.copy("1");

    vi.advanceTimersByTime(3001);
    await new Promise(process.nextTick);

    // Should have auto-cleared after 3 seconds
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2);
  });

  it("handles clipboard write failure gracefully", async () => {
    navigator.clipboard.writeText = vi.fn().mockRejectedValue(new Error("permission denied"));

    document.body.innerHTML = '<span class="card-code" data-id="1">123456</span>';
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 30);

    await mgr.copy("1");
    expect(toast).toHaveBeenCalledWith("Copy failed", true);
  });

  it("clear() cancels pending timer without writing", async () => {
    document.body.innerHTML = '<span class="card-code" data-id="1">777777</span>';
    const toast = vi.fn();
    const mgr = createClipboardManager(toast, 30);

    await mgr.copy("1");
    mgr.clear();

    vi.advanceTimersByTime(30001);
    await new Promise(process.nextTick);

    // Only the copy write — auto-clear was cancelled
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(1);
  });
});
