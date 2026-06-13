//! Integration tests for the TOTP module using Tauri mock IPC and DOM elements.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { formatCode, refreshCodes, updateBars, startCountdown, stopCountdown } from "../totp.js";
beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  stopCountdown();
});

// ── formatCode ─────────────────────────────────────────

describe("formatCode", () => {
  it("formats 6-digit code as XXX XXX", () => {
    expect(formatCode("123456")).toBe("123 456");
  });

  it("formats 8-digit code as XXXX XXXX", () => {
    expect(formatCode("12345678")).toBe("1234 5678");
  });

  it("returns untounched for other lengths", () => {
    expect(formatCode("123")).toBe("123");
    expect(formatCode("1234567890")).toBe("1234567890");
  });
});

// ── refreshCodes ───────────────────────────────────────────

describe("refreshCodes", () => {
  it("skips refresh when locked", async () => {
    const invoke = vi.fn();
    const result = await refreshCodes(invoke, true, {}, vi.fn(), vi.fn());
    expect(invoke).not.toHaveBeenCalled();
    expect(result).toEqual({});
  });

  it("calls invoke('generate_all_codes') and updates DOM", async () => {
    document.body.innerHTML = `
      <div class="account-card">
        <span class="card-code" data-id="a1">------</span>
        <circle class="ring-fg" data-id="a1" stroke-dashoffset="0"></circle>
      </div>
    `;

    const invoke = vi.fn().mockResolvedValue([
      ["a1", "123456", 15],
    ]);
    const secondsRemaining = {};
    const updateBarsFn = vi.fn();

    const result = await refreshCodes(invoke, false, secondsRemaining, updateBarsFn, vi.fn());

    expect(invoke).toHaveBeenCalledWith("generate_all_codes");
    expect(secondsRemaining.a1).toBe(15);
    expect(document.querySelector(".card-code").textContent).toBe("123 456");
    expect(updateBarsFn).toHaveBeenCalled();
    expect(result).toBe(secondsRemaining);
  });

  it("handles invoke errors gracefully", async () => {
    const invoke = vi.fn().mockRejectedValue(new Error("IPC error"));
    const onError = vi.fn();
    const result = await refreshCodes(invoke, false, {}, vi.fn(), onError);

    expect(onError).toHaveBeenCalledWith("Failed to refresh codes", true);
    expect(result).toEqual({});
  });

  it("handles string error messages", async () => {
    const invoke = vi.fn().mockRejectedValue("Backend error");
    const onError = vi.fn();
    await refreshCodes(invoke, false, {}, vi.fn(), onError);

    expect(onError).toHaveBeenCalledWith("Backend error", true);
  });
});

// ── updateBars ─────────────────────────────────────────────

describe("updateBars", () => {
  it("updates ring dashoffset and color based on remaining time", () => {
    document.body.innerHTML = `
      <svg>
        <circle class="ring-fg" data-id="a1" stroke-dashoffset="0" stroke="#000"></circle>
        <text class="ring-text" data-id="a1">30</text>
      </svg>
    `;

    const accounts = [{ id: "a1", period: 30 }];
    const secondsRemaining = { a1: 16 };

    updateBars(accounts, secondsRemaining);

    const ring = document.querySelector(".ring-fg");
    const text = document.querySelector(".ring-text");

    // 16/30 > 0.5 → blue
    // offset = (14/30) * 119.381 ≈ 55.71
    expect(parseFloat(ring.style.strokeDashoffset)).toBeCloseTo(55.71, 0);
    expect(ring.style.stroke).toBe("#5dade2"); // > 50% remaining
    expect(text.textContent).toBe("16");
  });

  it("shows orange when 25-50% remaining", () => {
    document.body.innerHTML = `
      <svg>
        <circle class="ring-fg" data-id="a1"></circle>
        <text class="ring-text" data-id="a1"></text>
      </svg>
    `;

    updateBars([{ id: "a1", period: 30 }], { a1: 9 });
    const ring = document.querySelector(".ring-fg");

    // 9/30 = 30% remaining → orange
    expect(ring.style.stroke).toBe("#e67e22");
  });

  it("shows red when < 25% remaining", () => {
    document.body.innerHTML = `
      <svg>
        <circle class="ring-fg" data-id="a1"></circle>
        <text class="ring-text" data-id="a1"></text>
      </svg>
    `;

    updateBars([{ id: "a1", period: 30 }], { a1: 5 });
    const ring = document.querySelector(".ring-fg");

    // 5/30 = 16.7% → red
    expect(ring.style.stroke).toBe("#e81123");
  });

  it("handles missing DOM elements gracefully", () => {
    // No elements in DOM — should not throw
    expect(() => {
      updateBars([{ id: "a1", period: 30 }], { a1: 15 });
    }).not.toThrow();
  });
});

// ── startCountdown / stopCountdown ─────────────────────────

describe("startCountdown / stopCountdown", () => {
  it("calls refreshCodes on start", () => {
    document.body.innerHTML = `
      <span class="card-code" data-id="a1">------</span>
    `;

    const invoke = vi.fn().mockResolvedValue([["a1", "654321", 30]]);
    const getAccounts = () => [{ id: "a1", period: 30 }];
    const getLocked = () => false;
    const getSecondsRemaining = () => ({ a1: 30 });
    const updateTray = vi.fn();
    const onError = vi.fn();

    startCountdown(invoke, getAccounts, getLocked, getSecondsRemaining, updateTray, onError);

    // Initial refreshCodes should have been called
    expect(invoke).toHaveBeenCalledWith("generate_all_codes");
  });

  it("decrements seconds each tick", () => {
    document.body.innerHTML = `
      <svg>
        <circle class="ring-fg" data-id="a1"></circle>
        <text class="ring-text" data-id="a1"></text>
      </svg>
    `;

    const secondsMap = { a1: 30 };
    const invoke = vi.fn().mockResolvedValue([["a1", "000000", 30]]);
    const getAccounts = () => [{ id: "a1", period: 30 }];
    const getLocked = () => false;
    const updateTray = vi.fn();

    startCountdown(invoke, getAccounts, getLocked, () => secondsMap, updateTray, vi.fn());

    // Advance 2 ticks
    vi.advanceTimersByTime(2000);
    expect(secondsMap.a1).toBe(28);
  });

  it("stopCountdown clears the interval", () => {
    const secondsMap = { a1: 30 };
    const invoke = vi.fn().mockResolvedValue([["a1", "000000", 30]]);
    const getAccounts = () => [{ id: "a1", period: 30 }];
    const getLocked = () => false;
    const updateTray = vi.fn();

    startCountdown(invoke, getAccounts, getLocked, () => secondsMap, updateTray, vi.fn());

    // Stop immediately
    stopCountdown();

    // Advance 5 seconds — nothing should decrement
    vi.advanceTimersByTime(5000);
    expect(secondsMap.a1).toBe(30);
  });

  it("refreshes codes when any counter hits 0", () => {
    document.body.innerHTML = `
      <span class="card-code" data-id="a1">------</span>
    `;

    const secondsMap = { a1: 2 }; // will hit 0 in 2 ticks
    let codeCallCount = 0;
    const invoke = vi.fn().mockImplementation((cmd) => {
      if (cmd === "generate_all_codes") {
        codeCallCount++;
        return Promise.resolve([["a1", "999999", 30]]);
      }
      return Promise.resolve(null);
    });

    const getAccounts = () => [{ id: "a1", period: 30 }];
    const getLocked = () => false;

    startCountdown(invoke, getAccounts, getLocked, () => secondsMap, vi.fn(), vi.fn());

    // Advance past 0
    vi.advanceTimersByTime(3000);

    // refreshCodes should have been called when counter hit 0
    expect(codeCallCount).toBeGreaterThanOrEqual(2); // initial + refresh
  });
});
