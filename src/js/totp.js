//! TOTP display logic: countdown timer, code formatting, progress bars.
//! Pure utility functions — state is managed by the caller (main.js).

/**
 * Format a TOTP code with spacing: "123456" → "123 456", "12345678" → "1234 5678"
 */
export function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

/**
 * Refresh all TOTP codes from the backend and update the DOM.
 * Returns the updated secondsRemaining map.
 * `onError(msg, isError)` is called on failure so the caller can show a toast.
 */
export async function refreshCodes(invoke, locked, secondsRemaining, updateBarsFn, onError) {
  if (locked) return secondsRemaining;
  try {
    const codes = await invoke("generate_all_codes");
    codes.forEach(([id, code, remaining]) => {
      secondsRemaining[id] = remaining;
      const codeEl = document.querySelector(`.card-code[data-id="${id}"]`);
      if (codeEl) codeEl.textContent = formatCode(code);
    });
    updateBarsFn();
  } catch (e) {
    console.error("generate_all_codes error:", e);
    if (onError) onError(typeof e === "string" ? e : "Failed to refresh codes", true);
  }
  return secondsRemaining;
}

/**
 * Update the countdown progress bars and timer labels.
 */
export function updateBars(accounts, secondsRemaining) {
  accounts.forEach((a) => {
    const remaining = secondsRemaining[a.id] || a.period;
    const pct = ((a.period - remaining) / a.period) * 100;
    const fill = document.querySelector(`.card-bar-fill[data-id="${a.id}"]`);
    const timer = document.querySelector(`.card-timer[data-id="${a.id}"]`);
    if (fill) fill.style.width = `${pct}%`;
    if (timer) timer.textContent = `${Math.max(0, remaining)}s`;
  });
}

/**
 * Start the 1-second countdown interval.
 * Returns a `stop` function.
 * `onError(msg, isError)` forwarded to refreshCodes for toast visibility.
 */
export function startCountdown(invoke, getAccounts, getLocked, getSecondsRemaining, updateTrayIcon, onError) {
  const stopFn = stopCountdown;

  refreshCodes(invoke, getLocked(), getSecondsRemaining(), () =>
    updateBars(getAccounts(), getSecondsRemaining())
  , onError);

  const interval = setInterval(() => {
    let needsRefresh = true;
    let totalPct = 0;
    let count = 0;
    const secs = getSecondsRemaining();
    const accts = getAccounts();

    for (const id in secs) {
      secs[id]--;
      if (secs[id] <= 0) {
        delete secs[id];
        needsRefresh = true;
      }
      const a = accts.find((acc) => acc.id === id);
      if (a && secs[id] !== undefined) {
        totalPct += ((a.period - secs[id]) / a.period) * 100;
        count++;
      }
    }
    updateBars(accts, secs);
    if (count > 0) {
      updateTrayIcon(totalPct / count);
    }
    if (needsRefresh) {
      // No onError here — interval failures shouldn't spam toasts every second
      refreshCodes(invoke, getLocked(), secs, () => updateBars(getAccounts(), secs));
    }
  }, 1000);

  stopFn._interval = interval;
  return stopFn;
}

export function stopCountdown() {
  if (stopCountdown._interval) {
    clearInterval(stopCountdown._interval);
    stopCountdown._interval = null;
  }
}
