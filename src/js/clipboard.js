//! Clipboard copy with configurable auto-clear timer.

/** Generate random data to overwrite clipboard contents, preventing recovery from clipboard history. */
function randomClearString() {
  try {
    return crypto.randomUUID() + crypto.randomUUID();
  } catch (_) {
    // Fallback if crypto.randomUUID is unavailable
    return Math.random().toString(36).repeat(8);
  }
}

/** Overwrite clipboard with random noise instead of an empty string. */
async function clearClipboard() {
  await navigator.clipboard.writeText(randomClearString());
}

/**
 * Create a clipboard manager that auto-clears copied codes after `clearSeconds`.
 * Returns { copy, clear, setClearSeconds, clearOnLock }.
 */
export function createClipboardManager(toastFn, clearSeconds = 30) {
  let clipboardTimer = null;
  let timeout = clearSeconds;

  async function copyCode(id) {
    const el = document.querySelector(`.card-code[data-id="${id}"]`);
    if (!el) return;
    const code = el.textContent.replace(/\s/g, "");
    try {
      await navigator.clipboard.writeText(code);
      if (timeout > 0) {
        toastFn("Code copied — auto-clears in " + timeout + "s");
        if (clipboardTimer) clearTimeout(clipboardTimer);
        clipboardTimer = setTimeout(async () => {
          try {
            await clearClipboard();
            toastFn("Clipboard cleared");
          } catch (_) {}
        }, timeout * 1000);
      } else {
        toastFn("Code copied");
      }
    } catch (e) {
      toastFn("Copy failed", true);
    }
  }

  function clearTimer() {
    if (clipboardTimer) {
      clearTimeout(clipboardTimer);
      clipboardTimer = null;
    }
  }

  function setClearSeconds(seconds) {
    timeout = seconds;
  }

  /**
   * Clear the clipboard immediately (called when the app locks).
   * Cancels any pending auto-clear timer and wipes the clipboard contents.
   */
  async function clearOnLock() {
    clearTimer();
    try {
      await clearClipboard();
      toastFn("Clipboard cleared");
    } catch (_) {}
  }

  return { copy: copyCode, clear: clearTimer, setClearSeconds, clearOnLock };
}
