//! Clipboard copy with configurable auto-clear timer.

/**
 * Create a clipboard manager that auto-clears copied codes after `clearSeconds`.
 * Returns { copy, clear, setClearSeconds }.
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
      toastFn("Code copied — auto-clears in " + timeout + "s");
      if (clipboardTimer) clearTimeout(clipboardTimer);
      clipboardTimer = setTimeout(async () => {
        try {
          await navigator.clipboard.writeText("");
          toastFn("Clipboard cleared");
        } catch (_) {}
      }, timeout * 1000);
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

  return { copy: copyCode, clear: clearTimer, setClearSeconds };
}
