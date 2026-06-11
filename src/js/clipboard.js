//! Clipboard copy with auto-clear timer.

/**
 * Create a clipboard manager that auto-clears copied codes after 30s.
 * Returns { copy, clear }.
 */
export function createClipboardManager(toastFn) {
  let clipboardTimer = null;

  async function copyCode(id) {
    const el = document.querySelector(`.card-code[data-id="${id}"]`);
    if (!el) return;
    const code = el.textContent.replace(/\s/g, "");
    try {
      await navigator.clipboard.writeText(code);
      toastFn("Code copied — auto-clears in 30s");
      if (clipboardTimer) clearTimeout(clipboardTimer);
      clipboardTimer = setTimeout(async () => {
        try {
          await navigator.clipboard.writeText("");
          toastFn("Clipboard cleared");
        } catch (_) {}
      }, 30000);
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

  return { copy: copyCode, clear: clearTimer };
}
