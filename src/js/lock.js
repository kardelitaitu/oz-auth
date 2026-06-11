//! App lock screen: overlay, PIN entry, unlock flow.

/**
 * Create a lock screen manager.
 * Returns { checkLock, show, hide, getLocked }.
 */
export function createLockManager(config) {
  const {
    invoke,
    lockOverlay,
    lockInput,
    lockSubmit,
    lockError,
    onUnlock,      // called after successful unlock
    onLockStart,   // called when showing lock screen
    onLockEnd,     // called when hiding lock screen
  } = config;

  let locked = false;

  async function checkLock() {
    try {
      locked = await invoke("is_locked");
      if (locked) show();
    } catch (e) {
      console.error("is_locked error:", e);
    }
    return locked;
  }

  function show() {
    lockOverlay.classList.remove("hidden");
    lockError.classList.add("hidden");
    lockInput.value = "";
    if (onLockStart) onLockStart();
    setTimeout(() => lockInput.focus(), 100);
  }

  function hide() {
    lockOverlay.classList.add("hidden");
    if (onLockEnd) onLockEnd();
  }

  lockSubmit.addEventListener("click", async () => {
    const pin = lockInput.value;
    if (!pin) return;
    lockSubmit.disabled = true;
    try {
      const ok = await invoke("unlock", { pin });
      if (ok) {
        locked = false;
        hide();
        if (onUnlock) await onUnlock();
      } else {
        lockError.classList.remove("hidden");
        lockInput.value = "";
        lockInput.focus();
      }
    } catch (e) {
      lockError.textContent = typeof e === "string" ? e : "Wrong PIN.";
      lockError.classList.remove("hidden");
    } finally {
      lockSubmit.disabled = false;
    }
  });

  lockInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") lockSubmit.click();
  });

  return {
    checkLock,
    show,
    hide,
    getLocked: () => locked,
    setLocked: (val) => { locked = val; },
  };
}
