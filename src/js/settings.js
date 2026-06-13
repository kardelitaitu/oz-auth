//! Settings dialog: PIN set/change, Lock Now, backup instructions, About.

let cancelHandler = null;

/**
 * Open the settings overlay and populate it.
 * `config.ctx` must provide: invoke, toast, onPinSet, onLockNow, lockTimeoutSeconds
 */
export function openSettings(config) {
  const {
    invoke,
    toast,
    isLocked,
    onPinSet,
    onLockNow,
    onClipboardClearSecondsChanged,
    onLockTimeoutChanged,
    onFocusLossChanged,
    lockTimeoutSeconds,
    clipboardClearSeconds,
    appName,
    appVersion,
    settingsOverlay,
    settingsTitle,
    settingsBody,
    settingsCloseBtn,
    backupConfirmOverlay,
    backupPinInput,
    backupConfirmSubmit,
    backupConfirmCancel,
    backupConfirmError,
  } = config;

  settingsOverlay.classList.remove("hidden");

  // Clean up previous close handler to prevent listener accumulation
  if (cancelHandler) {
    settingsCloseBtn.removeEventListener("click", cancelHandler);
  }
  cancelHandler = () => settingsOverlay.classList.add("hidden");
  settingsCloseBtn.addEventListener("click", cancelHandler);

  invoke("load_config").then((cfg) => {
    const hasPin = cfg.password_protected;

    settingsTitle.textContent = "Settings";
    let html = "";

    if (hasPin) {
      html += `
        <div class="settings-section">
          <h3>Change PIN</h3>
          <div class="settings-pin-row">
            <div class="settings-pin-inputs">
              <input type="password" id="pin-old" placeholder="Current PIN" spellcheck="false" autocomplete="off" />
              <input type="password" id="pin-new" placeholder="New PIN" spellcheck="false" autocomplete="off" />
              <input type="password" id="pin-confirm" placeholder="Confirm new PIN" spellcheck="false" autocomplete="off" />
            </div>
            <button class="settings-btn primary settings-pin-btn" id="pin-change-btn">Change</button>
          </div>
          <div class="settings-error hidden" id="pin-error"></div>
        </div>
        <div class="settings-section">
          <h3>Security</h3>
          <button class="settings-btn danger" id="pin-lock-now">Lock Now</button>
        </div>
      `;
    } else {
      html += `
        <div class="settings-section">
          <h3>Set PIN</h3>
          <div class="settings-pin-row">
            <div class="settings-pin-inputs">
              <input type="password" id="pin-new" placeholder="New PIN" spellcheck="false" autocomplete="off" />
              <input type="password" id="pin-confirm" placeholder="Confirm new PIN" spellcheck="false" autocomplete="off" />
            </div>
            <button class="settings-btn primary settings-pin-btn" id="pin-set-btn">Set</button>
          </div>
          <div class="settings-error hidden" id="pin-error"></div>
        </div>
      `;
    }

    html += `
      <div class="settings-section">
        <h3>Backup</h3>
        <button class="settings-btn" id="backup-keys-btn">Backup all keys to file</button>
        <p style="font-size:11px;color:var(--warn-color);margin-top:6px;line-height:1.4;">⚠ Warning: This exports ALL secrets in plain text.<br>Keep the file secure and never share it.</p>
        <p style="font-size:12px;color:var(--btn-color);margin-top:8px;">Find <code>.auth</code> file next to the app .exe</p>
        <p style="font-size:11px;color:var(--btn-color);line-height:1.4;">To export: copy the <code>.auth</code> file to a safe location.<br>To import: replace the <code>.auth</code> file and restart.</p>
      </div>
      <div class="settings-section">
        <div class="settings-row">
          <label class="settings-row-label">Auto-lock (seconds)</label>
          <input type="number" id="lock-timeout" value="${lockTimeoutSeconds}" min="0" max="3600" step="30" class="settings-row-input" />
        </div>
        <div class="settings-row-hint">0 = disabled</div>
      </div>
      <div class="settings-section">
        <div class="settings-row">
          <input type="checkbox" id="lock-on-focus-loss" />
          <label for="lock-on-focus-loss" class="settings-row-label">Lock on focus loss</label>
        </div>
        <div class="settings-row-hint">Auto-lock when the window loses focus</div>
      </div>
      <div class="settings-section">
        <div class="settings-row">
          <label class="settings-row-label">Auto-clear clipboard (seconds)</label>
          <input type="number" id="clipboard-clear" value="${clipboardClearSeconds}" min="0" max="300" step="5" class="settings-row-input" />
        </div>
        <div class="settings-row-hint">0 = disabled</div>
      </div>
    `;

    // Interpolated values are safe (numbers, backend-controlled strings),
    // but escape any string fields for defense-in-depth.
    const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
    );
    html += `
      <div class="settings-section settings-about">
        <div class="about-name">${esc(appName)}</div>
        <div class="about-version" id="about-version-link" title="View on GitHub">v${esc(appVersion)}</div>
      </div>
    `;

    settingsBody.innerHTML = html;
    const pinError = document.getElementById("pin-error");

    // Enter key on PIN inputs triggers the Set/Change button
    const pinInputs = settingsBody.querySelectorAll("#pin-old, #pin-new, #pin-confirm");
    const pinSubmitBtn = document.getElementById(hasPin ? "pin-change-btn" : "pin-set-btn");
    pinInputs.forEach((input) => {
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          if (pinSubmitBtn) pinSubmitBtn.click();
        }
      });
    });

    // Auto-save on input change (debounced)
    let saveTimer;
    async function saveField(field, value, callback) {
      clearTimeout(saveTimer);
      saveTimer = setTimeout(async () => {
        try {
          const cfg = await invoke("load_config");
          cfg[field] = value;
          await invoke("save_config", { cfg });
          if (callback) callback(value);
        } catch (e) {
          // silently ignore — user may still be typing
        }
      }, 400);
    }

    document.getElementById("lock-timeout").addEventListener("input", (e) => {
      const val = parseInt(e.target.value, 10);
      if (isNaN(val) || val < 0 || val > 3600) return;
      saveField("lock_timeout_seconds", val, onLockTimeoutChanged);
    });

    const focusLossCb = document.getElementById("lock-on-focus-loss");
    if (focusLossCb) {
      focusLossCb.checked = cfg.lock_on_focus_loss === true;
      focusLossCb.addEventListener("change", (e) => {
        saveField("lock_on_focus_loss", e.target.checked, onFocusLossChanged);
      });
    }

    document.getElementById("clipboard-clear").addEventListener("input", (e) => {
      const val = parseInt(e.target.value, 10);
      if (isNaN(val) || val < 0 || val > 300) return;
      saveField("clipboard_clear_seconds", val, onClipboardClearSecondsChanged);
    });

    // ── Backup all keys ──────────────────────────────
    document.getElementById("backup-keys-btn").addEventListener("click", () => {
      if (isLocked()) {
        toast("App is locked", true);
        return;
      }
      backupPinInput.value = "";
      backupConfirmError.classList.add("hidden");
      // Show/hide PIN input based on whether PIN is set
      backupPinInput.style.display = hasPin ? "" : "none";
      backupConfirmOverlay.classList.remove("hidden");
      if (hasPin) {
        backupPinInput.focus();
      } else {
        backupConfirmSubmit.focus();
      }
    });

    backupConfirmCancel.addEventListener("click", () => {
      backupConfirmOverlay.classList.add("hidden");
      backupPinInput.value = "";
    });

    backupConfirmSubmit.addEventListener("click", async () => {
      if (isLocked()) {
        toast("App is locked", true);
        return;
      }
      if (hasPin) {
        const pin = backupPinInput.value;
        if (!pin) {
          backupConfirmError.textContent = "PIN required";
          backupConfirmError.classList.remove("hidden");
          return;
        }
        // Verify PIN before exporting
        try {
          await invoke("unlock", { pin });
        } catch (e) {
          backupConfirmError.textContent = "Wrong PIN";
          backupConfirmError.classList.remove("hidden");
          return;
        }
      }
      try {
        const path = await invoke("save_backup_file");
        toast(`Backup saved — ${path}`);
        backupConfirmOverlay.classList.add("hidden");
        backupPinInput.value = "";
        settingsOverlay.classList.add("hidden");
      } catch (e) {
        backupConfirmError.textContent = typeof e === "string" ? e : "Failed";
        backupConfirmError.classList.remove("hidden");
      }
    });

    backupPinInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        backupConfirmSubmit.click();
      }
    });

    if (hasPin) {
      document.getElementById("pin-change-btn").addEventListener("click", async () => {
        if (isLocked()) {
          toast("App is locked", true);
          return;
        }
        const oldPin = document.getElementById("pin-old").value;
        const newPin = document.getElementById("pin-new").value;
        const confirm = document.getElementById("pin-confirm").value;
        if (!oldPin || !newPin || !confirm) {
          pinError.textContent = "All fields required";
          pinError.classList.remove("hidden");
          return;
        }
        if (newPin !== confirm) {
          pinError.textContent = "New PINs don't match";
          pinError.classList.remove("hidden");
          return;
        }
        try {
          await invoke("change_pin", { oldPin, newPin });
          toast("PIN changed");
          settingsOverlay.classList.add("hidden");
        } catch (e) {
          pinError.textContent = typeof e === "string" ? e : "Failed to change PIN";
          pinError.classList.remove("hidden");
        }
      });

      document.getElementById("pin-lock-now").addEventListener("click", async () => {
        onLockNow();
        settingsOverlay.classList.add("hidden");
      });
    } else {
      document.getElementById("pin-set-btn").addEventListener("click", async () => {
        if (isLocked()) {
          toast("App is locked", true);
          return;
        }
        const newPin = document.getElementById("pin-new").value;
        const confirm = document.getElementById("pin-confirm").value;
        if (!newPin || !confirm) {
          pinError.textContent = "All fields required";
          pinError.classList.remove("hidden");
          return;
        }
        if (newPin !== confirm) {
          pinError.textContent = "PINs don't match";
          pinError.classList.remove("hidden");
          return;
        }
        try {
          await invoke("set_lock", { pin: newPin });
          toast("PIN set — app is now protected");
          settingsOverlay.classList.add("hidden");
          if (onPinSet) onPinSet();
        } catch (e) {
          pinError.textContent = typeof e === "string" ? e : "Failed to set PIN";
          pinError.classList.remove("hidden");
        }
      });
    }
    // Clickable version link
    const versionLink = document.getElementById("about-version-link");
    if (versionLink) {
      versionLink.addEventListener("click", () => {
        window.open("https://github.com/kardelitaitu/oz-auth", "_blank");
      });
    }
  }).catch((e) => {
    toast("Failed to load settings", true);
  });
}
