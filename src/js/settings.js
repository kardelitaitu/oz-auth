//! Settings dialog: PIN set/change, Lock Now, backup instructions, About.

let cancelHandler = null;

/**
 * Open the settings overlay and populate it.
 * `config.ctx` must provide: invoke, toast, onPinSet, onLockNow, lockTimeoutMinutes
 */
export function openSettings(config) {
  const {
    invoke,
    toast,
    onPinSet,
    onLockNow,
    onClipboardClearSecondsChanged,
    lockTimeoutMinutes,
    clipboardClearSeconds,
    appName,
    appVersion,
    settingsOverlay,
    settingsTitle,
    settingsBody,
    settingsCancel,
  } = config;

  settingsOverlay.classList.remove("hidden");

  // Clean up previous cancel handler to prevent listener accumulation
  if (cancelHandler) {
    settingsCancel.removeEventListener("click", cancelHandler);
  }
  cancelHandler = () => settingsOverlay.classList.add("hidden");
  settingsCancel.addEventListener("click", cancelHandler);

  invoke("load_config").then((cfg) => {
    const hasPin = cfg.password_protected;

    settingsTitle.textContent = "Settings";
    let html = "";

    if (hasPin) {
      html += `
        <div class="settings-section">
          <h3>Change PIN</h3>
          <input type="password" id="pin-old" placeholder="Current PIN" spellcheck="false" autocomplete="off" />
          <input type="password" id="pin-new" placeholder="New PIN" spellcheck="false" autocomplete="off" />
          <input type="password" id="pin-confirm" placeholder="Confirm new PIN" spellcheck="false" autocomplete="off" />
          <div class="settings-error hidden" id="pin-error"></div>
          <button class="settings-btn primary" id="pin-change-btn">Change PIN</button>
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
          <input type="password" id="pin-new" placeholder="New PIN" spellcheck="false" autocomplete="off" />
          <input type="password" id="pin-confirm" placeholder="Confirm new PIN" spellcheck="false" autocomplete="off" />
          <div class="settings-error hidden" id="pin-error"></div>
          <button class="settings-btn primary" id="pin-set-btn">Set PIN</button>
        </div>
      `;
    }

    html += `
      <div class="settings-section">
        <h3>Backup</h3>
        <p style="font-size:12px;color:var(--btn-color);margin-bottom:4px;">Find <code>.auth</code> file next to the app .exe</p>
        <p style="font-size:11px;color:var(--btn-color);line-height:1.4;">To export: copy the <code>.auth</code> file to a safe location.<br>To import: replace the <code>.auth</code> file and restart.</p>
      </div>
      <div class="settings-section">
        <h3>Auto-Lock</h3>
        <p style="font-size:12px;color:var(--btn-color);margin-bottom:4px;">Lock after ${lockTimeoutMinutes} min of inactivity</p>
      </div>
      <div class="settings-section">
        <h3>Clipboard</h3>
        <label style="font-size:12px;color:var(--btn-color);">Auto-clear after (seconds):</label>
        <input type="number" id="clipboard-clear" value="${clipboardClearSeconds}" min="5" max="300" step="5" style="width:80px;margin-top:4px;" />
        <button class="settings-btn primary" id="clipboard-save-btn" style="margin-top:4px;">Save</button>
        <div class="settings-error hidden" id="clipboard-error"></div>
      </div>
    `;

    html += `
      <div class="settings-section settings-about">
        <div class="about-name">${appName}</div>
        <div class="about-version">v${appVersion}</div>
        <div class="about-credits">
          <p>A secure, offline TOTP authenticator</p>
          <p>Built with <strong>Tauri v2</strong> + <strong>Rust</strong></p>
          <p class="about-copyright">&copy; ${new Date().getFullYear()} ${appName}</p>
        </div>
      </div>
    `;

    settingsBody.innerHTML = html;
    const pinError = document.getElementById("pin-error");

    // Clipboard timeout save
    document.getElementById("clipboard-save-btn").addEventListener("click", async () => {
      const val = parseInt(document.getElementById("clipboard-clear").value, 10);
      const clipError = document.getElementById("clipboard-error");
      if (isNaN(val) || val < 5 || val > 300) {
        clipError.textContent = "Must be 5–300 seconds";
        clipError.classList.remove("hidden");
        return;
      }
      try {
        const cfg = await invoke("load_config");
        cfg.clipboard_clear_seconds = val;
        await invoke("save_config", { cfg });
        toast("Clipboard timeout saved");
        if (onClipboardClearSecondsChanged) onClipboardClearSecondsChanged(val);
      } catch (e) {
        clipError.textContent = typeof e === "string" ? e : "Failed to save";
        clipError.classList.remove("hidden");
      }
    });

    if (hasPin) {
      document.getElementById("pin-change-btn").addEventListener("click", async () => {
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
  }).catch((e) => {
    toast("Failed to load settings", true);
  });
}
