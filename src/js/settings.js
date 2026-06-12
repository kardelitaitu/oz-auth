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
    settingsCloseBtn,
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
        <div class="settings-error hidden" id="clipboard-error"></div>
      </div>
    `;

    html += `
      <div class="settings-section settings-about">
        <div class="about-name">${appName}</div>
        <div class="about-version" id="about-version-link" title="View on GitHub">v${appVersion}</div>
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

    // Clipboard timeout auto-save on change
    let clipboardSaveTimer;
    document.getElementById("clipboard-clear").addEventListener("input", () => {
      clearTimeout(clipboardSaveTimer);
      clipboardSaveTimer = setTimeout(async () => {
        const val = parseInt(document.getElementById("clipboard-clear").value, 10);
        const clipError = document.getElementById("clipboard-error");
        clipError.classList.add("hidden");
        if (isNaN(val) || val < 5 || val > 300) return;
        try {
          const cfg = await invoke("load_config");
          cfg.clipboard_clear_seconds = val;
          await invoke("save_config", { cfg });
          if (onClipboardClearSecondsChanged) onClipboardClearSecondsChanged(val);
        } catch (e) {
          clipError.textContent = typeof e === "string" ? e : "Failed to save";
          clipError.classList.remove("hidden");
        }
      }, 400);
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
