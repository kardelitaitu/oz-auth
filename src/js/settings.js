//! Settings dialog: PIN set/change, Lock Now, backup instructions.

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
    lockTimeoutMinutes,
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
    `;

    settingsBody.innerHTML = html;
    const pinError = document.getElementById("pin-error");

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
