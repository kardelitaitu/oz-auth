//! Vitest setup: DOM helpers for Tauri integration tests.
//! Note: All modules under test receive `invoke` via config params (dependency
//! injection), so we use vi.fn() mocks per test rather than global mockIPC.

/**
 * A default mock handler that returns sensible defaults for common Tauri commands.
 * Used directly in test files as a fallback inside mockImplementation.
 * Override specific commands by passing overrides to your createConfig function.
 */
export function defaultMockHandler(cmd) {
  switch (cmd) {
    case "list_accounts":
      return [];
    case "generate_all_codes":
      return [];
    case "load_config":
      return {
        theme: "dark",
        always_on_top: false,
        lock_timeout_seconds: 300,
        clipboard_clear_seconds: 30,
        password_protected: false,
        lock_on_focus_loss: false,
        width: 400,
        height: 600,
      };
    case "get_app_name":
      return "oz-auth";
    case "get_app_version":
      return "0.1.4";
    case "is_locked":
      return false;
    case "unlock":
      return true;
    case "get_audit_log":
      return [];
    case "get_otpauth_uri":
      return "otpauth://totp/test?secret=TEST&issuer=Test";
    case "save_backup_file":
      return "/tmp/backup.auth";
    default:
      return null;
  }
}

/**
 * Create DOM elements commonly needed by settings and account dialog tests.
 * Attaches them to document.body if not already present.
 */
export function ensureSettingsDom() {
  const container = document.getElementById("settings-overlay");
  if (container) return;

  const html = `
    <div id="settings-overlay" class="hidden">
      <div id="settings-card">
        <div class="settings-header">
          <h2 id="settings-title">Settings</h2>
          <button id="settings-close-btn">×</button>
        </div>
        <div id="settings-body"></div>
      </div>
    </div>
    <div id="backup-confirm-overlay" class="hidden">
      <div id="backup-confirm-card">
        <h2 id="backup-confirm-title">Export all keys?</h2>
        <p id="backup-confirm-msg"></p>
        <input type="password" id="backup-pin-input" />
        <div id="backup-confirm-error" class="hidden"></div>
        <div class="dialog-actions">
          <button id="backup-confirm-cancel">Cancel</button>
          <button id="backup-confirm-submit">Confirm</button>
        </div>
      </div>
    </div>
    <div id="toast-bar" class="hidden"></div>
    <div id="account-dialog" class="hidden">
      <div id="dialog-card">
        <h2 id="dialog-title">Add Account</h2>
        <input type="text" id="dialog-issuer" />
        <input type="text" id="dialog-label" />
        <input type="text" id="dialog-secret" />
        <div class="dialog-row"><label>Algorithm</label><select id="dialog-algorithm"><option value="SHA1">SHA1</option><option value="SHA256">SHA256</option><option value="SHA512">SHA512</option></select></div>
        <div class="dialog-row"><label>Digits</label><select id="dialog-digits"><option value="6">6</option><option value="8">8</option></select></div>
        <div class="dialog-row"><label>Period</label><select id="dialog-period"><option value="30">30s</option><option value="60">60s</option></select></div>
        <div class="dialog-actions">
          <button id="dialog-cancel">Cancel</button>
          <button id="dialog-submit">Add</button>
        </div>
      </div>
    </div>
    <div id="lock-overlay" class="hidden">
      <div id="lock-card">
        <h2 id="lock-title">locked</h2>
        <input type="password" id="lock-input" />
        <button id="lock-submit">Unlock</button>
        <div id="lock-error" class="hidden"></div>
        <button id="lock-close">Close</button>
      </div>
    </div>
    <div id="account-list"></div>
    <div id="context-menu" class="hidden">
      <div class="ctx-item" data-action="edit">Edit</div>
      <div class="ctx-item" data-action="qr">QR</div>
      <div class="ctx-item ctx-delete" data-action="delete">Delete</div>
    </div>
    <div id="delete-confirm-overlay" class="hidden">
      <div id="delete-confirm-card">
        <h2 id="delete-confirm-title">Delete?</h2>
        <p id="delete-confirm-msg"></p>
        <button id="delete-confirm-submit">Delete</button>
        <button id="delete-confirm-cancel">Cancel</button>
      </div>
    </div>
    <div id="qr-popup" class="hidden">
      <div id="qr-card">
        <h2 id="qr-title">QR</h2>
        <canvas id="qr-canvas"></canvas>
        <button id="qr-close-btn">Close</button>
      </div>
    </div>
    <div id="app"></div>
  `;
  document.body.insertAdjacentHTML("beforeend", html);
}
