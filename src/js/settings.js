//! Settings dialog: PIN set/change, Lock Now, backup instructions, About.
//! All content built with DOM APIs (no innerHTML) to prevent XSS.

let cancelHandler = null;

// ── DOM helper utilities ──────────────────────────────────

/** Common weak PINs checked by the strength meter. */
const COMMON_WEAK_PINS = [
  "123456", "12345678", "000000", "111111", "222222", "333333",
  "444444", "555555", "666666", "777777", "888888", "999999",
  "password", "qwerty", "abc123",
];

/** Create a <div class="settings-section"> with an optional <h3> heading. */
function createSection(heading) {
  const section = document.createElement("div");
  section.className = "settings-section";
  if (heading) {
    const h3 = document.createElement("h3");
    h3.textContent = heading;
    section.appendChild(h3);
  }
  return section;
}

/** Create a password <input> with common attributes. */
function createPasswordInput(id, placeholder) {
  const input = document.createElement("input");
  input.type = "password";
  input.id = id;
  input.placeholder = placeholder;
  input.spellcheck = false;
  input.autocomplete = "off";
  return input;
}

/** Create a <button class="settings-btn [extraClass]" id="[id]">text</button>. */
function createButton(text, extraClass, id) {
  const btn = document.createElement("button");
  btn.className = extraClass ? `settings-btn ${extraClass}` : "settings-btn";
  if (id) btn.id = id;
  btn.textContent = text;
  return btn;
}

/** Create a labelled settings row with a number input. */
function createNumberRow(labelText, id, value, min, max, step) {
  const row = document.createElement("div");
  row.className = "settings-row";

  const label = document.createElement("label");
  label.className = "settings-row-label";
  label.textContent = labelText;
  row.appendChild(label);

  const input = document.createElement("input");
  input.type = "number";
  input.id = id;
  input.value = String(value);
  input.min = String(min);
  input.max = String(max);
  input.step = String(step);
  input.className = "settings-row-input";
  row.appendChild(input);

  return row;
}

// ── Section builders ──────────────────────────────────────

/**
 * Score a PIN (0–100) and return a label + level for the strength meter.
 * Pure function — no minimum length enforced, just informative feedback.
 */
function computePinStrength(pin) {
  if (!pin) return { score: 0, label: "", level: "none" };

  let score = 0;
  const len = pin.length;

  // Length contribution (up to 40 points)
  score += Math.min(len * 4, 40);

  // Character variety
  if (/[a-z]/.test(pin)) score += 10;
  if (/[A-Z]/.test(pin)) score += 10;
  if (/[0-9]/.test(pin)) score += 10;
  if (/[^a-zA-Z0-9]/.test(pin)) score += 15;

  // Bonus for longer PINs
  if (len >= 8) score += 10;
  if (len >= 12) score += 5;

  // Deductions for weak patterns
  if (/^(.)\1+$/.test(pin)) score -= 20;  // all same char
  if ("1234567890".includes(pin) || "0987654321".includes(pin)) score -= 20;  // sequential digits
  if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(pin)) score -= 15;  // sequential letters
  // Common weak PINs
  if (COMMON_WEAK_PINS.includes(pin.toLowerCase())) score -= 20;

  // Clamp to 0–100
  score = Math.max(0, Math.min(100, score));

  let label, level;
  if (score >= 76) { label = "Very Strong"; level = "very-strong"; }
  else if (score >= 51) { label = "Strong"; level = "strong"; }
  else if (score >= 26) { label = "Medium"; level = "medium"; }
  else { label = "Weak"; level = "weak"; }

  return { score, label, level };
}

/** Build the PIN section (Set PIN or Change PIN + Lock Now). */
function buildPinSection(hasPin) {
  const section = createSection(hasPin ? "Change PIN" : "Set PIN");
  const row = document.createElement("div");
  row.className = "settings-pin-row";

  const inputs = document.createElement("div");
  inputs.className = "settings-pin-inputs";

  if (hasPin) {
    inputs.appendChild(createPasswordInput("pin-old", "Current PIN"));
  }
  inputs.appendChild(createPasswordInput("pin-new", "New PIN"));
  inputs.appendChild(createPasswordInput("pin-confirm", "Confirm new PIN"));

  // ── PIN strength meter ────────────────────────────────────
  const meter = document.createElement("div");
  meter.className = "pin-strength-meter hidden";
  meter.id = "pin-strength-meter";

  const bar = document.createElement("div");
  bar.className = "pin-strength-bar";
  const fill = document.createElement("div");
  fill.className = "pin-strength-fill";
  fill.id = "pin-strength-fill";
  bar.appendChild(fill);
  meter.appendChild(bar);

  const lbl = document.createElement("span");
  lbl.className = "pin-strength-label";
  lbl.id = "pin-strength-label";
  lbl.textContent = "";
  meter.appendChild(lbl);

  inputs.appendChild(meter);

  row.appendChild(inputs);

  const btnId = hasPin ? "pin-change-btn" : "pin-set-btn";
  const btnLabel = hasPin ? "Change" : "Set";
  row.appendChild(createButton(btnLabel, "primary settings-pin-btn", btnId));
  section.appendChild(row);

  const error = document.createElement("div");
  error.className = "settings-error hidden";
  error.id = "pin-error";
  section.appendChild(error);

  // If PIN is already set, also show Lock Now button
  if (hasPin) {
    const secSection = createSection("Security");
    secSection.appendChild(createButton("Lock Now", "danger", "pin-lock-now"));
    return [section, secSection];
  }
  return [section];
}

/** Build the Backup section. */
function buildBackupSection() {
  const section = createSection("Backup");
  section.appendChild(createButton("Backup all keys to file", "", "backup-keys-btn"));

  const warn = document.createElement("p");
  warn.style.cssText = "font-size:11px;color:var(--warn-color);margin-top:6px;line-height:1.4;";
  warn.textContent = "⚠ Warning: This exports ALL secrets in plain text. Keep the file secure and never share it.";
  section.appendChild(warn);

  const hint1 = document.createElement("p");
  hint1.style.cssText = "font-size:12px;color:var(--btn-color);margin-top:8px;";
  hint1.appendChild(document.createTextNode("Find "));
  const code1 = document.createElement("code");
  code1.textContent = ".auth";
  hint1.appendChild(code1);
  hint1.appendChild(document.createTextNode(" file next to the app .exe"));
  section.appendChild(hint1);

  const hint2 = document.createElement("p");
  hint2.style.cssText = "font-size:11px;color:var(--btn-color);line-height:1.4;";
  hint2.appendChild(document.createTextNode("To export: copy the "));
  const code2a = document.createElement("code");
  code2a.textContent = ".auth";
  hint2.appendChild(code2a);
  hint2.appendChild(document.createTextNode(" file to a safe location."));
  const br = document.createElement("br");
  hint2.appendChild(br);
  hint2.appendChild(document.createTextNode("To import: replace the "));
  const code2b = document.createElement("code");
  code2b.textContent = ".auth";
  hint2.appendChild(code2b);
  hint2.appendChild(document.createTextNode(" file and restart."));
  section.appendChild(hint2);

  return section;
}

/** Build the About section. */
function buildAboutSection(appName, appVersion) {
  const section = document.createElement("div");
  section.className = "settings-section settings-about";

  const name = document.createElement("div");
  name.className = "about-name";
  name.textContent = appName;
  section.appendChild(name);

  const version = document.createElement("div");
  version.className = "about-version";
  version.id = "about-version-link";
  version.title = "View on GitHub";
  version.textContent = `v${appVersion}`;
  section.appendChild(version);

  return section;
}

/** Build the static Audit Log section shell (rows inserted on toggle). */
function buildAuditLogSection() {
  const section = createSection();
  const row = document.createElement("div");
  row.className = "settings-row";

  const label = document.createElement("span");
  label.className = "settings-row-label";
  label.textContent = "Audit Log";
  row.appendChild(label);

  const toggleBtn = createButton("Show", "small", "audit-log-toggle");
  row.appendChild(toggleBtn);
  section.appendChild(row);

  const container = document.createElement("div");
  container.className = "audit-log-container hidden";
  container.id = "audit-log-container";

  const status = document.createElement("div");
  status.className = "audit-log-status";
  status.id = "audit-log-status";
  status.textContent = "Loading...";
  container.appendChild(status);

  const wrap = document.createElement("div");
  wrap.className = "audit-log-table-wrap";

  const table = document.createElement("table");
  table.className = "audit-log-table";
  const thead = document.createElement("thead");
  const headerRow = document.createElement("tr");
  ["#", "Time", "Event", "Details"].forEach((text) => {
    const th = document.createElement("th");
    th.textContent = text;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  tbody.id = "audit-log-body";
  table.appendChild(tbody);

  wrap.appendChild(table);
  container.appendChild(wrap);
  section.appendChild(container);

  return { section, toggleBtn, container, tbody, status };
}

// ── Main entry point ──────────────────────────────────────

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

    // Clear previous content and rebuild with DOM
    settingsBody.innerHTML = "";
    settingsBody.appendChild(buildSettingsContent({
      hasPin,
      lockTimeoutSeconds,
      clipboardClearSeconds,
      appName,
      appVersion,
    }));

    // Wire up all event listeners
    wireEventListeners({
      hasPin,
      cfg,
      settingsBody,
      settingsOverlay,
      backupConfirmOverlay,
      backupPinInput,
      backupConfirmSubmit,
      backupConfirmCancel,
      backupConfirmError,
      invoke,
      toast,
      isLocked,
      onPinSet,
      onLockNow,
      onClipboardClearSecondsChanged,
      onLockTimeoutChanged,
      onFocusLossChanged,
    });    }).catch(() => {
    toast("Failed to load settings", true);
  });
}

// ── Settings content builder ──────────────────────────────

function buildSettingsContent({
  hasPin,
  lockTimeoutSeconds,
  clipboardClearSeconds,
  appName,
  appVersion,
}) {
  const fragment = document.createDocumentFragment();

  // PIN section(s)
  const pinSections = buildPinSection(hasPin);
  pinSections.forEach((s) => fragment.appendChild(s));

  // Backup section
  fragment.appendChild(buildBackupSection());

  // Auto-lock timeout row
  {
    const section = createSection();
    section.appendChild(createNumberRow("Auto-lock (seconds)", "lock-timeout", lockTimeoutSeconds, 0, 3600, 30));
    const hint = document.createElement("div");
    hint.className = "settings-row-hint";
    hint.textContent = "0 = disabled";
    section.appendChild(hint);
    fragment.appendChild(section);
  }

  // Lock on focus loss checkbox
  {
    const section = createSection();
    const row = document.createElement("div");
    row.className = "settings-row";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.id = "lock-on-focus-loss";
    row.appendChild(cb);
    const label = document.createElement("label");
    label.htmlFor = "lock-on-focus-loss";
    label.className = "settings-row-label";
    label.textContent = "Lock on focus loss";
    row.appendChild(label);
    section.appendChild(row);
    const hint = document.createElement("div");
    hint.className = "settings-row-hint";
    hint.textContent = "Auto-lock when the window loses focus";
    section.appendChild(hint);
    fragment.appendChild(section);
  }

  // Clipboard clear timeout row
  {
    const section = createSection();
    section.appendChild(createNumberRow("Auto-clear clipboard (seconds)", "clipboard-clear", clipboardClearSeconds, 0, 300, 5));
    const hint = document.createElement("div");
    hint.className = "settings-row-hint";
    hint.textContent = "0 = disabled";
    section.appendChild(hint);
    fragment.appendChild(section);
  }

  // Audit Log section
  const audit = buildAuditLogSection();
  fragment.appendChild(audit.section);

  // About section
  fragment.appendChild(buildAboutSection(appName, appVersion));

  return fragment;
}

// ── Event listeners ───────────────────────────────────────

function wireEventListeners({
  hasPin,
  cfg,
  settingsBody,
  settingsOverlay,
  backupConfirmOverlay,
  backupPinInput,
  backupConfirmSubmit,
  backupConfirmCancel,
  backupConfirmError,
  invoke,
  toast,
  isLocked,
  onPinSet,
  onLockNow,
  onClipboardClearSecondsChanged,
  onLockTimeoutChanged,
  onFocusLossChanged,
}) {
  // ── Audit log toggle ─────────────────────────────────────
  const auditToggle = document.getElementById("audit-log-toggle");
  const auditContainer = document.getElementById("audit-log-container");
  const auditBody = document.getElementById("audit-log-body");
  const auditStatus = document.getElementById("audit-log-status");
  let auditLoaded = false;

  if (auditToggle) {
    auditToggle.addEventListener("click", async () => {
      const isHidden = auditContainer.classList.contains("hidden");
      if (isHidden) {
        auditContainer.classList.remove("hidden");
        auditToggle.textContent = "Hide";
        if (!auditLoaded) {
          try {
            const entries = await invoke("get_audit_log");
            auditLoaded = true;
            if (!entries || entries.length === 0) {
              auditStatus.textContent = "No audit entries yet.";
              return;
            }
            auditStatus.textContent = `${entries.length} entries (verified on load)`;
            // Clear before rebuilding
            auditBody.innerHTML = "";
            entries.forEach((e) => {
              const dt = new Date(e.ts * 1000);
              const pad = (n) => String(n).padStart(2, "0");
              const dateStr = `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;

              const tr = document.createElement("tr");

              const tdSeq = document.createElement("td");
              tdSeq.className = "audit-seq";
              tdSeq.textContent = e.seq;
              tr.appendChild(tdSeq);

              const tdTs = document.createElement("td");
              tdTs.className = "audit-ts";
              tdTs.textContent = dateStr;
              tr.appendChild(tdTs);

              const tdCat = document.createElement("td");
              const spanCat = document.createElement("span");
              spanCat.className = `audit-cat audit-cat-${e.cat.replace(/[^a-z0-9]/g, "-")}`;
              spanCat.textContent = e.cat;
              tdCat.appendChild(spanCat);
              tr.appendChild(tdCat);

              const tdMsg = document.createElement("td");
              tdMsg.className = "audit-msg";
              tdMsg.textContent = e.msg;
              tr.appendChild(tdMsg);

              auditBody.appendChild(tr);
            });
          } catch (err) {
            auditStatus.textContent = "Failed to load audit log.";
            // Build error row with DOM APIs
            auditBody.innerHTML = "";
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 4;
            td.style.cssText = "color:var(--close-bg);text-align:center;padding:12px;";
            td.textContent = `Error: ${typeof err === "string" ? err : "Unknown error"}`;
            tr.appendChild(td);
            auditBody.appendChild(tr);
          }
        }
      } else {
        auditContainer.classList.add("hidden");
        auditToggle.textContent = "Show";
      }
    });
  }

  // ── PIN strength meter: live update on New PIN input ───────
  const pinNewInput = document.getElementById("pin-new");
  const strengthFill = document.getElementById("pin-strength-fill");
  const strengthLabel = document.getElementById("pin-strength-label");
  const strengthMeter = document.getElementById("pin-strength-meter");
  if (pinNewInput && strengthFill && strengthLabel && strengthMeter) {
    pinNewInput.addEventListener("input", () => {
      const pin = pinNewInput.value;
      const result = computePinStrength(pin);
      if (!pin) {
        strengthMeter.classList.add("hidden");
        return;
      }
      strengthMeter.classList.remove("hidden");
      // Remove previous level class and set the new one
      strengthFill.className = "pin-strength-fill";
      strengthFill.classList.add(`level-${result.level}`);
      strengthFill.style.width = `${result.score}%`;
      strengthLabel.textContent = `${result.label} (${result.score}/100)`;
    });
  }

  // ── Enter key on PIN inputs triggers the Set/Change button ──
  const pinError = document.getElementById("pin-error");
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

  // ── Auto-save on input change (debounced per field) ────────
  const saveTimers = {};
  async function saveField(field, value, callback) {
    if (saveTimers[field]) clearTimeout(saveTimers[field]);
    saveTimers[field] = setTimeout(async () => {
      try {
        const cfg = await invoke("load_config");
        cfg[field] = value;
        await invoke("save_config", { cfg });
        if (callback) callback(value);
      } catch {
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

  // ── Backup all keys ──────────────────────────────────────
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
      // Verify PIN before exporting (read-only check, no side effects)
      try {
        const valid = await invoke("verify_pin", { pin });
        if (!valid) {
          backupConfirmError.textContent = "Wrong PIN";
          backupConfirmError.classList.remove("hidden");
          return;
        }
      } catch (e) {
        backupConfirmError.textContent = typeof e === "string" ? e : "PIN verification failed";
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

  // ── Clickable version link ────────────────────────────────
  const versionLink = document.getElementById("about-version-link");
  if (versionLink) {
    versionLink.addEventListener("click", () => {
      window.open("https://github.com/kardelitaitu/oz-auth", "_blank");
    });
  }
}
