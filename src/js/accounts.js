//! Account list rendering, HTML escaping, and add/edit dialog management.

/**
 * Escape HTML entities to prevent XSS.
 * Uses manual replacement to avoid creating + reading DOM nodes.
 */
export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Render account cards into the account list container.
 * `callbacks` must provide: onCopy, onEdit, onDelete, onContextMenu
 * Drag & drop handlers are attached by the caller via setupDragDrop.
 * All content built with DOM APIs (no innerHTML) to prevent XSS.
 */
export function renderAccounts(accounts, accountListEl, callbacks) {
  const { onCopy, onContextMenu } = callbacks;
  accountListEl.innerHTML = "";

  if (accounts.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.appendChild(document.createTextNode("No accounts yet."));
    empty.appendChild(document.createElement("br"));
    empty.appendChild(document.createTextNode("Click + to add one."));
    accountListEl.appendChild(empty);
    return;
  }

  const SVG_NS = "http://www.w3.org/2000/svg";

  accounts.forEach((a) => {
    const card = document.createElement("div");
    card.className = "account-card";
    card.dataset.id = a.id;

    // ── Drag handle ────────────────────────────────────────
    const dragHandle = document.createElement("div");
    dragHandle.className = "card-drag-handle";
    dragHandle.title = "Drag to reorder";
    for (let i = 0; i < 3; i++) {
      dragHandle.appendChild(document.createElement("span"));
    }
    card.appendChild(dragHandle);

    // ── Main row ───────────────────────────────────────────
    const mainRow = document.createElement("div");
    mainRow.className = "card-main-row";

    // Column 1: issuer + label
    const col1 = document.createElement("div");
    col1.className = "card-col-1";

    const issuerSpan = document.createElement("span");
    issuerSpan.className = "card-issuer";
    issuerSpan.textContent = a.issuer;
    col1.appendChild(issuerSpan);

    const labelSpan = document.createElement("span");
    labelSpan.className = "card-label";
    labelSpan.textContent = a.label;
    col1.appendChild(labelSpan);

    mainRow.appendChild(col1);

    // Column 2: TOTP code
    const col2 = document.createElement("div");
    col2.className = "card-col-2";

    const codeSpan = document.createElement("span");
    codeSpan.className = "card-code";
    codeSpan.dataset.id = a.id;
    codeSpan.textContent = "------";
    codeSpan.addEventListener("click", () => onCopy(a.id));
    col2.appendChild(codeSpan);

    mainRow.appendChild(col2);

    // Column 3: SVG countdown ring
    const col3 = document.createElement("div");
    col3.className = "card-col-3";

    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "card-ring");
    svg.setAttribute("viewBox", "0 0 44 44");
    svg.setAttribute("width", "44");
    svg.setAttribute("height", "44");
    svg.dataset.id = a.id;

    const bgCircle = document.createElementNS(SVG_NS, "circle");
    bgCircle.setAttribute("cx", "22");
    bgCircle.setAttribute("cy", "22");
    bgCircle.setAttribute("r", "19");
    bgCircle.setAttribute("fill", "none");
    bgCircle.setAttribute("class", "ring-bg");
    svg.appendChild(bgCircle);

    const fgCircle = document.createElementNS(SVG_NS, "circle");
    fgCircle.setAttribute("cx", "22");
    fgCircle.setAttribute("cy", "22");
    fgCircle.setAttribute("r", "19");
    fgCircle.setAttribute("fill", "none");
    fgCircle.setAttribute("class", "ring-fg");
    fgCircle.dataset.id = a.id;
    fgCircle.setAttribute("stroke-dasharray", "119.381");
    fgCircle.setAttribute("stroke-dashoffset", "119.381");
    fgCircle.setAttribute("transform", "rotate(-90 22 22)");
    svg.appendChild(fgCircle);

    const ringText = document.createElementNS(SVG_NS, "text");
    ringText.setAttribute("x", "22");
    ringText.setAttribute("y", "22");
    ringText.dataset.id = a.id;
    ringText.setAttribute("class", "ring-text");
    ringText.textContent = "--";
    svg.appendChild(ringText);

    col3.appendChild(svg);
    mainRow.appendChild(col3);

    card.appendChild(mainRow);

    // Right-click context menu
    card.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      onContextMenu(e.clientX, e.clientY, a.id);
    });

    accountListEl.appendChild(card);
  });
}

/**
 * Set up the Add/Edit Account dialog.
 * Returns { openAdd, openEdit, getEditId }.
 */
export function setupAccountDialog(config) {
  const {
    invoke,
    dialog,
    dialogTitle,
    dialogIssuer,
    dialogLabel,
    dialogSecret,
    dialogAlgorithm,
    dialogDigits,
    dialogPeriod,
    dialogSubmit,
    dialogCancel,
    btnAdd,
    toast,
    getAccounts,
    isLocked,
    onAccountsChanged,
  } = config;

  let editId = null;

  function openEditDialog(id) {
    if (isLocked()) {
      toast("App is locked", true);
      return;
    }
    const accounts = getAccounts();
    const account = accounts.find((a) => a.id === id);
    if (!account) return;
    editId = id;
    dialogTitle.textContent = "Edit Account";
    dialogIssuer.value = account.issuer;
    dialogLabel.value = account.label;
    dialogSecret.value = "";
    dialogSecret.style.display = "none";
    dialogAlgorithm.parentElement.style.display = "none";
    dialogDigits.parentElement.style.display = "none";
    dialogPeriod.parentElement.style.display = "none";
    dialogSubmit.textContent = "Save";
    dialog.classList.remove("hidden");
    dialogIssuer.focus();
  }

  function openAddDialog() {
    if (isLocked()) {
      toast("App is locked", true);
      return;
    }
    editId = null;
    dialogTitle.textContent = "Add Account";
    dialogIssuer.value = "";
    dialogLabel.value = "";
    dialogSecret.value = "";
    dialogSecret.placeholder = "Secret key";
    dialogSecret.style.display = "";
    dialogAlgorithm.parentElement.style.display = "";
    dialogDigits.parentElement.style.display = "";
    dialogPeriod.parentElement.style.display = "";
    dialogAlgorithm.value = "SHA1";
    dialogDigits.value = "6";
    dialogPeriod.value = "30";
    dialogSubmit.textContent = "Add";
    dialog.classList.remove("hidden");
    dialogIssuer.focus();
  }

  btnAdd.addEventListener("click", openAddDialog);

  dialogCancel.addEventListener("click", () => {
    dialog.classList.add("hidden");
  });

  // Enter key submits the dialog (skip on select dropdowns)
  dialog.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !dialog.classList.contains("hidden")) {
      if (e.target.tagName === "SELECT") return;
      e.preventDefault();
      dialogSubmit.click();
    }
  });

  dialogSubmit.addEventListener("click", async () => {
    if (isLocked()) {
      toast("App is locked", true);
      return;
    }
    const issuer = dialogIssuer.value.trim();
    const label = dialogLabel.value.trim();
    const secret = dialogSecret.value.trim();

    if (editId) {
      if (!issuer || !label) {
        toast("Issuer and label are required", true);
        return;
      }
      try {
        await invoke("update_account", {
          accountId: editId,
          issuer: issuer || null,
          label: label || null,
          sortOrder: null,
        });
        toast("Account updated");
        editId = null;
        dialog.classList.add("hidden");
        await onAccountsChanged();
      } catch (e) {
        toast(typeof e === "string" ? e : "Failed to update account", true);
      }
    } else {
      if (!issuer || !label || !secret) {
        toast("All fields required", true);
        return;
      }
      try {
        await invoke("add_account", {
          issuer,
          label,
          secret,
          algorithm: dialogAlgorithm.value,
          digits: parseInt(dialogDigits.value),
          period: parseInt(dialogPeriod.value),
        });
        toast("Account added");
        dialog.classList.add("hidden");
        await onAccountsChanged();
      } catch (e) {
        toast(typeof e === "string" ? e : "Failed to add account", true);
      }
    }
  });

  return { openAdd: openAddDialog, openEdit: openEditDialog, getEditId: () => editId };
}
