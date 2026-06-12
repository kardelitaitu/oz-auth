//! Account list rendering, HTML escaping, and add/edit dialog management.

/**
 * Escape HTML entities to prevent XSS.
 */
export function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

/**
 * Render account cards into the account list container.
 * `callbacks` must provide: onCopy, onEdit, onDelete, onContextMenu
 * Drag & drop handlers are attached by the caller via setupDragDrop.
 */
export function renderAccounts(accounts, accountListEl, callbacks) {
  const { onCopy, onEdit, onDelete, onContextMenu } = callbacks;
  accountListEl.innerHTML = "";

  if (accounts.length === 0) {
    accountListEl.innerHTML = '<div class="empty-state">No accounts yet.<br>Click + to add one.</div>';
    return;
  }

  accounts.forEach((a) => {
    const card = document.createElement("div");
    card.className = "account-card";
    card.dataset.id = a.id;
    card.draggable = true;
    card.innerHTML = `
      <div class="card-row1">
        <span class="card-issuer">${escapeHtml(a.issuer)}</span>
        <div class="card-row1-right" draggable="false">
          <span class="card-code" data-id="${a.id}">------</span>
          <svg class="card-ring" viewBox="0 0 24 24" width="24" height="24" data-id="${a.id}">
            <circle cx="12" cy="12" r="9" fill="none" class="ring-bg"/>
            <circle cx="12" cy="12" r="9" fill="none" class="ring-fg"
              data-id="${a.id}"
              stroke-dasharray="56.549" stroke-dashoffset="56.549"
              transform="rotate(-90 12 12)"/>
            <text x="12" y="12" data-id="${a.id}" class="ring-text">--</text>
          </svg>
          <button class="card-edit" title="Edit" data-id="${a.id}" draggable="false">✎</button>
          <button class="card-delete" title="Delete" draggable="false">×</button>
        </div>
      </div>
      <div class="card-row2">
        <span class="card-label">${escapeHtml(a.label)}</span>
        <span class="card-timer" data-id="${a.id}">--s</span>
      </div>
    `;

    // Click to copy
    card.querySelector(".card-code").addEventListener("click", () => onCopy(a.id));
    // Edit button
    card.querySelector(".card-edit").addEventListener("click", (e) => {
      e.stopPropagation();
      onEdit(a.id);
    });
    // Delete button
    card.querySelector(".card-delete").addEventListener("click", (e) => {
      e.stopPropagation();
      onDelete(a.id);
    });
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
    onAccountsChanged,
  } = config;

  let editId = null;

  function openEditDialog(id) {
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
