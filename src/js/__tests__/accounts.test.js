//! Integration tests for the accounts module using Tauri mock IPC.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { escapeHtml, renderAccounts, setupAccountDialog } from "../accounts.js";
import { ensureSettingsDom } from "./setup.js";

beforeEach(() => {
  document.body.innerHTML = "";
  ensureSettingsDom();
});

// ── escapeHtml ─────────────────────────────────────────────

describe("escapeHtml", () => {
  it("escapes & < > \" '", () => {
    expect(escapeHtml('&<>"\'')).toBe("&amp;&lt;&gt;&quot;&#39;");
  });

  it("returns empty string for empty input", () => {
    expect(escapeHtml("")).toBe("");
  });

  it("passes through safe strings", () => {
    expect(escapeHtml("Hello World 123")).toBe("Hello World 123");
  });

  it("converts non-string input to string", () => {
    expect(escapeHtml(42)).toBe("42");
    expect(escapeHtml(null)).toBe("null");
    expect(escapeHtml(undefined)).toBe("undefined");
  });
});

// ── renderAccounts ─────────────────────────────────────────

describe("renderAccounts", () => {
  it("renders empty state when no accounts", () => {
    const list = document.getElementById("account-list");
    renderAccounts([], list, { onCopy: vi.fn(), onContextMenu: vi.fn() });
    expect(list.textContent).toContain("No accounts yet");
    expect(list.querySelectorAll(".account-card").length).toBe(0);
  });

  it("renders account cards for each account", () => {
    const accounts = [
      { id: "1", issuer: "Google", label: "user@gmail.com" },
      { id: "2", issuer: "GitHub", label: "user@github.com" },
    ];
    const list = document.getElementById("account-list");
    renderAccounts(accounts, list, { onCopy: vi.fn(), onContextMenu: vi.fn() });

    const cards = list.querySelectorAll(".account-card");
    expect(cards.length).toBe(2);

    expect(cards[0].querySelector(".card-issuer").textContent).toBe("Google");
    expect(cards[0].querySelector(".card-label").textContent).toBe("user@gmail.com");
    expect(cards[1].querySelector(".card-issuer").textContent).toBe("GitHub");
  });

  it("sets data-id on each card", () => {
    const accounts = [{ id: "abc-123", issuer: "X", label: "Y" }];
    const list = document.getElementById("account-list");
    renderAccounts(accounts, list, { onCopy: vi.fn(), onContextMenu: vi.fn() });

    const card = list.querySelector(".account-card");
    expect(card.dataset.id).toBe("abc-123");
  });

  it("escapes HTML in issuer and label", () => {
    const accounts = [{ id: "1", issuer: "<script>alert('xss')</script>", label: '"quoted"' }];
    const list = document.getElementById("account-list");
    renderAccounts(accounts, list, { onCopy: vi.fn(), onContextMenu: vi.fn() });

    const card = list.querySelector(".account-card");
    // The script tag must be escaped in the HTML source
    // textContent renders the literal string safely — script tag IS present in text
    // but was never parsed as HTML (proven by no XSS execution)
    expect(card.textContent).toContain("<script>alert('xss')</script>");
    // The label value should be rendered as text (not as executable HTML)
    expect(card.textContent).toContain('"quoted"');
    expect(card.textContent).toContain("alert('xss')");
  });

  it("calls onCopy when code is clicked", () => {
    const onCopy = vi.fn();
    const accounts = [{ id: "42", issuer: "Test", label: "test" }];
    const list = document.getElementById("account-list");
    renderAccounts(accounts, list, { onCopy, onContextMenu: vi.fn() });

    const codeEl = list.querySelector(".card-code");
    codeEl.click();
    expect(onCopy).toHaveBeenCalledWith("42");
  });

  it("calls onContextMenu on right-click", () => {
    const onContextMenu = vi.fn();
    const accounts = [{ id: "7", issuer: "Test", label: "test" }];
    const list = document.getElementById("account-list");
    renderAccounts(accounts, list, { onCopy: vi.fn(), onContextMenu });

    const card = list.querySelector(".account-card");
    const event = new MouseEvent("contextmenu", { clientX: 100, clientY: 200, bubbles: true });
    // preventDefault to avoid browser context menu
    event.preventDefault = vi.fn();
    card.dispatchEvent(event);

    expect(onContextMenu).toHaveBeenCalledWith(100, 200, "7");
    expect(event.preventDefault).toHaveBeenCalled();
  });
});

// ── setupAccountDialog ─────────────────────────────────────

describe("setupAccountDialog", () => {
  function createDialogConfig(overrides = {}) {
    return {
      invoke: vi.fn(),
      dialog: document.getElementById("account-dialog"),
      dialogTitle: document.getElementById("dialog-title"),
      dialogIssuer: document.getElementById("dialog-issuer"),
      dialogLabel: document.getElementById("dialog-label"),
      dialogSecret: document.getElementById("dialog-secret"),
      dialogAlgorithm: document.getElementById("dialog-algorithm"),
      dialogDigits: document.getElementById("dialog-digits"),
      dialogPeriod: document.getElementById("dialog-period"),
      dialogSubmit: document.getElementById("dialog-submit"),
      dialogCancel: document.getElementById("dialog-cancel"),
      btnAdd: document.createElement("button"),
      toast: vi.fn(),
      getAccounts: () => [],
      isLocked: () => false,
      onAccountsChanged: vi.fn(),
      ...overrides,
    };
  }

  it("returns openAdd, openEdit, getEditId methods", () => {
    const cfg = createDialogConfig();
    const api = setupAccountDialog(cfg);
    expect(api).toHaveProperty("openAdd");
    expect(api).toHaveProperty("openEdit");
    expect(api).toHaveProperty("getEditId");
  });

  it("openAdd clears fields and shows dialog", () => {
    const cfg = createDialogConfig();
    const api = setupAccountDialog(cfg);

    cfg.dialogIssuer.value = "old";
    cfg.dialogSecret.style.display = "none";

    api.openAdd();

    expect(cfg.dialogTitle.textContent).toBe("Add Account");
    expect(cfg.dialogIssuer.value).toBe("");
    expect(cfg.dialogLabel.value).toBe("");
    expect(cfg.dialogSecret.style.display).not.toBe("none");
    expect(cfg.dialog.classList.contains("hidden")).toBe(false);
  });

  it("openEdit populates fields and hides secret/alg/digits/period for editing", () => {
    const accounts = [{ id: "e1", issuer: "EditCo", label: "edit@co.com" }];
    const cfg = createDialogConfig({ getAccounts: () => accounts });
    const api = setupAccountDialog(cfg);

    api.openEdit("e1");

    expect(cfg.dialogTitle.textContent).toBe("Edit Account");
    expect(cfg.dialogIssuer.value).toBe("EditCo");
    expect(cfg.dialogLabel.value).toBe("edit@co.com");
    expect(cfg.dialogSecret.value).toBe("");
    expect(cfg.dialogSecret.style.display).toBe("none");
    expect(cfg.dialogSubmit.textContent).toBe("Save");
  });

  it("openEdit returns early if account not found", () => {
    const cfg = createDialogConfig({ getAccounts: () => [{ id: "x", issuer: "X", label: "Y" }] });
    const api = setupAccountDialog(cfg);

    cfg.dialog.classList.add("hidden");
    api.openEdit("nonexistent");
    // Dialog should remain hidden
    expect(cfg.dialog.classList.contains("hidden")).toBe(true);
  });

  it("submit with editId calls invoke('update_account') and onAccountsChanged", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    const onAccountsChanged = vi.fn();
    const accounts = [{ id: "e1", issuer: "Old", label: "old" }];
    const cfg = createDialogConfig({ invoke, getAccounts: () => accounts, onAccountsChanged });
    const api = setupAccountDialog(cfg);

    api.openEdit("e1");
    cfg.dialogIssuer.value = "Updated";
    cfg.dialogLabel.value = "updated@co.com";
    cfg.dialogSubmit.click();

    // Wait for async handler
    await new Promise(process.nextTick);

    expect(invoke).toHaveBeenCalledWith("update_account", {
      accountId: "e1",
      issuer: "Updated",
      label: "updated@co.com",
      sortOrder: null,
    });
    expect(onAccountsChanged).toHaveBeenCalled();
  });

  it("submit with no editId calls invoke('add_account') with all fields", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    const onAccountsChanged = vi.fn();
    const cfg = createDialogConfig({ invoke, onAccountsChanged });
    const api = setupAccountDialog(cfg);

    api.openAdd();
    cfg.dialogIssuer.value = "NewCo";
    cfg.dialogLabel.value = "new@co.com";
    cfg.dialogSecret.value = "JBSWY3DPEHPK3PXP";
    cfg.dialogAlgorithm.value = "SHA256";
    cfg.dialogDigits.value = "8";
    cfg.dialogPeriod.value = "60";
    cfg.dialogSubmit.click();

    await new Promise(process.nextTick);

    expect(invoke).toHaveBeenCalledWith("add_account", {
      issuer: "NewCo",
      label: "new@co.com",
      secret: "JBSWY3DPEHPK3PXP",
      algorithm: "SHA256",
      digits: 8,
      period: 60,
    });
    expect(onAccountsChanged).toHaveBeenCalled();
  });

  it("submit validates required fields in add mode", async () => {
    const toast = vi.fn();
    const cfg = createDialogConfig({ toast });
    const api = setupAccountDialog(cfg);

    api.openAdd();
    // Leave fields empty
    cfg.dialogSubmit.click();

    await new Promise(process.nextTick);
    expect(toast).toHaveBeenCalledWith("All fields required", true);
  });

  it("submit validates required fields in edit mode", async () => {
    const toast = vi.fn();
    const accounts = [{ id: "e1", issuer: "X", label: "Y" }];
    const cfg = createDialogConfig({ toast, getAccounts: () => accounts });
    const api = setupAccountDialog(cfg);

    api.openEdit("e1");
    cfg.dialogIssuer.value = "";
    cfg.dialogLabel.value = "";
    cfg.dialogSubmit.click();

    await new Promise(process.nextTick);
    expect(toast).toHaveBeenCalledWith("Issuer and label are required", true);
  });

  it("does not submit if app is locked", async () => {
    const toast = vi.fn();
    const invoke = vi.fn();
    const cfg = createDialogConfig({ toast, invoke, isLocked: () => true });
    const api = setupAccountDialog(cfg);

    api.openAdd();
    cfg.dialogIssuer.value = "X";
    cfg.dialogLabel.value = "Y";
    cfg.dialogSecret.value = "SECRET";
    cfg.dialogSubmit.click();

    await new Promise(process.nextTick);
    expect(toast).toHaveBeenCalledWith("App is locked", true);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("cancel closes the dialog", () => {
    const cfg = createDialogConfig();
    setupAccountDialog(cfg);

    cfg.dialog.classList.remove("hidden");
    cfg.dialogCancel.click();
    expect(cfg.dialog.classList.contains("hidden")).toBe(true);
  });

  it("openAdd respects locked-state guard", () => {
    const toast = vi.fn();
    const cfg = createDialogConfig({ toast, isLocked: () => true });
    const api = setupAccountDialog(cfg);

    cfg.dialog.classList.add("hidden");
    api.openAdd();

    expect(toast).toHaveBeenCalledWith("App is locked", true);
    expect(cfg.dialog.classList.contains("hidden")).toBe(true);
  });

  it("openEdit respects locked-state guard", () => {
    const toast = vi.fn();
    const cfg = createDialogConfig({ toast, isLocked: () => true, getAccounts: () => [{ id: "e1", issuer: "X", label: "Y" }] });
    const api = setupAccountDialog(cfg);

    cfg.dialog.classList.add("hidden");
    api.openEdit("e1");

    expect(toast).toHaveBeenCalledWith("App is locked", true);
    expect(cfg.dialog.classList.contains("hidden")).toBe(true);
  });

  it("Enter key triggers dialog submit", () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    const cfg = createDialogConfig({ invoke });
    const api = setupAccountDialog(cfg);

    api.openAdd();
    cfg.dialogIssuer.value = "EnterCo";
    cfg.dialogLabel.value = "enter@co.com";
    cfg.dialogSecret.value = "SECRET";

    const clickSpy = vi.spyOn(cfg.dialogSubmit, "click");
    const event = new KeyboardEvent("keydown", { key: "Enter", bubbles: true });
    cfg.dialog.dispatchEvent(event);

    expect(clickSpy).toHaveBeenCalled();
  });

  it("Enter key does not submit when dialog is hidden", () => {
    const cfg = createDialogConfig();
    setupAccountDialog(cfg);

    cfg.dialog.classList.add("hidden");
    const clickSpy = vi.spyOn(cfg.dialogSubmit, "click");
    const event = new KeyboardEvent("keydown", { key: "Enter", bubbles: true });
    cfg.dialog.dispatchEvent(event);

    expect(clickSpy).not.toHaveBeenCalled();
  });
});
