//! Integration tests for the drag & drop module.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { setupDragDrop } from "../dragdrop.js";

beforeEach(() => {
  document.body.innerHTML = "";
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("setupDragDrop", () => {
  function createCards(ids) {
    return ids
      .map(
        (id) => `
      <div class="account-card" data-id="${id}">
        <div class="card-drag-handle">
          <span></span><span></span><span></span>
        </div>
        <span class="card-issuer">${id}</span>
      </div>`
      )
      .join("");
  }

  it("attaches mousedown listener to container", () => {
    const container = document.createElement("div");
    const listenerSpy = vi.spyOn(container, "addEventListener");

    setupDragDrop(container, container, vi.fn());

    expect(listenerSpy).toHaveBeenCalledWith("mousedown", expect.any(Function));
  });

  it("does not initiate drag from outside the handle", () => {
    const container = document.createElement("div");
    container.innerHTML = createCards(["a1", "a2"]);
    document.body.appendChild(container);

    const onReorder = vi.fn();
    setupDragDrop(container, container, onReorder);

    // Click on the card body (not handle)
    const card = container.querySelector(".account-card");
    card.dispatchEvent(new MouseEvent("mousedown", { button: 0, bubbles: true }));

    // No drag state should be active — simulate mouse move
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 10, clientY: 10 }));
    document.dispatchEvent(new MouseEvent("mouseup"));

    expect(onReorder).not.toHaveBeenCalled();
  });

  it("initiates drag from the handle after 4px movement", () => {
    const container = document.createElement("div");
    container.innerHTML = createCards(["a1", "a2"]);
    document.body.appendChild(container);

    const onReorder = vi.fn();
    setupDragDrop(container, container, onReorder);

    const handle = container.querySelector(".card-drag-handle");

    // Mousedown on handle
    handle.dispatchEvent(new MouseEvent("mousedown", { button: 0, bubbles: true }));

    // Move 4px (threshold)
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 4, clientY: 0 }));

    // The source card should have "dragging" class
    const srcCard = container.querySelector('[data-id="a1"]');
    expect(srcCard.classList.contains("dragging")).toBe(true);
  });

  it("does not initiate drag before 4px threshold", () => {
    const container = document.createElement("div");
    container.innerHTML = createCards(["a1", "a2"]);
    document.body.appendChild(container);

    setupDragDrop(container, container, vi.fn());

    const handle = container.querySelector(".card-drag-handle");

    handle.dispatchEvent(new MouseEvent("mousedown", { button: 0, bubbles: true }));
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 3, clientY: 0 }));

    const srcCard = container.querySelector('[data-id="a1"]');
    expect(srcCard.classList.contains("dragging")).toBe(false);
  });

  it("does not initiate drag on right-click (button !== 0)", () => {
    const container = document.createElement("div");
    container.innerHTML = createCards(["a1", "a2"]);
    document.body.appendChild(container);

    setupDragDrop(container, container, vi.fn());

    const handle = container.querySelector(".card-drag-handle");

    handle.dispatchEvent(new MouseEvent("mousedown", { button: 2, bubbles: true }));
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 10, clientY: 0 }));

    const srcCard = container.querySelector('[data-id="a1"]');
    expect(srcCard.classList.contains("dragging")).toBe(false);
  });

  it("calls onReorder on drop over another card", () => {
    const container = document.createElement("div");
    container.innerHTML = createCards(["a1", "a2"]);
    document.body.appendChild(container);

    const onReorder = vi.fn();
    setupDragDrop(container, container, onReorder);

    const handle = container.querySelector(".card-drag-handle");

    // Start drag on a1
    handle.dispatchEvent(new MouseEvent("mousedown", { button: 0, bubbles: true, clientX: 0, clientY: 0 }));
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 4, clientY: 0 }));

    // elementFromPoint needs to return the target card
    const cardA2 = container.querySelector('[data-id="a2"]');
    vi.spyOn(document, "elementFromPoint").mockReturnValue(cardA2);

    // Drop on a2
    document.dispatchEvent(new MouseEvent("mouseup", { clientX: 10, clientY: 10, bubbles: true }));

    expect(onReorder).toHaveBeenCalledWith("a1", "a2");
  });

  it("cleans up drag state on window blur", () => {
    const container = document.createElement("div");
    container.innerHTML = createCards(["a1", "a2"]);
    document.body.appendChild(container);

    const onReorder = vi.fn();
    setupDragDrop(container, container, onReorder);

    const handle = container.querySelector(".card-drag-handle");
    handle.dispatchEvent(new MouseEvent("mousedown", { button: 0, bubbles: true }));
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 10, clientY: 10 }));

    const srcCard = container.querySelector('[data-id="a1"]');
    expect(srcCard.classList.contains("dragging")).toBe(true);

    // Window blur should cancel drag
    window.dispatchEvent(new Event("blur"));

    expect(srcCard.classList.contains("dragging")).toBe(false);
    expect(srcCard.classList.contains("drag-over")).toBe(false);
  });
});
