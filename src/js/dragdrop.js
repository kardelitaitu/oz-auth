//! Drag & drop account reordering using mouse events on a dedicated handle.
//! Only triggers when the user grabs the ≡ handle on the left of each card.
//! Uses mousedown/mousemove/mouseup (not pointer events) for WebView2 reliability.

/**
 * Attach drag & drop handlers to all account cards inside `container`.
 * Drag is only initiated from the `.card-drag-handle` element.
 * `onReorder(srcId, targetId)` is called when the user drops a card onto another.
 */
export function setupDragDrop(container, accountListEl, onReorder) {
  let dragState = null;

  function getCardFromPoint(x, y) {
    const el = document.elementFromPoint(x, y);
    return el ? el.closest(".account-card") : null;
  }

  function clearDragOver() {
    accountListEl.querySelectorAll(".drag-over").forEach((c) => c.classList.remove("drag-over"));
  }

  function onMouseDown(e) {
    // Left button only
    if (e.button !== 0) return;
    // Only start drag from the handle
    const handle = e.target.closest(".card-drag-handle");
    if (!handle) return;

    const card = handle.closest(".account-card");
    if (!card) return;

    e.preventDefault(); // prevent text selection

    dragState = {
      srcId: card.dataset.id,
      srcCard: card,
      startX: e.clientX,
      startY: e.clientY,
      moved: false,
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    window.addEventListener("blur", cancelDrag);
  }

  function onMouseMove(e) {
    if (!dragState) return;

    const dx = e.clientX - dragState.startX;
    const dy = e.clientY - dragState.startY;

    // Require 4px movement to initiate drag
    if (!dragState.moved && Math.abs(dx) + Math.abs(dy) < 4) return;

    if (!dragState.moved) {
      dragState.moved = true;
      dragState.srcCard.classList.add("dragging");
    }

    // Hide source card so elementFromPoint finds the card beneath
    dragState.srcCard.style.pointerEvents = "none";
    const cardBelow = getCardFromPoint(e.clientX, e.clientY);
    dragState.srcCard.style.pointerEvents = "";

    // Update drag-over indicator
    clearDragOver();
    if (cardBelow && cardBelow.dataset.id !== dragState.srcId) {
      cardBelow.classList.add("drag-over");
    }
  }

  function cancelDrag() {
    if (!dragState) return;
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
    window.removeEventListener("blur", cancelDrag);
    dragState.srcCard.classList.remove("dragging");
    clearDragOver();
    dragState = null;
  }

  function onMouseUp(e) {
    if (!dragState) return;

    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
    window.removeEventListener("blur", cancelDrag);

    if (dragState.moved) {
      dragState.srcCard.classList.remove("dragging");

      // Find target card
      dragState.srcCard.style.pointerEvents = "none";
      const cardBelow = getCardFromPoint(e.clientX, e.clientY);
      dragState.srcCard.style.pointerEvents = "";

      clearDragOver();

      if (cardBelow) {
        const targetId = cardBelow.dataset.id;
        if (dragState.srcId !== targetId) {
          onReorder(dragState.srcId, targetId);
        }
      }
    }

    dragState = null;
  }

  // Delegated mousedown on container — only triggers via .card-drag-handle
  container.addEventListener("mousedown", onMouseDown);
}
