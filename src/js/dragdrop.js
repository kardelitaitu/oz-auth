//! Drag & drop account reordering using pointer events (reliable in Tauri WebView2).

/**
 * Attach drag & drop handlers to all account cards inside `container`.
 * Uses pointer events instead of HTML5 Drag API for cross-platform reliability.
 * `onReorder(srcId, targetId)` is called when the user drops a card onto another card.
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

  function onPointerDown(e) {
    // Left button only, skip if clicking on code (copy click)
    if (e.button !== 0) return;
    if (e.target.closest(".card-code") || e.target.closest(".card-ring")) return;

    const card = e.target.closest(".account-card");
    if (!card) return;

    dragState = {
      srcId: card.dataset.id,
      srcCard: card,
      startX: e.clientX,
      startY: e.clientY,
      moved: false,
    };

    // Capture pointer for reliable tracking
    card.setPointerCapture(e.pointerId);
    card.addEventListener("pointermove", onPointerMove);
    card.addEventListener("pointerup", onPointerUp);
    card.addEventListener("pointercancel", onPointerCancel);
  }

  function onPointerMove(e) {
    if (!dragState) return;

    const dx = e.clientX - dragState.startX;
    const dy = e.clientY - dragState.startY;

    // Require 4px movement to initiate drag (avoids false triggers on click)
    if (!dragState.moved && Math.abs(dx) + Math.abs(dy) < 4) return;

    if (!dragState.moved) {
      dragState.moved = true;
      dragState.srcCard.classList.add("dragging");
      e.preventDefault();
    }

    // Temporarily hide the source card so elementFromPoint finds the card beneath
    dragState.srcCard.style.pointerEvents = "none";
    const cardBelow = getCardFromPoint(e.clientX, e.clientY);
    dragState.srcCard.style.pointerEvents = "";

    // Update drag-over indicator
    clearDragOver();
    if (cardBelow && cardBelow.dataset.id !== dragState.srcId) {
      cardBelow.classList.add("drag-over");
    }
  }

  function onPointerUp(e) {
    if (!dragState) return;

    dragState.srcCard.removeEventListener("pointermove", onPointerMove);
    dragState.srcCard.removeEventListener("pointerup", onPointerUp);
    dragState.srcCard.removeEventListener("pointercancel", onPointerCancel);

    if (dragState.moved) {
      dragState.srcCard.classList.remove("dragging");

      // Find target card using elementFromPoint
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

  function onPointerCancel() {
    if (!dragState) return;

    dragState.srcCard.removeEventListener("pointermove", onPointerMove);
    dragState.srcCard.removeEventListener("pointerup", onPointerUp);
    dragState.srcCard.removeEventListener("pointercancel", onPointerCancel);

    dragState.srcCard.classList.remove("dragging");
    clearDragOver();
    dragState = null;
  }

  // Delegated pointerdown on container (works for dynamically created cards)
  container.addEventListener("pointerdown", onPointerDown);
}
