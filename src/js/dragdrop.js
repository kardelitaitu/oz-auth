//! Drag & drop account reordering.

/**
 * Attach drag & drop handlers to all account cards inside `container`.
 * `onReorder(srcId, targetId)` is called when the user drops a card
 * onto another card.
 */
export function setupDragDrop(container, accountListEl, onReorder) {
  let dragSrcId = null;

  function handleDragStart(e) {
    dragSrcId = this.dataset.id;
    this.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", dragSrcId);
  }

  function handleDragEnd() {
    this.classList.remove("dragging");
    accountListEl.querySelectorAll(".drag-over").forEach((c) => c.classList.remove("drag-over"));
    dragSrcId = null;
  }

  function handleDragOver(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    const card = e.target.closest(".account-card");
    if (card && card.dataset.id !== dragSrcId) {
      card.classList.add("drag-over");
    }
  }

  function handleDragLeave(e) {
    const card = e.target.closest(".account-card");
    if (card) card.classList.remove("drag-over");
  }

  function handleDrop(e) {
    e.preventDefault();
    const card = e.target.closest(".account-card");
    if (!card) return;
    card.classList.remove("drag-over");
    const targetId = card.dataset.id;
    if (dragSrcId && targetId && dragSrcId !== targetId) {
      onReorder(dragSrcId, targetId);
    }
  }

  // Event delegation on the container
  container.addEventListener("dragstart", (e) => {
    const card = e.target.closest(".account-card");
    if (card) {
      dragSrcId = card.dataset.id;
      card.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", dragSrcId);
    }
  });

  container.addEventListener("dragend", (e) => {
    const card = e.target.closest(".account-card");
    if (card) card.classList.remove("dragging");
    accountListEl.querySelectorAll(".drag-over").forEach((c) => c.classList.remove("drag-over"));
    dragSrcId = null;
  });

  container.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    const card = e.target.closest(".account-card");
    if (card && card.dataset.id !== dragSrcId) {
      card.classList.add("drag-over");
    }
  });

  container.addEventListener("dragleave", (e) => {
    const card = e.target.closest(".account-card");
    if (card) card.classList.remove("drag-over");
  });

  container.addEventListener("drop", (e) => {
    e.preventDefault();
    const card = e.target.closest(".account-card");
    if (!card) return;
    card.classList.remove("drag-over");
    const targetId = card.dataset.id;
    if (dragSrcId && targetId && dragSrcId !== targetId) {
      onReorder(dragSrcId, targetId);
    }
  });
}
