document.addEventListener("DOMContentLoaded", () => {
  const feedRoot = document.querySelector("[data-feed-controls]");
  if (!feedRoot) {
    return;
  }

  const unitsInput = feedRoot.querySelector("[data-feed-units]");
  const runButton = feedRoot.querySelector("[data-feed-run]");
  const outputBox = document.querySelector("[data-feed-output]");

  const append = (line) => {
    if (!outputBox) {
      return;
    }
    outputBox.textContent = `${line}\n${outputBox.textContent}`.trim();
  };

  runButton.addEventListener("click", async () => {
    const units = Number(unitsInput.value || "120000");
    runButton.disabled = true;
    append(`Request started: /api/cat-feed?units=${units}`);

    try {
      const response = await fetch(`/api/cat-feed?units=${units}`);
      const payload = await response.json();
      append(`Status ${response.status}: checksum=${payload.checksum}`);
    } catch (error) {
      append(`Request failed: ${String(error)}`);
    } finally {
      runButton.disabled = false;
    }
  });
});
