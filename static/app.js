document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".drop-zone").forEach((zone) => {
    const input = zone.querySelector('input[type="file"]');
    const label = zone.querySelector(".file-label");
    if (!input || !label) return;
    const show = () => {
      const file = input.files?.[0];
      if (file) label.textContent = `${file.name} · ${formatBytes(file.size)}`;
    };
    zone.addEventListener("click", (event) => { if (event.target !== input) input.click(); });
    zone.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); input.click(); } });
    input.addEventListener("change", show);
    ["dragenter", "dragover"].forEach((name) => zone.addEventListener(name, (event) => { event.preventDefault(); zone.classList.add("dragging"); }));
    ["dragleave", "drop"].forEach((name) => zone.addEventListener(name, (event) => { event.preventDefault(); zone.classList.remove("dragging"); }));
    zone.addEventListener("drop", (event) => {
      const file = event.dataTransfer?.files?.[0];
      if (!file) return;
      if (!file.name.toLowerCase().endsWith(".jar")) { alert("The main file must be a .jar file."); return; }
      const transfer = new DataTransfer(); transfer.items.add(file); input.files = transfer.files; show();
    });
  });

  document.querySelectorAll("[data-tabs]").forEach((tabs) => {
    const buttons = [...tabs.querySelectorAll("[data-tab]")];
    const panels = [...tabs.querySelectorAll("[data-panel]")];
    buttons.forEach((button) => button.addEventListener("click", () => {
      const selected = button.dataset.tab;
      buttons.forEach((item) => item.classList.toggle("active", item === button));
      panels.forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === selected));
    }));
  });

  document.querySelectorAll("[data-job-form]").forEach((form) => setupJobForm(form));
});

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB"]; let value = bytes; let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function setupJobForm(form) {
  const panel = document.querySelector("[data-status-panel]");
  if (!panel) return;
  const submit = form.querySelector('button[type="submit"]');
  let timer = null;
  const fields = {
    pill: panel.querySelector("[data-status-pill]"), title: panel.querySelector("[data-status-title]"),
    message: panel.querySelector("[data-status-message]"), spinner: panel.querySelector("[data-spinner]"),
    error: panel.querySelector("[data-error-box]"), result: panel.querySelector("[data-result-grid]"),
    downloads: panel.querySelector("[data-downloads]"), frameworks: panel.querySelector("[data-frameworks]"),
    renamed: panel.querySelector("[data-renamed-count]"), elapsed: panel.querySelector("[data-elapsed]"),
    entries: panel.querySelector("[data-entry-classes]"), jar: panel.querySelector("[data-jar-download]"),
    bundle: panel.querySelector("[data-bundle-download]")
  };
  const reset = () => {
    panel.classList.remove("hidden"); fields.spinner.classList.remove("hidden"); fields.error.classList.add("hidden");
    fields.result.classList.add("hidden"); fields.downloads.classList.add("hidden"); fields.pill.className = "status-pill";
  };
  const fail = (message) => {
    reset(); fields.spinner.classList.add("hidden"); fields.pill.textContent = "failed"; fields.pill.classList.add("failed");
    fields.title.textContent = "Build failed"; fields.message.textContent = "The server could not complete this build.";
    fields.error.textContent = message; fields.error.classList.remove("hidden"); submit.disabled = false; submit.textContent = "Try again";
  };
  const render = (job) => {
    reset(); fields.pill.textContent = job.status; fields.message.textContent = job.message || "";
    if (job.status === "queued") fields.title.textContent = "Waiting for a worker";
    if (job.status === "running") fields.title.textContent = job.workflow === "protect" ? "Protecting your plugin" : "Obfuscating your JAR";
    if (job.status === "complete") {
      fields.spinner.classList.add("hidden"); fields.pill.classList.add("success"); fields.title.textContent = "Build complete";
      fields.frameworks.textContent = (job.frameworks || []).join(", ") || "Generic Java JAR";
      fields.renamed.textContent = Number(job.renamed_class_count || 0).toLocaleString(); fields.elapsed.textContent = `${job.elapsed_seconds || 0} seconds`;
      fields.entries.textContent = Object.entries(job.entry_classes || {}).map(([a,b]) => `${a} → ${b}`).join(" | ") || "None detected";
      fields.result.classList.remove("hidden"); fields.jar.href = job.jar_download; fields.bundle.href = job.bundle_download; fields.downloads.classList.remove("hidden");
      submit.disabled = false; submit.textContent = "Build another JAR";
    }
    if (job.status === "failed") fail(job.error || "Unknown build error.");
  };
  const poll = async (url) => {
    try {
      const response = await fetch(url, { cache: "no-store" }); const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Status request failed (${response.status})`);
      render(data); if (data.status === "queued" || data.status === "running") timer = setTimeout(() => poll(url), 1200);
    } catch (error) { fail(error.message); }
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); if (timer) clearTimeout(timer); reset(); fields.pill.textContent = "uploading";
    fields.title.textContent = "Uploading your JAR"; fields.message.textContent = "Processing begins after the upload finishes.";
    submit.disabled = true; submit.textContent = "Uploading…"; panel.scrollIntoView({ behavior: "smooth", block: "start" });
    try {
      const response = await fetch("/api/jobs", { method: "POST", body: new FormData(form) }); const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Upload failed (${response.status})`); render(data); submit.textContent = "Processing…"; poll(data.status_url);
    } catch (error) { fail(error.message); }
  });
}
