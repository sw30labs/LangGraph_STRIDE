const appState = {
  status: null,
  reportType: "stride",
  selectedJobId: null,
  selectedReportPath: null,
  lastJobStatuses: new Map(),
};

const $ = (id) => document.getElementById(id);

function showToast(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("visible"), 3200);
}

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || response.statusText);
  }
  return payload;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function shortCommand(command) {
  return command
    .map((part) => {
      if (part.includes("/")) return part.split("/").slice(-2).join("/");
      return part;
    })
    .join(" ");
}

function providerById(id) {
  return (appState.status?.provider.providers || []).find((provider) => provider.id === id);
}

function fillProviderSelect(select, defaultProvider) {
  const requested = defaultProvider || appState.status.provider.default;
  select.replaceChildren();
  for (const provider of appState.status.provider.providers) {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = `${provider.label} ${provider.ready ? "" : "(missing key)"}`.trim();
    select.appendChild(option);
  }
  if (requested && appState.status.provider.providers.some((provider) => provider.id === requested)) {
    select.value = requested;
  }
}

function populateProviderControls() {
  fillProviderSelect($("model-provider"), $("model-provider").value || appState.status.provider.default);
  fillProviderSelect($("scenario-provider"), $("scenario-provider").value || appState.status.provider.default);
  const provider = providerById(appState.status.provider.default);
  const chip = $("default-provider");
  chip.textContent = provider ? `${provider.label} · ${provider.model}` : "Provider";
  chip.className = `status-chip ${provider?.ready ? "ready" : "warning"}`;
  updateProviderState("model-provider", "model-provider-state");
  updateProviderState("scenario-provider", "scenario-provider-state");
}

function updateProviderState(selectId, stateId) {
  const provider = providerById($(selectId).value);
  const target = $(stateId);
  if (!provider) {
    target.textContent = "Provider";
    target.className = "state-indicator";
    return;
  }
  target.textContent = provider.ready ? `${provider.label} ready` : `${provider.label} key missing`;
  target.className = `state-indicator ${provider.ready ? "ready" : "warning"}`;
}

function populatecmdb() {
  const select = $("aa-id");
  const current = select.value;
  select.replaceChildren();
  for (const row of appState.status.cmdb) {
    const option = document.createElement("option");
    option.value = row.aa_id;
    option.textContent = `${row.aa_id} · ${row.name}`;
    select.appendChild(option);
  }
  if (current && appState.status.cmdb.some((row) => row.aa_id === current)) {
    select.value = current;
  }
  rendercmdbDetail();
}

function rendercmdbDetail() {
  const selected = $("aa-id").value;
  const row = appState.status.cmdb.find((item) => item.aa_id === selected);
  const target = $("cmdb-detail");
  target.replaceChildren();
  if (!row) {
    target.innerHTML = '<div class="empty-state">No application selected</div>';
    return;
  }
  const fields = [
    ["Application", row.name],
    ["Confidentiality", row.confidentiality],
    ["Integrity", row.integrity],
    ["Externally facing", row.externally_facing],
    ["Platform", Array.isArray(row.platform) ? row.platform.join(", ") : row.platform],
    ["Development category", row.development_category],
  ];
  const grid = document.createElement("div");
  grid.className = "detail-grid";
  for (const [label, value] of fields) {
    const item = document.createElement("div");
    item.className = "detail-item";
    const labelEl = document.createElement("span");
    labelEl.textContent = label;
    const valueEl = document.createElement("strong");
    valueEl.textContent = value || "Not specified";
    item.append(labelEl, valueEl);
    grid.appendChild(item);
  }
  target.appendChild(grid);
}

function populateTemplates() {
  const select = $("attack-template");
  const current = select.value;
  select.replaceChildren();
  for (const template of appState.status.attack_templates) {
    const option = document.createElement("option");
    option.value = template.name;
    option.textContent = template.name;
    select.appendChild(option);
  }
  if (current && appState.status.attack_templates.some((template) => template.name === current)) {
    select.value = current;
  }
  renderTechniques();
}

function renderTechniques() {
  const selected = $("attack-template").value;
  const template = appState.status.attack_templates.find((item) => item.name === selected);
  const target = $("technique-list");
  target.replaceChildren();
  if (!template || !template.techniques.length) {
    target.innerHTML = '<div class="empty-state">No attack template selected</div>';
    return;
  }
  for (const technique of template.techniques.slice(0, 16)) {
    const item = document.createElement("div");
    item.className = "technique";
    item.textContent = technique;
    target.appendChild(item);
  }
}

function populateJsonFiles() {
  const select = $("json-file");
  const current = select.value;
  select.replaceChildren();
  const files = appState.status.outputs.stride || [];
  if (!files.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No threat model JSON files";
    select.appendChild(option);
    return;
  }
  for (const file of files) {
    const option = document.createElement("option");
    option.value = file.path;
    option.textContent = file.name;
    select.appendChild(option);
  }
  if (current && files.some((file) => file.path === current)) {
    select.value = current;
  }
}

function updateMetrics() {
  $("workspace").textContent = appState.status.workspace;
  $("metric-cmdb").textContent = String(appState.status.cmdb.length);
  $("metric-templates").textContent = String(appState.status.attack_templates.length);
  $("metric-stride").textContent = String(appState.status.outputs.stride.length);
  $("metric-scenarios").textContent = String(appState.status.outputs.scenarios.length);
}

function renderReports() {
  const table = $("reports-table");
  table.replaceChildren();
  const files = appState.status.outputs[appState.reportType] || [];
  if (!files.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.textContent = "No JSON files";
    row.appendChild(cell);
    table.appendChild(row);
    $("report-preview").textContent = "No artifacts";
    return;
  }
  for (const file of files) {
    const row = document.createElement("tr");
    if (file.path === appState.selectedReportPath) row.classList.add("selected");
    row.addEventListener("click", () => previewReport(file.path));

    const name = document.createElement("td");
    const nameText = document.createElement("span");
    nameText.className = "file-name";
    nameText.textContent = file.name;
    name.appendChild(nameText);

    const modified = document.createElement("td");
    modified.textContent = file.modified;

    const size = document.createElement("td");
    size.textContent = formatBytes(file.size);

    row.append(name, modified, size);
    table.appendChild(row);
  }
}

async function previewReport(path) {
  appState.selectedReportPath = path;
  renderReports();
  $("report-preview").textContent = "Loading artifact";
  try {
    const payload = await fetchJson(`/api/file?path=${encodeURIComponent(path)}`);
    $("report-preview").textContent = JSON.stringify(payload.content, null, 2);
  } catch (error) {
    $("report-preview").textContent = error.message;
  }
}

function renderJobs() {
  const list = $("job-list");
  const jobs = appState.status.jobs || [];
  list.replaceChildren();
  $("job-count").textContent = `${jobs.length} jobs`;
  if (!jobs.length) {
    list.innerHTML = '<div class="empty-state">No jobs</div>';
    renderConsole(null);
    return;
  }
  if (!appState.selectedJobId || !jobs.some((job) => job.id === appState.selectedJobId)) {
    const running = jobs.find((job) => job.status === "running");
    appState.selectedJobId = (running || jobs[0]).id;
  }
  for (const job of jobs) {
    const previous = appState.lastJobStatuses.get(job.id);
    if (previous && previous === "running" && job.status !== "running") {
      showToast(`${job.kind} ${job.status}`);
    }
    appState.lastJobStatuses.set(job.id, job.status);

    const row = document.createElement("button");
    row.type = "button";
    row.className = `job-row ${job.id === appState.selectedJobId ? "active" : ""}`;
    row.addEventListener("click", () => {
      appState.selectedJobId = job.id;
      renderJobs();
    });

    const title = document.createElement("strong");
    title.textContent = `${job.kind} · ${job.status}`;
    const command = document.createElement("code");
    command.textContent = shortCommand(job.command);
    row.append(title, command);
    list.appendChild(row);
  }
  renderConsole(jobs.find((job) => job.id === appState.selectedJobId));
}

function renderConsole(job) {
  if (!job) {
    $("console-title").textContent = "No active job";
    $("console-state").textContent = "Idle";
    $("console-state").className = "state-indicator";
    $("console-log").textContent = "Awaiting execution";
    return;
  }
  $("console-title").textContent = `${job.kind} ${job.id}`;
  $("console-state").textContent = job.status;
  $("console-state").className = `state-indicator ${job.status}`;
  $("console-log").textContent = job.log.length ? job.log.join("\n") : "Process started";
  $("console-log").scrollTop = $("console-log").scrollHeight;
}

async function refreshStatus() {
  appState.status = await fetchJson("/api/status");
  updateMetrics();
  populateProviderControls();
  populatecmdb();
  populateTemplates();
  populateJsonFiles();
  renderReports();
  renderJobs();
}

async function submitJob(url, body) {
  const job = await fetchJson(url, {
    method: "POST",
    body: JSON.stringify(body),
  });
  appState.selectedJobId = job.id;
  showToast(`${job.kind} started`);
  await refreshStatus();
}

function bindEvents() {
  $("refresh").addEventListener("click", () => {
    refreshStatus().catch((error) => showToast(error.message));
  });

  $("aa-id").addEventListener("change", rendercmdbDetail);
  $("attack-template").addEventListener("change", renderTechniques);
  $("model-provider").addEventListener("change", () => updateProviderState("model-provider", "model-provider-state"));
  $("scenario-provider").addEventListener("change", () => updateProviderState("scenario-provider", "scenario-provider-state"));

  $("model-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitJob("/api/jobs/model", {
      aa_id: $("aa-id").value,
      provider: $("model-provider").value,
    }).catch((error) => showToast(error.message));
  });

  $("scenario-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitJob("/api/jobs/scenario", {
      json_file: $("json-file").value,
      attack_template: $("attack-template").value,
      provider: $("scenario-provider").value,
      min_cvss: $("min-cvss").value,
      db_path: "cve_database.db",
    }).catch((error) => showToast(error.message));
  });

  document.querySelectorAll(".segment").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".segment").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      appState.reportType = button.dataset.reportType;
      appState.selectedReportPath = null;
      renderReports();
    });
  });

  document.querySelectorAll(".rail-item").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".rail-item").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      $(button.dataset.target).scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

bindEvents();
refreshStatus()
  .then(() => {
    window.setInterval(() => {
      refreshStatus().catch(() => {});
    }, 2500);
  })
  .catch((error) => {
    showToast(error.message);
    $("workspace").textContent = "Workspace unavailable";
  });
