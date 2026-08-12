const appState = {
  status: null,
  reportType: "stride",
  selectedJobId: null,
  selectedReportPath: null,
  lastJobStatuses: new Map(),
  maintainCards: null,
  maintainGraph: null,
  lastMaintainResult: null,
  maintainVizMode: "cooccurrence",
  ctiPacks: [],
  selectedCtiPackId: null,
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

function thinkingConfig() {
  return (
    appState.status?.thinking || {
      enabled: false,
      reasoning_strength: "high",
      reasoning_strengths: ["low", "medium", "high", "xhigh"],
    }
  );
}

function fillReasoningSelect(select, preferred) {
  const strengths = thinkingConfig().reasoning_strengths || ["low", "medium", "high", "xhigh"];
  const current = preferred || select.value || thinkingConfig().reasoning_strength || "high";
  select.replaceChildren();
  for (const strength of strengths) {
    const option = document.createElement("option");
    option.value = strength;
    option.textContent = strength;
    select.appendChild(option);
  }
  select.value = strengths.includes(current) ? current : strengths[0];
}

function syncThinkingControls(prefix) {
  const thinking = $(`${prefix}-thinking`);
  const strength = $(`${prefix}-reasoning-strength`);
  const wrap = $(`${prefix}-reasoning-wrap`);
  if (!thinking || !strength || !wrap) return;
  const enabled = thinking.value === "on";
  strength.disabled = !enabled;
  wrap.classList.toggle("is-disabled", !enabled);
}

function populateThinkingControls() {
  const defaults = thinkingConfig();
  for (const prefix of ["model", "scenario", "maintain"]) {
    const thinking = $(`${prefix}-thinking`);
    const strength = $(`${prefix}-reasoning-strength`);
    if (!thinking || !strength) continue;
    if (!thinking.dataset.initialized) {
      thinking.value = defaults.enabled ? "on" : "off";
      thinking.dataset.initialized = "1";
    }
    fillReasoningSelect(strength, strength.dataset.initialized ? strength.value : defaults.reasoning_strength);
    strength.dataset.initialized = "1";
    syncThinkingControls(prefix);
  }
}

function thinkingPayload(prefix) {
  const thinking = $(`${prefix}-thinking`);
  const strength = $(`${prefix}-reasoning-strength`);
  const enabled = thinking?.value === "on";
  const payload = { thinking: enabled };
  if (enabled && strength?.value) {
    payload.reasoning_strength = strength.value;
  }
  return payload;
}

function populateProviderControls() {
  fillProviderSelect($("model-provider"), $("model-provider").value || appState.status.provider.default);
  fillProviderSelect($("scenario-provider"), $("scenario-provider").value || appState.status.provider.default);
  if ($("maintain-provider")) {
    fillProviderSelect($("maintain-provider"), $("maintain-provider").value || appState.status.provider.default);
  }
  populateThinkingControls();
  const provider = providerById(appState.status.provider.default);
  const chip = $("default-provider");
  chip.textContent = provider ? `${provider.label} · ${provider.model}` : "Provider";
  chip.className = `status-chip ${provider?.ready ? "ready" : "warning"}`;
  updateProviderState("model-provider", "model-provider-state");
  updateProviderState("scenario-provider", "scenario-provider-state");
  if ($("maintain-provider") && $("maintain-provider-state")) {
    updateProviderState("maintain-provider", "maintain-provider-state");
  }
}

function updateProviderState(selectId, stateId) {
  const provider = providerById($(selectId).value);
  const target = $(stateId);
  if (!provider) {
    target.textContent = "Provider";
    target.className = "state-indicator";
    return;
  }
  // I show the probe detail when not ready so 401 / unreachable is obvious.
  target.textContent = provider.ready
    ? `${provider.label} ready`
    : `${provider.label}: ${provider.detail || "not ready"}`;
  target.title = `${provider.base_url} · ${provider.model}`;
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
  const cves = appState.status.intel?.catalogs?.nvd?.cve_count;
  if ($("metric-cves")) $("metric-cves").textContent = String(cves || 0);
}

function renderCmdbTable() {
  const table = $("cmdb-table");
  if (!table) return;
  table.replaceChildren();
  for (const row of appState.status.cmdb || []) {
    const tr = document.createElement("tr");
    if (row.aa_id === appState.selectedCmdbId) tr.classList.add("selected");
    tr.addEventListener("click", () => {
      appState.selectedCmdbId = row.aa_id;
      fillCmdbForm(row);
      renderCmdbTable();
    });
    for (const value of [row.aa_id, row.name, row.externally_facing || "—"]) {
      const td = document.createElement("td");
      td.textContent = value || "—";
      tr.appendChild(td);
    }
    table.appendChild(tr);
  }
}

function fillCmdbForm(row) {
  if (!$("cmdb-aa-id")) return;
  $("cmdb-aa-id").value = row?.aa_id || "";
  $("cmdb-name").value = row?.name || "";
  $("cmdb-description").value = row?.description || "";
  $("cmdb-confidentiality").value = row?.confidentiality || "";
  $("cmdb-integrity").value = row?.integrity || "";
  $("cmdb-platform").value = Array.isArray(row?.platform)
    ? row.platform.join(", ")
    : row?.platform || "";
  $("cmdb-facing").value = row?.externally_facing || "";
}

function renderNavigator() {
  const tree = $("navigator-tree");
  const detail = $("navigator-detail");
  const counts = $("navigator-counts");
  if (!tree || !detail) return;
  const nav = appState.status.navigator || { applications: [], counts: {} };
  if (counts) {
    counts.textContent = `${nav.counts?.applications || 0} apps · ${nav.counts?.threat_models || 0} models · ${nav.counts?.scenarios || 0} scenarios`;
  }
  tree.replaceChildren();
  const apps = nav.applications || [];
  if (!apps.length) {
    tree.innerHTML = '<div class="empty-state">No applications yet</div>';
    return;
  }
  for (const app of apps) {
    const appNode = document.createElement("details");
    appNode.open = true;
    const summary = document.createElement("summary");
    summary.textContent = `${app.aa_id} · ${app.name || "Unnamed"} (${(app.threat_models || []).length})`;
    summary.addEventListener("click", (event) => {
      event.preventDefault();
      appNode.open = !appNode.open;
      showNavigatorDetail({ type: "app", app });
    });
    appNode.appendChild(summary);
    for (const model of app.threat_models || []) {
      const modelBtn = document.createElement("button");
      modelBtn.type = "button";
      modelBtn.className = "nav-node";
      modelBtn.textContent = `TM ${model.artifact_id || model.path} · threats ${model.threat_count || 0}`;
      modelBtn.addEventListener("click", () => {
        showNavigatorDetail({ type: "model", app, model });
        if (model.path) {
          $("json-file").value = model.path;
        }
      });
      appNode.appendChild(modelBtn);
      for (const scenario of model.scenarios || []) {
        const scBtn = document.createElement("button");
        scBtn.type = "button";
        scBtn.className = "nav-node nested";
        scBtn.textContent = `SC ${scenario.attack_template || scenario.path}`;
        scBtn.addEventListener("click", () => showNavigatorDetail({ type: "scenario", app, model, scenario }));
        appNode.appendChild(scBtn);
      }
    }
    tree.appendChild(appNode);
  }
}

function showNavigatorDetail(selection) {
  const detail = $("navigator-detail");
  if (!detail) return;
  detail.replaceChildren();
  const block = document.createElement("div");
  block.className = "detail-grid";
  const lines = [];
  if (selection.type === "app") {
    lines.push(["AA ID", selection.app.aa_id], ["Name", selection.app.name], ["Models", String((selection.app.threat_models || []).length)]);
  } else if (selection.type === "model") {
    lines.push(
      ["Artifact", selection.model.artifact_id || ""],
      ["Path", selection.model.path || ""],
      ["Threats", String(selection.model.threat_count || 0)],
      ["Max DREAD", selection.model.max_dread == null ? "—" : String(selection.model.max_dread)],
      ["Scenarios", String((selection.model.scenarios || []).length)],
    );
    const actions = document.createElement("div");
    actions.className = "panel-actions";
    const run = document.createElement("button");
    run.type = "button";
    run.className = "button primary";
    run.textContent = "Use in scenario form";
    run.addEventListener("click", () => {
      if (selection.model.path) $("json-file").value = selection.model.path;
      if (selection.app.aa_id) $("aa-id").value = selection.app.aa_id;
      showToast("Scenario form prefilled from navigator");
      document.querySelector('[data-target="scenario-panel"]')?.click();
    });
    actions.appendChild(run);
    detail.appendChild(actions);
  } else if (selection.type === "scenario") {
    lines.push(
      ["Attack chain", selection.scenario.attack_template || ""],
      ["Path", selection.scenario.path || ""],
      ["Created", selection.scenario.created_at || ""],
    );
  }
  for (const [label, value] of lines) {
    const item = document.createElement("div");
    item.className = "detail-item";
    const labelEl = document.createElement("span");
    labelEl.textContent = label;
    const valueEl = document.createElement("strong");
    valueEl.textContent = value || "—";
    item.append(labelEl, valueEl);
    block.appendChild(item);
  }
  detail.appendChild(block);
}

function renderIntelCards() {
  const host = $("intel-cards");
  if (!host) return;
  const catalogs = appState.status.intel?.catalogs || {};
  host.replaceChildren();
  for (const key of ["nvd", "mitre", "cti"]) {
    const cat = catalogs[key] || {};
    const card = document.createElement("div");
    card.className = "intel-card";
    const title = document.createElement("h3");
    title.textContent = key.toUpperCase();
    const status = document.createElement("span");
    status.className = `state-indicator ${cat.status || "missing"}`;
    status.textContent = cat.status || "missing";
    const body = document.createElement("p");
    if (key === "nvd") body.textContent = `${cat.cve_count || 0} CVEs · ${cat.source || "no source"}`;
    if (key === "mitre") body.textContent = `${cat.technique_count || 0} techniques · ${cat.source || "no source"}`;
    if (key === "cti") body.textContent = `${cat.pack_count || 0} packs · ${cat.source || "no source"}`;
    const when = document.createElement("p");
    when.className = "form-hint";
    when.textContent = cat.last_success_at ? `Last success: ${cat.last_success_at}` : "Never updated";
    if (cat.last_error) when.textContent += ` · error: ${cat.last_error}`;
    card.append(title, status, body, when);
    host.appendChild(card);
  }
}

async function loadCtiPacks() {
  appState.ctiPacks = await fetchJson("/api/cti");
  if (
    appState.selectedCtiPackId &&
    !appState.ctiPacks.some((pack) => pack.id === appState.selectedCtiPackId)
  ) {
    appState.selectedCtiPackId = null;
  }
  renderCtiPacks();
}

function renderCtiPacks() {
  const table = $("cti-packs-table");
  if (!table) return;
  table.replaceChildren();
  const filter = ($("cti-filter")?.value || "").trim().toLowerCase();
  const packs = appState.ctiPacks.filter((pack) => {
    if (!filter) return true;
    const blob = [pack.id, pack.title, ...(pack.techniques || []), ...(pack.iocs || [])]
      .join(" ")
      .toLowerCase();
    return blob.includes(filter);
  });
  if (!packs.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 2;
    cell.textContent = appState.ctiPacks.length ? "No packs match the filter" : "No CTI packs yet";
    row.appendChild(cell);
    table.appendChild(row);
    $("cti-pack-preview").textContent = "Select a pack";
    return;
  }
  for (const pack of packs) {
    const row = document.createElement("tr");
    if (pack.id === appState.selectedCtiPackId) row.classList.add("selected");
    row.addEventListener("click", () => previewCtiPack(pack.id));

    const name = document.createElement("td");
    const nameText = document.createElement("span");
    nameText.className = "file-name";
    nameText.textContent = pack.title;
    name.appendChild(nameText);

    const techniques = document.createElement("td");
    techniques.textContent = (pack.techniques || []).slice(0, 4).join(", ");

    row.append(name, techniques);
    table.appendChild(row);
  }
}

function previewCtiPack(packId) {
  appState.selectedCtiPackId = packId;
  renderCtiPacks();
  const pack = appState.ctiPacks.find((item) => item.id === packId);
  if (!pack) return;
  $("cti-pack-preview").textContent = [
    `${pack.title} (${pack.id})`,
    `Source: ${pack.source || "n/a"} · Updated: ${pack.updated_at || "n/a"}`,
    `Actors: ${(pack.actors || []).join(", ") || "n/a"}`,
    `Techniques: ${(pack.techniques || []).join(", ") || "n/a"}`,
    `IOCs: ${(pack.iocs || []).join(", ") || "n/a"}`,
    "",
    pack.notes || "",
  ].join("\n");
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
      if (/^intel-(cti|advisories|geointel)/.test(job.kind)) loadCtiPacks().catch(() => {});
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

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function fieldControlHtml(field, cardId) {
  const id = `mc-${cardId}-${field.k}`;
  if (field.type === "textarea") {
    return `<label for="${id}">${escapeHtml(field.label)}
      <textarea id="${id}" data-field="${escapeHtml(field.k)}" placeholder="${escapeHtml(field.ph || "")}"></textarea>
    </label>`;
  }
  if (field.type === "checkbox") {
    return `<label class="check-row" for="${id}">
      <input id="${id}" data-field="${escapeHtml(field.k)}" type="checkbox" />
      <span>${escapeHtml(field.label)}</span>
    </label>`;
  }
  if (field.type === "aa_select") {
    const options = (appState.status?.cmdb || [])
      .map((row) => `<option value="${escapeHtml(row.aa_id)}">${escapeHtml(row.aa_id)} · ${escapeHtml(row.name)}</option>`)
      .join("");
    return `<label for="${id}">${escapeHtml(field.label)}
      <select id="${id}" data-field="${escapeHtml(field.k)}">${options || '<option value="">No apps</option>'}</select>
    </label>`;
  }
  if (field.type === "number") {
    return `<label for="${id}">${escapeHtml(field.label)}
      <input id="${id}" data-field="${escapeHtml(field.k)}" type="number"
        min="${field.min ?? ""}" max="${field.max ?? ""}" step="${field.step ?? "any"}"
        value="${field.value ?? ""}" />
    </label>`;
  }
  return `<label for="${id}">${escapeHtml(field.label)}
    <input id="${id}" data-field="${escapeHtml(field.k)}" type="text" placeholder="${escapeHtml(field.ph || "")}" />
  </label>`;
}

function renderMaintainCards() {
  const root = $("maintain-card-groups");
  if (!root || !appState.maintainCards) return;
  const { groups, cards } = appState.maintainCards;
  const byGroup = new Map((groups || []).map((g) => [g.id, { ...g, cards: [] }]));
  for (const card of cards || []) {
    const bucket = byGroup.get(card.group) || {
      id: card.group,
      title: card.group,
      sub: "",
      cards: [],
    };
    bucket.cards.push(card);
    byGroup.set(card.group, bucket);
  }
  root.replaceChildren();
  for (const group of byGroup.values()) {
    if (!group.cards.length) continue;
    const section = document.createElement("div");
    section.className = "pg-group";
    section.innerHTML = `<div class="pg-group-head">
      <span class="pg-group-title">${escapeHtml(group.title)}</span>
      <span class="pg-group-sub">${escapeHtml(group.sub || "")}</span>
    </div>`;
    const grid = document.createElement("div");
    grid.className = "maintain-card-grid";
    for (const card of group.cards) {
      const el = document.createElement("article");
      el.className = "maintain-card";
      el.dataset.cardId = card.id;
      el.innerHTML = `
        <div class="maintain-card-top">
          <h3>${escapeHtml(card.name)}</h3>
          <span class="card-tag ${card.llm ? "llm" : ""}">${card.llm ? "LLM + judge" : "offline"}</span>
        </div>
        <p>${escapeHtml(card.desc)}</p>
        ${(card.fields || []).map((field) => fieldControlHtml(field, card.id)).join("")}
        <button class="button primary" type="button" data-run-card="${escapeHtml(card.id)}">${escapeHtml(card.btn || "RUN")}</button>
      `;
      grid.appendChild(el);
    }
    section.appendChild(grid);
    root.appendChild(section);
  }
}

function collectCardFields(cardId) {
  const card = document.querySelector(`.maintain-card[data-card-id="${cardId}"]`);
  const payload = { card: cardId };
  if (!card) return payload;
  card.querySelectorAll("[data-field]").forEach((input) => {
    const key = input.dataset.field;
    if (input.type === "checkbox") {
      payload[key] = input.checked;
    } else if (input.type === "number") {
      payload[key] = input.value === "" ? undefined : Number(input.value);
    } else {
      payload[key] = input.value;
    }
  });
  return payload;
}

function updateNeo4jChip(neo) {
  const chip = $("maintain-neo4j-state");
  const link = $("maintain-neo4j-browser");
  if (!chip) return;
  if (!neo) {
    chip.textContent = "Neo4j unknown";
    chip.className = "state-indicator";
    return;
  }
  if (link && neo.browser_url) link.href = neo.browser_url;
  if (neo.ready || neo.synced) {
    const c = neo.counts || {};
    chip.textContent = `Neo4j · ${c.chains ?? "?"}c / ${c.techniques ?? "?"}t`;
    chip.className = "state-indicator ready";
    chip.title = `${neo.uri || ""} · ${neo.detail || "ok"} · synced ${neo.synced_at || "—"}`;
  } else {
    chip.textContent = `Neo4j · ${neo.detail || "offline"}`;
    chip.className = "state-indicator warning";
    chip.title = neo.uri || "";
  }
}

function showGraphTooltip(event, html) {
  const tip = $("maintain-graph-tooltip");
  const stage = event.currentTarget?.closest?.(".galaxy-stage") || tip?.parentElement;
  if (!tip || !stage) return;
  tip.hidden = false;
  tip.innerHTML = html;
  const rect = stage.getBoundingClientRect();
  tip.style.left = `${Math.min(event.clientX - rect.left + 12, rect.width - 180)}px`;
  tip.style.top = `${Math.max(8, event.clientY - rect.top - 10)}px`;
}

function hideGraphTooltip() {
  const tip = $("maintain-graph-tooltip");
  if (tip) tip.hidden = true;
}

function renderForceLayout(svg, layout, { voidEdges = [] } = {}) {
  const width = layout.width || 720;
  const height = layout.height || 460;
  const nodes = layout.nodes || [];
  const edges = layout.edges || [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const maxW = Math.max(1, ...nodes.map((n) => n.weight || 1));

  const edgeMarkup = edges
    .map((edge) => {
      const a = byId.get(edge.source);
      const b = byId.get(edge.target);
      if (!a || !b) return "";
      const strong = (edge.weight || 1) >= 3 ? "strong" : "";
      return `<line class="edge ${strong}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" data-w="${edge.weight || 1}"/>`;
    })
    .join("");

  const voidMarkup = voidEdges
    .map((edge) => {
      const a = byId.get(edge.source);
      const b = byId.get(edge.target);
      if (!a || !b) return "";
      return `<line class="edge void" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`;
    })
    .join("");

  const nodeMarkup = nodes
    .map((node) => {
      const r = 4 + Math.min(10, ((node.weight || 1) / maxW) * 10);
      const kind = node.kind === "chain" ? "node-chain" : "node-tech";
      const hub = (node.weight || 0) >= maxW * 0.7 && node.kind !== "chain" ? "node-hub" : "";
      const label = (node.label || node.id || "").slice(0, 22);
      return `<g class="node" data-id="${escapeHtml(node.id)}" data-label="${escapeHtml(node.label || "")}" data-weight="${node.weight || 1}" data-kind="${escapeHtml(node.kind || "")}">
        <circle class="${kind} ${hub}" cx="${node.x}" cy="${node.y}" r="${r}"/>
        <text class="node-label" x="${node.x + r + 4}" y="${node.y + 3}">${escapeHtml(label)}</text>
      </g>`;
    })
    .join("");

  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = `${edgeMarkup}${voidMarkup}${nodeMarkup}`;
  svg.querySelectorAll(".node").forEach((el) => {
    el.addEventListener("mousemove", (event) => {
      showGraphTooltip(
        event,
        `<strong>${escapeHtml(el.dataset.label || el.dataset.id)}</strong><br/>${escapeHtml(el.dataset.kind)} · weight ${escapeHtml(el.dataset.weight)}`
      );
    });
    el.addEventListener("mouseleave", hideGraphTooltip);
  });
}

function renderDarkMatterLayout(svg, graph) {
  const pairs = (graph?.dark_matter_pairs || []).slice(0, 18);
  const width = 720;
  const height = Math.max(360, 40 + pairs.length * 22);
  if (!pairs.length) {
    svg.setAttribute("viewBox", `0 0 ${width} 200`);
    svg.innerHTML = `<text x="24" y="40" class="node-label">No dark-matter pairs — library is small or fully connected</text>`;
    return;
  }
  const left = pairs.map((p, i) => ({
    id: `a:${p.a}`,
    label: p.label_a || p.a,
    x: 160,
    y: 28 + i * 22,
    weight: p.freq_a || 1,
    kind: "technique",
  }));
  const right = pairs.map((p, i) => ({
    id: `b:${p.b}`,
    label: p.label_b || p.b,
    x: 560,
    y: 28 + i * 22,
    weight: p.freq_b || 1,
    kind: "technique",
  }));
  // dedupe nodes that appear multiple times
  const nodes = [];
  const seen = new Set();
  for (const node of [...left, ...right]) {
    if (seen.has(node.id)) continue;
    seen.add(node.id);
    nodes.push(node);
  }
  const byId = new Map(nodes.map((n) => [n.id, n]));
  // re-average y for duplicates that were skipped — keep first
  const edges = pairs.map((p) => ({
    source: `a:${p.a}`,
    target: `b:${p.b}`,
    weight: 1,
  }));
  const edgeMarkup = edges
    .map((edge) => {
      const a = byId.get(edge.source);
      const b = byId.get(edge.target);
      if (!a || !b) return "";
      return `<path class="edge void" d="M ${a.x + 8} ${a.y} C 320 ${a.y}, 400 ${b.y}, ${b.x - 8} ${b.y}"/>`;
    })
    .join("");
  const nodeMarkup = nodes
    .map((node) => {
      const side = node.id.startsWith("a:") ? -1 : 1;
      const labelX = node.x + side * 12;
      const anchor = side < 0 ? "end" : "start";
      return `<g class="node" data-label="${escapeHtml(node.label)}" data-weight="${node.weight}">
        <circle class="node-tech" cx="${node.x}" cy="${node.y}" r="4.5"/>
        <text class="node-label" text-anchor="${anchor}" x="${labelX}" y="${node.y + 3}">${escapeHtml((node.label || "").slice(0, 28))}</text>
      </g>`;
    })
    .join("");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.innerHTML = `${edgeMarkup}${nodeMarkup}
    <text x="160" y="14" class="node-label" text-anchor="middle">technique A (rare)</text>
    <text x="560" y="14" class="node-label" text-anchor="middle">technique B (never co-occurs)</text>`;
}

function renderGalaxy(graph) {
  const svg = $("maintain-galaxy");
  const counts = $("maintain-graph-counts");
  const title = $("maintain-viz-title");
  const caption = $("maintain-viz-caption");
  if (!svg) return;
  if (counts) {
    counts.textContent = `${graph?.counts?.chains || 0} chains · ${graph?.counts?.techniques || 0} techs`;
  }
  updateNeo4jChip(graph?.neo4j);

  const mode = appState.maintainVizMode || "cooccurrence";
  if (mode === "bipartite") {
    if (title) title.textContent = "Chain ↔ technique bipartite";
    if (caption) {
      caption.textContent = "Left: attack templates · Right: frequent techniques · edges = USES.";
    }
    const layout = graph?.layouts?.bipartite;
    if (layout) renderForceLayout(svg, layout);
    else svg.innerHTML = `<text x="24" y="40" class="node-label">No bipartite layout</text>`;
    return;
  }
  if (mode === "darkmatter") {
    if (title) title.textContent = "Dark-matter pairs";
    if (caption) {
      caption.textContent =
        "Amber dashed links = techniques that appear in the library but never together — forge fuel.";
    }
    renderDarkMatterLayout(svg, graph);
    return;
  }
  if (title) title.textContent = "Technique co-occurrence";
  if (caption) {
    caption.textContent =
      "Force-directed layout of frequent techniques. Edge weight = shared chains. Gold = hub nodes.";
  }
  const layout = graph?.layouts?.cooccurrence;
  if (layout) renderForceLayout(svg, layout);
  else svg.innerHTML = `<text x="24" y="40" class="node-label">No co-occurrence layout</text>`;
}

function renderTacticBars(graph) {
  const root = $("maintain-tactic-bars");
  if (!root) return;
  const rows = graph?.tactic_coverage || [];
  if (!rows.length) {
    root.innerHTML = '<div class="empty-state">No tactic coverage yet</div>';
    return;
  }
  const max = Math.max(1, ...rows.map((row) => row.count || 0));
  root.innerHTML = rows
    .map((row) => {
      const pct = Math.round(((row.count || 0) / max) * 100);
      const blind = (row.count || 0) === 0;
      return `<div class="tactic-row ${blind ? "blind" : ""}">
        <span>${escapeHtml(row.tactic)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${blind ? 4 : pct}%"></div></div>
        <span>${row.count || 0}</span>
      </div>`;
    })
    .join("");
}

function renderTechniqueUsage(graph) {
  const root = $("maintain-heatmap");
  if (!root) return;
  const heat = graph?.heatmap;
  if (!heat?.techniques?.length || !heat?.chains?.length) {
    root.innerHTML = '<div class="empty-state">No chain library data</div>';
    return;
  }
  // Count, per technique, how many chains use it — the matrix was unreadable
  // at library scale; the ranked hub list is the actionable summary.
  const counts = heat.techniques.map((tech, index) => ({
    label: tech.label || tech.id || "?",
    count: heat.chains.reduce((sum, chain) => sum + (chain.cells?.[index] ? 1 : 0), 0),
  }));
  counts.sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  const top = counts.slice(0, 12);
  const max = Math.max(1, ...top.map((row) => row.count));
  const rows = top
    .map((row) => {
      const pct = Math.round((row.count / max) * 100);
      const short = row.label.length > 30 ? `${row.label.slice(0, 29)}…` : row.label;
      return `<div class="tactic-row" title="${escapeHtml(row.label)} — used by ${row.count} of ${heat.chains.length} chains">
        <span>${escapeHtml(short)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        <span>${row.count}</span>
      </div>`;
    })
    .join("");
  root.innerHTML = `${rows}<p class="form-hint">Chains using each technique · top ${top.length} of ${counts.length} across ${heat.chains.length} chains</p>`;
}

function renderMaintainResult(result) {
  const root = $("maintain-result");
  if (!root) return;
  if (!result) {
    root.innerHTML = '<div class="empty-state">Run a card — forge proposals, clone autopsy, and galaxy rebuilds land here</div>';
    return;
  }
  appState.lastMaintainResult = result;
  if (result.graph) {
    root.innerHTML = `<div class="detail-grid">
      <div class="detail-item"><span>Card</span><strong>${escapeHtml(result.card || "technique_galaxy")}</strong></div>
      <div class="detail-item"><span>Chains</span><strong>${result.graph.counts?.chains ?? "—"}</strong></div>
      <div class="detail-item"><span>Techniques</span><strong>${result.graph.counts?.techniques ?? "—"}</strong></div>
      <div class="detail-item"><span>Artifact</span><strong>${escapeHtml(result.artifact_path || "—")}</strong></div>
    </div>
    <p class="form-hint">Galaxy rebuilt. Dark-matter pairs: ${(result.graph.dark_matter_pairs || []).length}. Clone the Maintain CLI for deeper JSON.</p>`;
    return;
  }
  if (result.pairs) {
    const rows = (result.pairs || [])
      .slice(0, 12)
      .map(
        (pair) => `<div class="proposal-step">
          <strong>${escapeHtml(pair.a_name)}</strong> ↔ <strong>${escapeHtml(pair.b_name)}</strong>
          · Jaccard ${pair.jaccard} · ${escapeHtml(pair.severity)}
          · shared ${pair.shared_count}
        </div>`
      )
      .join("");
    root.innerHTML = `<div class="detail-grid">
      <div class="detail-item"><span>Card</span><strong>clone_autopsy</strong></div>
      <div class="detail-item"><span>Pairs</span><strong>${result.pair_count ?? result.pairs.length}</strong></div>
      <div class="detail-item"><span>Threshold</span><strong>${result.threshold}</strong></div>
      <div class="detail-item"><span>Artifact</span><strong>${escapeHtml(result.artifact_path || "—")}</strong></div>
    </div>
    <div class="proposal-steps">${rows || '<div class="empty-state">No near-duplicates above threshold</div>'}</div>`;
    return;
  }
  // Forge proposal (from job log we may only have toast; full result via polling artifact is future work)
  const proposal = result.proposal;
  const steps = (proposal?.steps || [])
    .map((step) => {
      const tid = step.technique_id ? ` (${step.technique_id})` : "";
      return `<div class="proposal-step"><strong>${escapeHtml(step.tactic || "step")}</strong> · ${escapeHtml(step.name || step.raw || "")}${escapeHtml(tid)}</div>`;
    })
    .join("");
  const accepted = result.accepted ? "ACCEPTED" : "REJECTED / incomplete";
  root.innerHTML = `<div class="detail-grid">
      <div class="detail-item"><span>Card</span><strong>${escapeHtml(result.card || "forge")}</strong></div>
      <div class="detail-item"><span>Verdict</span><strong>${accepted}</strong></div>
      <div class="detail-item"><span>Jaccard gate</span><strong>${result.gate?.max_jaccard ?? "—"}</strong></div>
      <div class="detail-item"><span>Artifact</span><strong>${escapeHtml(result.artifact_path || "—")}</strong></div>
    </div>
    <p class="form-hint">${escapeHtml(result.novelty_thesis || result.judgment?.summary || "")}</p>
    <h3 style="margin:12px 0 0;font-size:14px;color:#fff">${escapeHtml(proposal?.name || "No proposal")}</h3>
    <p class="form-hint">${escapeHtml(proposal?.description || "")}</p>
    <div class="proposal-steps">${steps || ""}</div>
    ${
      result.accepted && result.artifact_path
        ? `<div class="panel-actions" style="padding:12px 0 0">
            <button class="button primary" type="button" id="maintain-commit-proposal">Commit to library</button>
          </div>`
        : ""
    }`;
  $("maintain-commit-proposal")?.addEventListener("click", () => {
    fetchJson("/api/maintain/commit", {
      method: "POST",
      body: JSON.stringify({ path: result.artifact_path }),
    })
      .then(() => {
        showToast("Proposal committed to attack templates");
        return refreshStatus();
      })
      .then(() => loadMaintainGraph())
      .catch((error) => showToast(error.message));
  });
}

async function loadMaintainCards() {
  appState.maintainCards = await fetchJson("/api/maintain/cards");
  renderMaintainCards();
}

async function loadMaintainGraph() {
  appState.maintainGraph = await fetchJson("/api/maintain/graph");
  renderGalaxy(appState.maintainGraph);
  renderTacticBars(appState.maintainGraph);
  renderTechniqueUsage(appState.maintainGraph);
  updateNeo4jChip(appState.maintainGraph?.neo4j);
}

async function loadCannedQueryList() {
  const select = $("maintain-canned-query");
  if (!select) return;
  try {
    const payload = await fetchJson("/api/maintain/neo4j/queries");
    select.replaceChildren();
    for (const row of payload.queries || []) {
      const option = document.createElement("option");
      option.value = row.id;
      option.textContent = row.title || row.id;
      select.appendChild(option);
    }
  } catch {
    select.innerHTML = '<option value="">Neo4j queries unavailable</option>';
  }
}

async function runCannedQuery() {
  const name = $("maintain-canned-query")?.value;
  const out = $("maintain-canned-result");
  if (!name || !out) return;
  out.textContent = "Running…";
  try {
    const payload = await fetchJson(`/api/maintain/neo4j/query/${encodeURIComponent(name)}`);
    out.textContent = JSON.stringify(payload, null, 2);
  } catch (error) {
    out.textContent = error.message;
  }
}

async function runMaintainCard(cardId) {
  const body = {
    ...collectCardFields(cardId),
    provider: $("maintain-provider")?.value,
    ...thinkingPayload("maintain"),
  };
  // Offline cards can run synchronously for instant viz; forges go through jobs.
  if (cardId === "technique_galaxy") {
    const graph = await fetchJson("/api/maintain/graph");
    appState.maintainGraph = graph;
    renderGalaxy(graph);
    renderTacticBars(graph);
    renderTechniqueUsage(graph);
    renderMaintainResult({ card: "technique_galaxy", graph, accepted: true });
    showToast("Technique galaxy refreshed");
    return;
  }
  if (cardId === "clone_autopsy") {
    const threshold = body.threshold ?? 0.55;
    const pairs = await fetchJson(`/api/maintain/clones?threshold=${encodeURIComponent(threshold)}`);
    // Also kick the CLI job so an artifact lands under output/maintain/
    await submitJob("/api/jobs/maintain", body);
    renderMaintainResult({
      card: "clone_autopsy",
      pairs,
      pair_count: pairs.length,
      threshold,
      accepted: true,
    });
    return;
  }
  await submitJob("/api/jobs/maintain", body);
  $("maintain-result").innerHTML = `<div class="empty-state">Forge running as background job — watch Activity / live log. Artifact lands in output/maintain/</div>`;
  // Jump operator to activity so the Ralph loop is visible
  document.querySelector('[data-target="activity-panel"]')?.click();
}

function isUserEditing() {
  // Polling must not rebuild DOM under an active text field — that steals focus
  // and wipes in-progress steer / CMDB / number input.
  const el = document.activeElement;
  if (!el || el === document.body) return false;
  const tag = (el.tagName || "").toLowerCase();
  if (tag === "textarea") return true;
  if (tag === "select") return true;
  if (tag === "input") {
    const type = (el.type || "text").toLowerCase();
    return !["button", "submit", "checkbox", "radio", "file", "reset", "image"].includes(type);
  }
  return Boolean(el.isContentEditable);
}

async function refreshStatus(options = {}) {
  const { force = false } = options;
  const editing = !force && isUserEditing();
  appState.status = await fetchJson("/api/status");
  updateMetrics();
  // Always keep job/console fresh — those nodes are not under the caret.
  renderJobs();
  if (editing) {
    // Leave selects, tables, maintain cards, and form values alone while typing.
    return;
  }
  populateProviderControls();
  populatecmdb();
  populateTemplates();
  populateJsonFiles();
  renderCmdbTable();
  renderNavigator();
  renderIntelCards();
  renderReports();
  // Maintain cards are static catalog UI with free-text steers — build once
  // in loadMaintainCards(), never on the poll tick.
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
    refreshStatus({ force: true }).catch((error) => showToast(error.message));
  });

  $("aa-id").addEventListener("change", rendercmdbDetail);
  $("attack-template").addEventListener("change", renderTechniques);
  $("model-provider").addEventListener("change", () => updateProviderState("model-provider", "model-provider-state"));
  $("scenario-provider").addEventListener("change", () => updateProviderState("scenario-provider", "scenario-provider-state"));
  $("maintain-provider")?.addEventListener("change", () => updateProviderState("maintain-provider", "maintain-provider-state"));
  $("model-thinking").addEventListener("change", () => syncThinkingControls("model"));
  $("scenario-thinking").addEventListener("change", () => syncThinkingControls("scenario"));
  $("maintain-thinking")?.addEventListener("change", () => syncThinkingControls("maintain"));

  $("maintain-card-groups")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-run-card]");
    if (!button) return;
    runMaintainCard(button.dataset.runCard).catch((error) => showToast(error.message));
  });
  $("maintain-refresh-galaxy")?.addEventListener("click", () => {
    loadMaintainGraph()
      .then(() => showToast("Observatory refreshed + Neo4j sync attempted"))
      .catch((error) => showToast(error.message));
  });
  $("maintain-neo4j-sync")?.addEventListener("click", () => {
    fetchJson("/api/maintain/neo4j/sync", { method: "POST", body: "{}" })
      .then((result) => {
        updateNeo4jChip(result.status || result);
        showToast(result.synced ? "Neo4j projection rebuilt" : result.detail || "Neo4j sync failed");
        return loadMaintainGraph();
      })
      .catch((error) => showToast(error.message));
  });
  $("maintain-run-canned")?.addEventListener("click", () => {
    runCannedQuery().catch((error) => showToast(error.message));
  });
  document.querySelectorAll("[data-viz-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-viz-mode]").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      appState.maintainVizMode = button.dataset.vizMode;
      if (appState.maintainGraph) renderGalaxy(appState.maintainGraph);
    });
  });

  $("model-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitJob("/api/jobs/model", {
      aa_id: $("aa-id").value,
      provider: $("model-provider").value,
      ...thinkingPayload("model"),
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
      ...thinkingPayload("scenario"),
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
      const targetId = button.dataset.target;
      if (!targetId) return;
      document.querySelectorAll(".rail-item").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      document.querySelectorAll(".view-page").forEach((page) => {
        const active = page.id === targetId || page.dataset.withView === targetId;
        page.classList.toggle("is-active", active);
      });
      window.scrollTo({ top: 0, behavior: "auto" });
    });
  });

  $("cmdb-seed")?.addEventListener("click", () => {
    fetchJson("/api/workspace/seed", { method: "POST", body: JSON.stringify({ force: false }) })
      .then(() => refreshStatus())
      .then(() => showToast("Workspace seeded"))
      .catch((error) => showToast(error.message));
  });

  $("cmdb-save")?.addEventListener("click", () => {
    const platform = ($("cmdb-platform").value || "")
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
    fetchJson("/api/cmdb", {
      method: "POST",
      body: JSON.stringify({
        aa_id: $("cmdb-aa-id").value,
        name: $("cmdb-name").value,
        swc_description: $("cmdb-description").value,
        confidentiality: $("cmdb-confidentiality").value,
        integrity: $("cmdb-integrity").value,
        platform,
        externally_facing: $("cmdb-facing").value,
      }),
    })
      .then(() => refreshStatus())
      .then(() => showToast("Application saved"))
      .catch((error) => showToast(error.message));
  });

  $("intel-refresh")?.addEventListener("click", () => {
    refreshStatus().catch((error) => showToast(error.message));
    loadCtiPacks().catch((error) => showToast(error.message));
  });
  $("cti-filter")?.addEventListener("input", renderCtiPacks);
  $("intel-seed-nvd")?.addEventListener("click", () => {
    fetchJson("/api/intel/seed-nvd", { method: "POST", body: "{}" })
      .then((result) => {
        showToast(`Seeded ${result.cve_count || 0} CVEs`);
        return refreshStatus();
      })
      .catch((error) => showToast(error.message));
  });
  $("intel-update-nvd")?.addEventListener("click", () => {
    submitJob("/api/intel/update", { catalog: "nvd", mode: "online", background: true }).catch(
      (error) => showToast(error.message),
    );
  });
  $("intel-update-mitre")?.addEventListener("click", () => {
    submitJob("/api/intel/update", { catalog: "mitre", mode: "online", background: true }).catch(
      (error) => showToast(error.message),
    );
  });
  $("intel-update-cti-kev")?.addEventListener("click", () => {
    submitJob("/api/intel/update", {
      catalog: "cti",
      mode: "online",
      background: true,
      recent: 40,
      ransomware: 25,
    }).catch((error) => showToast(error.message));
  });
  $("intel-update-cti-advisories")?.addEventListener("click", () => {
    submitJob("/api/intel/update", {
      catalog: "advisories",
      mode: "online",
      background: true,
      limit: 25,
    }).catch((error) => showToast(error.message));
  });
  $("intel-update-geointel")?.addEventListener("click", () => {
    submitJob("/api/intel/update", {
      catalog: "geointel",
      mode: "online",
      background: true,
      limit: 25,
    }).catch((error) => showToast(error.message));
  });

  $("export-pdf")?.addEventListener("click", () => {
    if (!appState.selectedReportPath) {
      showToast("Select a report first");
      return;
    }
    fetchJson("/api/export/pdf", {
      method: "POST",
      body: JSON.stringify({ path: appState.selectedReportPath }),
    })
      .then((result) => {
        showToast(`PDF ready: ${result.path}`);
        window.open(`/api/export/download?path=${encodeURIComponent(result.path)}`, "_blank");
      })
      .catch((error) => showToast(error.message));
  });
}

// I poll faster while jobs run, slower when idle, and pause when the tab is hidden.
// While the operator is typing, refreshStatus stays soft (jobs/metrics only).
let pollTimer = null;
function schedulePoll() {
  if (pollTimer) window.clearTimeout(pollTimer);
  if (document.hidden) return;
  const running = (appState.status?.jobs || []).some((job) => job.status === "running");
  const editing = isUserEditing();
  // Don't hammer the DOM while a steer textarea is focused.
  const delay = editing ? 15000 : running ? 2500 : 12000;
  pollTimer = window.setTimeout(() => {
    refreshStatus()
      .catch(() => {})
      .finally(schedulePoll);
  }, delay);
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    if (pollTimer) window.clearTimeout(pollTimer);
  } else {
    refreshStatus().catch(() => {}).finally(schedulePoll);
  }
});

bindEvents();
refreshStatus()
  .then(() => loadMaintainCards())
  .then(() => loadCannedQueryList())
  .then(() => loadMaintainGraph())
  .then(() => loadCtiPacks())
  .then(schedulePoll)
  .catch((error) => {
    showToast(error.message);
    $("workspace").textContent = "Workspace unavailable";
  });

/* ── Decorative layers below; application logic above is unchanged ── */

// Ambient background: drifting teal dots linked by faint cyan lines,
// gently repelled by the cursor. Purely decorative.
(function initAmbientBackground() {
  const canvas = document.getElementById("bg-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const COUNT = 70;
  const LINK = 130;
  const mouse = { x: -9999, y: -9999 };
  let width = 0;
  let height = 0;
  let points = [];
  let frameId = null;

  function resize() {
    const dpr = window.devicePixelRatio || 1;
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (!points.length) {
      points = Array.from({ length: COUNT }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.28,
        vy: (Math.random() - 0.5) * 0.28,
        r: Math.random() * 1.5 + 0.5,
      }));
    }
  }

  function tick() {
    frameId = null;
    ctx.clearRect(0, 0, width, height);
    for (const point of points) {
      point.x += point.vx;
      point.y += point.vy;
      const dx = point.x - mouse.x;
      const dy = point.y - mouse.y;
      const distance = Math.hypot(dx, dy);
      if (distance < 140 && distance > 0.1) {
        point.x += (dx / distance) * 0.5;
        point.y += (dy / distance) * 0.5;
      }
      if (point.x < -10) point.x = width + 10;
      if (point.x > width + 10) point.x = -10;
      if (point.y < -10) point.y = height + 10;
      if (point.y > height + 10) point.y = -10;
    }
    ctx.lineWidth = 0.6;
    for (let i = 0; i < COUNT; i += 1) {
      for (let j = i + 1; j < COUNT; j += 1) {
        const a = points[i];
        const b = points[j];
        const distance = Math.hypot(a.x - b.x, a.y - b.y);
        if (distance < LINK) {
          ctx.strokeStyle = `rgba(34,211,238,${(1 - distance / LINK) * 0.09})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }
    ctx.fillStyle = "rgba(94,234,212,0.4)";
    for (const point of points) {
      ctx.beginPath();
      ctx.arc(point.x, point.y, point.r, 0, 7);
      ctx.fill();
    }
    frameId = window.requestAnimationFrame(tick);
  }

  function start() {
    if (frameId === null) frameId = window.requestAnimationFrame(tick);
  }

  function stop() {
    if (frameId !== null) {
      window.cancelAnimationFrame(frameId);
      frameId = null;
    }
  }

  window.addEventListener("resize", resize);
  window.addEventListener("mousemove", (event) => {
    mouse.x = event.clientX;
    mouse.y = event.clientY;
    document.documentElement.style.setProperty("--mx", `${event.clientX}px`);
    document.documentElement.style.setProperty("--my", `${event.clientY}px`);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stop();
    else start();
  });

  resize();
  start();
})();

// Boot overlay: brief progress sequence, then fade out and remove.
// A CSS failsafe animation hides it even if this script never runs.
(function initBootOverlay() {
  const boot = document.getElementById("boot");
  if (!boot) return;
  const fill = document.getElementById("boot-fill");
  const log = document.getElementById("boot-log");
  const steps = [
    "loading workspace…",
    "connecting inference providers…",
    "reading output library…",
    "rendering console…",
  ];
  let index = 0;
  const timer = window.setInterval(() => {
    if (index >= steps.length) return;
    if (log) log.textContent = steps[index];
    index += 1;
    if (fill) fill.style.width = `${(index / (steps.length + 1)) * 100}%`;
  }, 170);
  window.setTimeout(() => {
    window.clearInterval(timer);
    if (fill) fill.style.width = "100%";
    boot.classList.add("done");
    boot.addEventListener("transitionend", () => boot.remove(), { once: true });
    window.setTimeout(() => boot.remove(), 1200);
  }, 1000);
})();
