const state = {
  index: null,
  timeline: null,
  sources: null,
  cves: [],
  selected: null,
};

const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const tierRank = { high: 3, medium: 2, low: 1 };

async function fetchJson(path, fallback) {
  try {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.warn(`Failed to load ${path}`, error);
    return fallback;
  }
}

function text(value, fallback = "n/a") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function formatDate(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString().slice(0, 10);
}

function formatPercent(value) {
  if (value === null || value === undefined) return "n/a";
  return `${Math.round(Number(value) * 100)}%`;
}

function metric(label, value) {
  return `<div class="metric"><span>${label}</span><strong>${text(value, "0")}</strong></div>`;
}

function timelineItem(label, value, suffix = "") {
  const display = value === null || value === undefined ? "n/a" : `${Math.round(value)}${suffix}`;
  return `<div class="timeline-item"><span>${label}</span><strong>${display}</strong></div>`;
}

function badge(value, extra = "") {
  if (!value) return "";
  return `<span class="badge ${String(value).toLowerCase()} ${extra}">${value}</span>`;
}

function renderLeadership() {
  const totals = state.index?.totals || {};
  const metrics = state.index?.timeline_metrics || {};
  document.getElementById("generatedAt").textContent =
    state.index?.generated_at ? `Generated ${formatDate(state.index.generated_at)}` : "No generated data yet";
  document.getElementById("warning").textContent =
    state.index?.warning ||
    "External PoC links are untrusted public GitHub repositories. Metadata only is stored.";
  document.getElementById("metrics").innerHTML = [
    metric("Tracked CVEs", totals.cves),
    metric("High Confidence PoC", totals.cves_with_high_confidence_poc),
    metric("CISA KEV", totals.cves_in_kev),
    metric("Critical CVEs", totals.critical_cves),
  ].join("");
  document.getElementById("timelineGrid").innerHTML = [
    timelineItem("Median Published to PoC", metrics.poc_lag_median_days, "d"),
    timelineItem("P90 Published to PoC", metrics.poc_lag_p90_days, "d"),
    timelineItem("Median Published to Exploited", metrics.exploitation_lag_median_days, "d"),
    timelineItem("P90 Published to Exploited", metrics.exploitation_lag_p90_days, "d"),
  ].join("");

  const rows = state.index?.latest_critical || [];
  document.getElementById("criticalRows").innerHTML = rows.length
    ? rows
        .map(
          (item) => `<tr>
            <td>${item.cve_id}</td>
            <td>${formatDate(item.published_at)}</td>
            <td>${badge(item.severity)}</td>
            <td>${text(item.cvss_score)}</td>
            <td>${text(item.poc_count, "0")}</td>
            <td>${item.has_kev ? badge("KEV", "kev") : "No"}</td>
          </tr>`,
        )
        .join("")
    : `<tr><td colspan="6" class="empty">No CVE records have been generated yet.</td></tr>`;
}

async function loadCveDetails(cveId) {
  const payload = await fetchJson(`api/cves/${cveId}.json`, null);
  if (payload) {
    state.selected = payload;
    renderDetail(payload);
  }
}

function renderResearch() {
  const query = document.getElementById("searchInput").value.trim().toLowerCase();
  const severity = document.getElementById("severityFilter").value;
  const kev = document.getElementById("kevFilter").value;
  const tier = document.getElementById("tierFilter").value;

  const filtered = state.cves.filter((item) => {
    if (severity && item.severity !== severity) return false;
    if (kev === "yes" && !item.has_kev) return false;
    if (kev === "no" && item.has_kev) return false;
    if (tier) {
      const best = bestTier(item);
      if ((tierRank[best] || 0) < (tierRank[tier] || 0)) return false;
    }
    if (query) {
      const haystack = [
        item.cve_id,
        item.severity,
        item.published_at,
        item.affected_summary,
        ...(item.top_pocs || []),
        item.first_high_confidence_poc_at,
      ]
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });

  document.getElementById("resultCount").textContent = `${filtered.length} results`;
  document.getElementById("researchRows").innerHTML = filtered.length
    ? filtered
        .slice(0, 500)
        .map(
          (item) => `<tr class="selectable" data-cve="${item.cve_id}">
            <td>${item.cve_id}</td>
            <td>${formatDate(item.published_at)}</td>
            <td>${badge(item.severity)}</td>
            <td>${formatPercent(item.epss_percentile)}</td>
            <td>${item.poc_count}</td>
            <td>${lag(item.published_to_first_poc_days)}</td>
            <td>${lag(item.published_to_first_exploitation_days)}</td>
          </tr>`,
        )
        .join("")
    : `<tr><td colspan="7" class="empty">No records match the current filters.</td></tr>`;
}

function bestTier(item) {
  return item.best_poc_tier || "";
}

function lag(value) {
  return value === null || value === undefined ? "n/a" : `${value}d`;
}

function renderDetail(cve) {
  const pocs = cve.pocs || [];
  const exploitation = cve.exploitation_signals || [];
  document.getElementById("detailPanel").innerHTML = `
    <h2>${cve.cve_id}</h2>
    <div class="detail-meta">
      ${badge(cve.severity)}
      ${cve.kev ? badge("KEV", "kev") : ""}
      <span>Published ${formatDate(cve.published_at)}</span>
      <span>CVSS ${text(cve.cvss_score)}</span>
      <span>EPSS ${formatPercent(cve.epss?.percentile)}</span>
    </div>
    <p class="description">${text(cve.description, "No description available.")}</p>
    <div class="detail-meta">
      <span>First PoC: ${formatDate(cve.timeline?.first_high_confidence_poc_at)}</span>
      <span>PoC lag: ${lag(cve.timeline?.published_to_first_poc_days)}</span>
      <span>First exploitation: ${formatDate(cve.timeline?.first_exploitation_signal_at)}</span>
      <span>Exploit lag: ${lag(cve.timeline?.published_to_first_exploitation_days)}</span>
    </div>
    ${exploitation.length ? `<p class="description">Exploitation signal: ${exploitation.map((s) => `${s.source} ${formatDate(s.observed_at)}`).join(", ")}</p>` : ""}
    <div class="poc-list">
      ${pocs.length ? pocs.map(renderPoc).join("") : `<p class="empty">No PoC candidates collected.</p>`}
    </div>
  `;
}

function renderPoc(poc) {
  return `<article class="poc-item">
    <a href="${poc.repo_url}" target="_blank" rel="noopener noreferrer">${poc.repo_full_name}</a>
    ${badge(poc.confidence_tier, `tier-${poc.confidence_tier}`)}
    <p class="description">${text(poc.description, "No repository description.")}</p>
    <div class="poc-meta">
      <span>Score ${text(poc.confidence_score)}</span>
      <span>Stars ${text(poc.stars, "0")}</span>
      <span>Created ${formatDate(poc.created_at)}</span>
      <span>Pushed ${formatDate(poc.pushed_at)}</span>
      <span>${text(poc.primary_language)}</span>
    </div>
    <p class="description">${text(poc.warning)}</p>
  </article>`;
}

function renderSources() {
  const rows = state.sources?.sources || state.index?.sources || [];
  document.getElementById("sourceRows").innerHTML = rows.length
    ? rows
        .map(
          (source) => `<tr>
            <td>${source.name}</td>
            <td>${source.ok ? "ok" : "partial"}</td>
            <td>${formatDate(source.fetched_at)}</td>
            <td>${text(source.record_count, "0")}</td>
            <td>${(source.errors || []).slice(0, 2).join("; ") || "None"}</td>
          </tr>`,
        )
        .join("")
    : `<tr><td colspan="5" class="empty">No source status has been generated yet.</td></tr>`;
}

function bindEvents() {
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((tab) => tab.classList.remove("active"));
      document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
      button.classList.add("active");
      document.getElementById(button.dataset.view).classList.add("active");
    });
  });

  ["searchInput", "severityFilter", "kevFilter", "tierFilter"].forEach((id) => {
    document.getElementById(id).addEventListener("input", renderResearch);
  });

  document.getElementById("researchRows").addEventListener("click", (event) => {
    const row = event.target.closest("tr[data-cve]");
    if (row) loadCveDetails(row.dataset.cve);
  });
}

async function init() {
  bindEvents();
  state.index = await fetchJson("api/index.json", {});
  state.timeline = await fetchJson("api/timelines/summary.json", { items: [] });
  state.sources = await fetchJson("api/sources/status.json", { sources: [] });
  state.cves = (state.timeline.items || []).sort((a, b) => {
    const severityDiff = (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
    if (severityDiff) return severityDiff;
    return String(b.published_at || "").localeCompare(String(a.published_at || ""));
  });
  renderLeadership();
  renderResearch();
  renderSources();
}

init();
