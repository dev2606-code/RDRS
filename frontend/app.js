
"use strict";

// ============================================================
// RDRS - Ransomware Detection and Response System
// Frontend JavaScript
// ============================================================

const API_BASE = "http://127.0.0.1:8000"

const content = document.getElementById("page-content");
const toast = document.getElementById("toast");

let toastTimer = null;
let activePage = "overview";

const originalOverview = content ? content.innerHTML : "";

// ============================================================
// PAGE INFORMATION
// ============================================================

const pageInfo = {
  overview: {
    title: "Security Overview",
    subtitle: "Monitor your defensive security sandbox."
  },
  detection: {
    title: "Live Detection",
    subtitle: "Review file activity and detection risk scores."
  },
  intelligence: {
    title: "Threat Intelligence",
    subtitle: "Review indicators and threat intelligence."
  },
  incidents: {
    title: "Incident Management",
    subtitle: "Review alerts returned by the RDRS backend."
  },
  tools: {
    title: "Security Tools",
    subtitle: "Defensive tools and sandbox utilities."
  },
  reports: {
    title: "Security Reports",
    subtitle: "Review and export available security data."
  },
  settings: {
    title: "Settings",
    subtitle: "RDRS application configuration."
  }
};

// ============================================================
// GENERAL HELPERS
// ============================================================

function escapeHTML(value) {
  return String(value ?? "—").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function showToast(message) {
  if (!toast) {
    console.log("[RDRS]", message);
    return;
  }

  toast.textContent = message;
  toast.classList.add("show");

  clearTimeout(toastTimer);

  toastTimer = setTimeout(() => {
    toast.classList.remove("show");
  }, 3000);
}

async function apiRequest(endpoint, options = {}) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    throw new Error(`API request failed: HTTP ${response.status}`);
  }

  return response.json();
}

function formatTimestamp(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function getSeverityClass(value) {
  const severity = String(value ?? "unknown").toLowerCase();

  if (["critical", "high", "medium", "low", "info"].includes(severity)) {
    return severity;
  }

  return "unknown";
}

function getRiskLevel(score) {
  const risk = Number(score) || 0;

  if (risk >= 80) return "Critical";
  if (risk >= 60) return "High";
  if (risk >= 40) return "Medium";
  if (risk >= 20) return "Low";

  return "Informational";
}

function downloadCSV(filename, rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    showToast("No data available to export.");
    return;
  }

  const columns = [...new Set(rows.flatMap(row => Object.keys(row)))];

  const escapeCSV = (value) => {
    let text = String(value ?? "");

    // Prevent spreadsheet formula injection in exported text.
    if (/^[=+\-@\t\r]/.test(text)) {
      text = "'" + text;
    }

    return `"${text.replace(/"/g, '""')}"`;
  };

  const csv = [
    columns.map(escapeCSV).join(","),
    ...rows.map(row =>
      columns.map(column => escapeCSV(row[column])).join(",")
    )
  ].join("\r\n");

  const blob = new Blob(["\uFEFF", csv], {
    type: "text/csv;charset=utf-8;"
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);

  showToast("CSV export downloaded.");
}

// ============================================================
// TABLE HELPER
// ============================================================

function tablePage(title, description, headers, rows, actionLabel = "Export CSV") {
  const tableHeaders = headers.map(header =>
    `<th>${escapeHTML(header)}</th>`
  ).join("");

  const tableRows = rows.map(row =>
    `<tr>${row.map(cell => `<td>${escapeHTML(cell)}</td>`).join("")}</tr>`
  ).join("");

  return `
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>${escapeHTML(title)}</h2>
          <p class="muted-note">${escapeHTML(description)}</p>
        </div>

        <div class="panel-actions">
          <span class="panel-badge">DEMO DATA</span>
          <button class="btn btn-secondary" id="page-action"
                  type="button">${escapeHTML(actionLabel)}</button>
        </div>
      </div>

      <div class="table-toolbar">
        <input
          type="search"
          id="table-filter"
          placeholder="Search table..."
          aria-label="Search table"
        />
      </div>

      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>${tableHeaders}</tr>
          </thead>

          <tbody id="filterable-rows">
            ${tableRows || `<tr><td colspan="${headers.length}">No records available.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

// ============================================================
// TABLE FILTER
// ============================================================

function bindTableFilter() {
  const filter = content?.querySelector("#table-filter");
  const tbody = content?.querySelector("#filterable-rows");

  if (!filter || !tbody) return;

  filter.addEventListener("input", () => {
    const query = filter.value.toLowerCase().trim();

    tbody.querySelectorAll("tr").forEach(row => {
      row.hidden = !row.textContent.toLowerCase().includes(query);
    });
  });
}

// ============================================================
// NAVIGATION
// ============================================================

function bindPageLinks() {
  document.querySelectorAll("[data-page]").forEach(element => {
    if (element.dataset.rdrsBound === "true") return;

    element.dataset.rdrsBound = "true";

    element.addEventListener("click", event => {
      event.preventDefault();

      const page = element.dataset.page;

      if (page) {
        renderPage(page);
      }
    });
  });
}

function updateNavigation(page) {
  document.querySelectorAll("[data-page]").forEach(element => {
    const isActive = element.dataset.page === page;

    element.classList.toggle("active", isActive);

    if (isActive) {
      element.setAttribute("aria-current", "page");
    } else {
      element.removeAttribute("aria-current");
    }
  });

  const heading = document.querySelector("#page-title");
  const subtitle = document.querySelector("#page-subtitle");

  if (heading && pageInfo[page]) {
    heading.textContent = pageInfo[page].title;
  }

  if (subtitle && pageInfo[page]) {
    subtitle.textContent = pageInfo[page].subtitle;
  }
}

// ============================================================
// OVERVIEW PAGE
// ============================================================

async function loadOverviewStatus() {
  try {
    const [health, status] = await Promise.all([
      apiRequest("/api/health"),
      apiRequest("/api/status")
    ]);

    console.log("RDRS health:", health);
    console.log("RDRS status:", status);

    const badge = document.querySelector("#api-status");

    if (badge) {
      badge.textContent = "API ONLINE";
      badge.classList.add("online");
      badge.classList.remove("offline");
    }
  } catch (error) {
    console.error("Overview status error:", error);

    const badge = document.querySelector("#api-status");

    if (badge) {
      badge.textContent = "API OFFLINE";
      badge.classList.add("offline");
      badge.classList.remove("online");
    }
  }
}

// ============================================================
// LIVE DETECTION PAGE
// ============================================================

async function loadLiveDetectionData() {
  const badge = content?.querySelector(".panel-badge");
  const tbody = content?.querySelector("#filterable-rows");
  const note = content?.querySelector(".muted-note");

  if (badge) badge.textContent = "LOADING";

  try {
    const [health, eventsResponse, alertsResponse] = await Promise.all([
      apiRequest("/api/health"),
      apiRequest("/api/events?limit=100"),
      apiRequest("/api/alerts?limit=100")
    ]);

    const events = Array.isArray(eventsResponse)
      ? eventsResponse
      : eventsResponse.events || eventsResponse.records || [];

    const alerts = Array.isArray(alertsResponse)
      ? alertsResponse
      : alertsResponse.alerts || [];

    if (badge) badge.textContent = "LIVE API";

    if (note) {
      note.textContent =
        `Connected to RDRS. Showing ${events.length} event(s) and ${alerts.length} alert(s).`;
    }

    const stats = content?.querySelectorAll(".stats-grid .stat-card");

    if (stats?.length) {
      const criticalCount = alerts.filter(item =>
        String(item.severity ?? "").toLowerCase() === "critical"
      ).length;

      const highCount = alerts.filter(item =>
        String(item.severity ?? "").toLowerCase() === "high"
      ).length;

      const values = [events.length, alerts.length, criticalCount + highCount];

      stats.forEach((card, index) => {
        const number = card.querySelector(".stat-number");

        if (number && index < values.length) {
          number.textContent = String(values[index]);
        }
      });
    }

    if (tbody) {

const existingToolbar = content?.querySelector("#incident-filters");
if (existingToolbar) existingToolbar.remove();

const toolbar = document.createElement("div");
toolbar.id = "incident-filters";
toolbar.style.cssText =
  "display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;";

toolbar.innerHTML = `
  <input
    id="incident-search"
    type="search"
    placeholder="Search ID, file path, status..."
    aria-label="Search incidents"
    style="padding:10px;min-width:220px;flex:1;"
  />

  <select
    id="incident-severity"
    aria-label="Filter by severity"
    style="padding:10px;min-width:160px;"
  >
    <option value="all">All severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
  </select>
`;

const incidentPanel = tbody?.closest(".panel");
if (incidentPanel) {
  incidentPanel.insertBefore(toolbar, incidentPanel.querySelector(".table-toolbar") || incidentPanel.firstChild);
}

function filterIncidentRows() {
  const query = (
    content.querySelector("#incident-search")?.value || ""
  ).toLowerCase().trim();

  const severityFilter =
    content.querySelector("#incident-severity")?.value || "all";

  tbody?.querySelectorAll("tr").forEach(row => {
    const text = row.textContent.toLowerCase();
    const rowSeverity = row.querySelector(".tag")?.textContent
      .toLowerCase() || "";

    const matchesSearch = text.includes(query);
    const matchesSeverity =
      severityFilter === "all" || rowSeverity.includes(severityFilter);

    row.hidden = !(matchesSearch && matchesSeverity);
  });
}

toolbar.querySelector("#incident-search")
  .addEventListener("input", filterIncidentRows);

toolbar.querySelector("#incident-severity")
  .addEventListener("change", filterIncidentRows);

      if (events.length === 0) {
        tbody.innerHTML =
          '<tr><td colspan="5">No file events returned by the backend.</td></tr>';
      } else {
        tbody.innerHTML = events.map(event => {
          const timestamp = formatTimestamp(event.timestamp);
          const path = event.path ?? "Unknown path";
          const action = event.action ?? event.event_type ?? "File event";
          const entropy = Number(event.entropy ?? 0).toFixed(2);
          const risk = Number(event.risk_score ?? 0);
          const severity = getSeverityClass(event.severity ?? getRiskLevel(risk));

          return `
            <tr>
              <td>${escapeHTML(timestamp)}</td>
              <td>${escapeHTML(path)}</td>
              <td>${escapeHTML(action)}</td>
              <td>${escapeHTML(entropy)}</td>
              <td><span class="tag ${severity}">${risk}</span></td>
            </tr>
          `;
        }).join("");
      }
    }

    showToast(`Loaded ${events.length} RDRS event(s).`);
  } catch (error) {
    console.error("RDRS detection API error:", error);

    if (badge) badge.textContent = "API OFFLINE";

    if (tbody) {
      tbody.innerHTML =
        '<tr><td colspan="5">Unable to load events. Check that the backend is running.</td></tr>';
    }

    if (note) note.textContent = "Could not retrieve live detection data.";

    showToast("Could not load detection data.");
  }
}

// ============================================================
// LIVE INCIDENTS PAGE
// ============================================================

async function loadLiveIncidents() {
  const badge = content?.querySelector(".panel-badge");
  const tbody = content?.querySelector("#filterable-rows");
  const note = content?.querySelector(".muted-note");
  const cards = content?.querySelectorAll(".stats-grid .stat-card");
  const emptyState = content?.querySelector(".empty-state");

  if (badge) badge.textContent = "LOADING";

  try {
    const response = await apiRequest("/api/incidents?limit=100");
    const incidents = Array.isArray(response)
      ? response
      : response.incidents || [];

    if (badge) badge.textContent = "LIVE API";

    if (note) {
      note.textContent =
        `Showing ${incidents.length} incident(s) from the RDRS backend.`;
    }

    const countStatus = (status) =>
      incidents.filter(
        incident =>
          String(incident.incident_status ?? incident.status ?? "")
            .toLowerCase() === status.toLowerCase()
      ).length;

    const counts = [
      incidents.filter(i =>
        !["resolved", "false positive"].includes(
          String(i.incident_status ?? i.status ?? "").toLowerCase()
        )
      ).length,
      countStatus("Investigating"),
      countStatus("Resolved")
    ];

    cards?.forEach((card, index) => {
      if (index >= counts.length) return;
      const number = card.querySelector(".stat-number");
      const foot = card.querySelector(".stat-foot");
      if (number) number.textContent = String(counts[index]).padStart(2, "0");
      if (foot) foot.textContent = "Live incident records";
    });

    if (tbody) {
      if (incidents.length === 0) {
        tbody.innerHTML =
          '<tr><td colspan="5">No incidents found. Create a test incident inside the sandbox.</td></tr>';
      } else {
        tbody.innerHTML = incidents.map(incident => {
          const id = incident.incident_id ?? incident.id;
          const path = incident.path ?? "Unknown path";
          const risk = Number(incident.risk_score ?? 0);
          const severity = getSeverityClass(incident.severity);
          const status = incident.incident_status ?? incident.status ?? "Open";
          const timestamp = formatTimestamp(incident.timestamp);
          const notes = incident.notes ?? "";

          return `
            <tr>
              <td>${escapeHTML(id)}</td>
              <td class="mono">${escapeHTML(path)}</td>
              <td><span class="tag ${severity}">${escapeHTML(incident.severity ?? "unknown")} · ${risk}</span></td>
              <td>
                <select class="incident-status" data-incident-id="${escapeHTML(id)}">
                  ${["Open", "Investigating", "Resolved", "False Positive"]
                    .map(option =>
                      `<option value="${option}" ${status === option ? "selected" : ""}>${option}</option>`
                    ).join("")}
                </select>
                <textarea class="incident-notes" data-incident-id="${escapeHTML(id)}"
                  placeholder="Investigation notes">${escapeHTML(notes)}</textarea>
                <button class="btn btn-secondary save-incident"
                  data-incident-id="${escapeHTML(id)}" type="button">Save</button>
              </td>
              <td>${escapeHTML(timestamp)}</td>
            </tr>
          `;
        }).join("");

        tbody.querySelectorAll(".save-incident").forEach(button => {
          button.addEventListener("click", async () => {
            const id = button.dataset.incidentId;
            const statusSelect = tbody.querySelector(
              `.incident-status[data-incident-id="${id}"]`
            );
            const notesInput = tbody.querySelector(
              `.incident-notes[data-incident-id="${id}"]`
            );

            button.disabled = true;
            button.textContent = "Saving...";

            try {
              await apiRequest(`/api/incidents/${encodeURIComponent(id)}`, {
                method: "PATCH",
                body: JSON.stringify({
                  status: statusSelect.value,
                  notes: notesInput.value
                })
              });

              showToast(`Incident #${id} updated.`);
              await loadLiveIncidents();
            } catch (error) {
              console.error("Incident update error:", error);
              showToast("Could not update incident. Check the backend.");
              button.disabled = false;
              button.textContent = "Save";
            }
          });
        });
      }
    }

    if (emptyState) {
      emptyState.innerHTML = incidents.length
        ? `<strong>Incidents loaded</strong>${incidents.length} incident record(s) retrieved from the backend.`
        : "<strong>No incidents found</strong>The backend returned an empty incidents list.";
    }

    showToast(`Loaded ${incidents.length} incident(s).`);
  } catch (error) {
    console.error("RDRS incidents API error:", error);

    if (badge) badge.textContent = "API OFFLINE";
    if (tbody) {
      tbody.innerHTML =
        '<tr><td colspan="5">Unable to load incidents. Check the backend.</td></tr>';
    }
    if (note) note.textContent = "Could not retrieve incident data.";

    showToast("Could not load incidents. Check the backend.");
  }
}


// ============================================================
// PAGE RENDERER
// ============================================================

function renderPage(page) {
  if (!content) {
    console.error("Missing #page-content element in the HTML.");
    return;
  }

  activePage = page;
  updateNavigation(page);

  if (page === "overview") {
    content.innerHTML = originalOverview;
  } else if (page === "detection") {
    content.innerHTML = `
      <div class="stats-grid">
        <article class="stat-card blue">
          <div class="stat-top"><span>File Events</span><span class="stat-icon">⌕</span></div>
          <div class="stat-number">—</div>
          <div class="stat-foot">Loading live events</div>
        </article>

        <article class="stat-card amber">
          <div class="stat-top"><span>Alerts</span><span class="stat-icon">!</span></div>
          <div class="stat-number">—</div>
          <div class="stat-foot">Loading live alerts</div>
        </article>

        <article class="stat-card red">
          <div class="stat-top"><span>High / Critical</span><span class="stat-icon">⚠</span></div>
          <div class="stat-number">—</div>
          <div class="stat-foot">Loading risk levels</div>
        </article>
      </div>

      ${tablePage(
        "Live File Events",
        "File activity collected by the sandbox monitor.",
        ["Time", "File Path", "Event", "Entropy", "Risk"],
        [],
        "Refresh Detection"
      )}
    `;
  } else if (page === "incidents") {
    content.innerHTML = `
      <div class="stats-grid">
        <article class="stat-card red">
          <div class="stat-top"><span>Open Incidents</span><span class="stat-icon">!</span></div>
          <div class="stat-number">—</div>
          <div class="stat-foot">Loading from API</div>
        </article>

        <article class="stat-card amber">
          <div class="stat-top"><span>Investigating</span><span class="stat-icon">⌕</span></div>
          <div class="stat-number">—</div>
          <div class="stat-foot">Loading from API</div>
        </article>

        <article class="stat-card green">
          <div class="stat-top"><span>Resolved</span><span class="stat-icon">✓</span></div>
          <div class="stat-number">—</div>
          <div class="stat-foot">Loading from API</div>
        </article>

        <article class="stat-card blue">
          <div class="stat-top"><span>Response Mode</span><span class="stat-icon">◈</span></div>
          <div class="stat-number smaller">Simulation</div>
          <div class="stat-foot">No process termination</div>
        </article>
      </div>

      <div class="section-heading">
        <div>
          <h2>Incident Queue</h2>
          <p>Review sandbox alerts and preserve test evidence safely.</p>
        </div>
      </div>

      ${tablePage(
        "Recent Incidents",
        "Live alert records from the RDRS backend.",
        ["ID", "Title / File Path", "Severity / Risk", "Status", "Detected"],
        [],
        "Refresh Incidents"
      )}
<div style="margin: 12px 0;">
  <button class="btn btn-secondary" id="export-incidents" type="button">
    Export Incidents CSV
  </button>
</div>
      <div class="empty-state">
        <strong>Loading incidents</strong>
        Waiting for the RDRS backend response.
      </div>
    `;
  } else if (page === "intelligence") {
    content.innerHTML = `
      <div class="section-heading">
        <div>
          <h2>Threat Intelligence</h2>
          <p>Indicator management can be connected to the backend next.</p>
        </div>
      </div>

      ${tablePage(
        "Indicators",
        "Illustrative records only; these are not live intelligence feeds.",
        ["Indicator", "Type", "Severity", "Status"],
        [
          ["example.test", "Domain", "Medium", "Demo"],
          ["203.0.113.10", "IP Address", "High", "Demo"]
        ],
        "Export CSV"
      )}

      <div class="empty-state">
        <strong>Demo data</strong>
        The indicators above are examples, not live threat intelligence.
      </div>
    `;
  } else if (page === "tools") {
    content.innerHTML = `
      <div class="section-heading">
        <div>
          <h2>Defensive Tools</h2>
          <p>Operate only on authorized test files inside the sandbox.</p>
        </div>
      </div>

      <div class="stats-grid">
        <article class="stat-card blue">
          <div class="stat-top"><span>Monitor</span><span class="stat-icon">◉</span></div>
          <div class="stat-number smaller">Sandbox</div>
          <div class="stat-foot">File activity monitoring</div>
          <button class="btn btn-secondary" id="monitor-start" type="button">Start Monitor</button>
        </article>

        <article class="stat-card amber">
          <div class="stat-top"><span>Monitoring</span><span class="stat-icon">Ⅱ</span></div>
          <div class="stat-number smaller">Status</div>
          <div class="stat-foot">Check the backend status endpoint</div>
          <button class="btn btn-secondary" id="monitor-status" type="button">Check Status</button>
        </article>

        <article class="stat-card red">
          <div class="stat-top"><span>Stop Monitor</span><span class="stat-icon">■</span></div>
          <div class="stat-number smaller">Safe Stop</div>
          <div class="stat-foot">Stop the sandbox monitor</div>
          <button class="btn btn-secondary" id="monitor-stop" type="button">Stop Monitor</button>
        </article>
      </div>

      <div class="empty-state">
        <strong>Sandbox-only operation</strong>
        These controls do not terminate processes or modify files outside the sandbox.
      </div>
    `;
  } else if (page === "reports") {
    content.innerHTML = `
      <div class="section-heading">
        <div>
          <h2>Security Reports</h2>
          <p>Export live backend events for review.</p>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Event Report</h2>
            <p>Download records returned by the RDRS API.</p>
          </div>
        </div>
        <button class="btn btn-secondary" id="export-events" type="button">Export Events CSV</button>
      </div>
    `;
  } else if (page === "settings") {
    content.innerHTML = `
      <div class="section-heading">
        <div>
          <h2>Application Settings</h2>
          <p>Current local RDRS connection settings.</p>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Backend Connection</h2>
            <p>API endpoint used by this frontend.</p>
          </div>
        </div>
        <p><strong>API URL:</strong> ${escapeHTML(API_BASE)}</p>
        <button class="btn btn-secondary" id="test-api" type="button">Test API Connection</button>
      </div>
    `;
  } else {
    content.innerHTML = `
      <div class="empty-state">
        <strong>Page not found</strong>
        Select a page from the navigation menu.
      </div>
    `;
  }

  bindPageLinks();
  bindTableFilter();
  bindPageActions();

  if (page === "detection") {
    loadLiveDetectionData();
  }

  if (page === "incidents") {
    loadLiveIncidents();
  }

  if (page === "overview") {
    loadOverviewStatus();
  }
}

// ============================================================
// PAGE ACTIONS
// ============================================================

function bindPageActions() {
  const pageAction = content?.querySelector("#page-action");

  if (pageAction) {
    pageAction.addEventListener("click", async () => {
      if (activePage === "detection") {
        await loadLiveDetectionData();
        return;
      }

      if (activePage === "incidents") {
        await loadLiveIncidents();
        return;
      }

      if (activePage === "intelligence") {
        const rows = [...content.querySelectorAll("#filterable-rows tr")];

        const data = rows.map(row => ({
          record: row.innerText
        }));

        downloadCSV("rdrs-indicators-demo.csv", data);
        return;
      }

      showToast("No live export is configured for this page yet.");
    });
  }

  const exportIncidents = content?.querySelector("#export-incidents");

  if (exportIncidents) {
    exportIncidents.addEventListener("click", async () => {
      try {
        const response = await apiRequest("/api/incidents?limit=100");

        const incidents = Array.isArray(response)
          ? response
          : response.incidents || [];

        const rows = incidents.map(item => ({
          incident_id: item.incident_id ?? item.id ?? "",
          event_id: item.event_id ?? "",
          timestamp: item.timestamp ?? "",
          path: item.path ?? "",
          action: item.action ?? "",
          severity: item.severity ?? "",
          risk_score: item.risk_score ?? "",
          status: item.incident_status ?? item.status ?? "",
          notes: item.notes ?? "",
          reasons: Array.isArray(item.reasons)
            ? item.reasons.join("; ")
            : item.reasons ?? ""
        }));

        downloadCSV("rdrs-incidents.csv", rows);
      } catch (error) {
        console.error("Export incidents error:", error);
        showToast("Could not export incidents. Check the backend.");
      }
    });
  }

  const exportEvents = content?.querySelector("#export-events");

  if (exportEvents) {
    exportEvents.addEventListener("click", async () => {
      try {
        const response = await apiRequest("/api/events?limit=100");
        const events = Array.isArray(response)
          ? response
          : response.events || response.records || [];

        downloadCSV("rdrs-events.csv", events);
      } catch (error) {
        console.error("Export events error:", error);
        showToast("Could not export events. Check the backend.");
      }
    });
  }

  const startButton = content?.querySelector("#monitor-start");

  if (startButton) {
    startButton.addEventListener("click", async () => {
      try {
        const result = await apiRequest("/api/monitor/start", {
          method: "POST"
        });

        showToast(result.message || "Monitor start request sent.");
      } catch (error) {
        console.error("Monitor start error:", error);
        showToast("Could not start the monitor.");
      }
    });
  }

  const stopButton = content?.querySelector("#monitor-stop");

  if (stopButton) {
    stopButton.addEventListener("click", async () => {
      try {
        const result = await apiRequest("/api/monitor/stop", {
          method: "POST"
        });

        showToast(result.message || "Monitor stop request sent.");
      } catch (error) {
        console.error("Monitor stop error:", error);
        showToast("Could not stop the monitor.");
      }
    });
  }

  const statusButton = content?.querySelector("#monitor-status");

  if (statusButton) {
    statusButton.addEventListener("click", async () => {
      try {
        const result = await apiRequest("/api/status");

        showToast(`Monitor status retrieved: ${JSON.stringify(result)}`);
      } catch (error) {
        console.error("Monitor status error:", error);
        showToast("Could not retrieve monitor status.");
      }
    });
  }

  const testApi = content?.querySelector("#test-api");

  if (testApi) {
    testApi.addEventListener("click", async () => {
      try {
        const result = await apiRequest("/api/health");

        showToast(`API connected: ${result.status || "healthy"}`);
      } catch (error) {
        console.error("API test error:", error);
        showToast("API connection failed.");
      }
    });
  }
}

// ============================================================
// GLOBAL REFRESH BUTTON
// ============================================================

function bindRefreshButton() {
  const refreshButton = document.querySelector("#refresh-button");

  if (!refreshButton || refreshButton.dataset.rdrsBound === "true") {
    return;
  }

  refreshButton.dataset.rdrsBound = "true";

  refreshButton.addEventListener("click", async () => {
    if (activePage === "detection") {
      await loadLiveDetectionData();
    } else if (activePage === "incidents") {
      await loadLiveIncidents();
    } else if (activePage === "overview") {
      await loadOverviewStatus();
      showToast("Overview refreshed.");
    } else {
      try {
        await apiRequest("/api/health");
        showToast("RDRS API is online.");
      } catch (error) {
        showToast("RDRS API is offline.");
      }
    }
  });
}

// ============================================================
// INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {
  bindPageLinks();
  bindRefreshButton();

  if (content) {
    renderPage("overview");
  }

  console.log("RDRS frontend initialized.");
});
