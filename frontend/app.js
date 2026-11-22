
"use strict";

// RDRS - Ransomware Detection and Response System
// Frontend JavaScript

const API_BASE = "";

const content = document.getElementById("page-content");
const toast = document.getElementById("toast");

let toastTimer = null;
let activePage = "overview";

window.overviewRefreshTimer = null;

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
  const method = (options.method || "GET").toUpperCase();

  const headers = {
    ...(options.headers || {})
  };

  if (method !== "GET" && options.body) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    method,
    headers,
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error(`API request failed: HTTP ${response.status}`);
  }

  return response.json();
}
// ============================================================
// AUTHENTICATION GATE
// ============================================================

let rdrsAuthenticated = false;


let rdrsAuthMode = "login";

function showLoginScreen(message = "", mode = rdrsAuthMode) {
  rdrsAuthMode = mode;
  const appShell = document.querySelector(".app-shell");
  if (appShell) appShell.style.display = "none";

  let screen = document.getElementById("rdrs-login-screen");
  if (!screen) {
    screen = document.createElement("section");
    screen.id = "rdrs-login-screen";
    screen.style.cssText = "min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#0b0b18;color:#f5f5ff;font-family:Inter,system-ui,sans-serif;";
    document.body.appendChild(screen);
  }

  const signup = mode === "signup";
  const field = "box-sizing:border-box;width:100%;padding:12px;border:1px solid #44445f;border-radius:8px;background:#101021;color:white;margin-bottom:14px;";
  const label = "display:block;margin-bottom:7px;font-size:14px;";
  const passwordInput = (id, name, text, autocomplete) => `
    <label for="${id}" style="${label}">${text}</label>
    <div style="position:relative;margin-bottom:14px">
      <input id="${id}" name="${name}" type="password" autocomplete="${autocomplete}" required style="${field}margin:0;padding-right:75px">
      <button type="button" data-toggle-password="${id}" style="position:absolute;right:8px;top:8px;padding:4px 8px;background:#292941;color:#cfc5ff;border:0;border-radius:5px;cursor:pointer">Show</button>
    </div>`;

  screen.innerHTML = `
    <div style="width:100%;max-width:420px;background:#17172b;border:1px solid #343450;border-radius:16px;padding:32px;box-shadow:0 20px 60px rgba(0,0,0,.35)">
      <div style="font-size:13px;letter-spacing:2px;color:#b9a0ff;margin-bottom:10px">RDRS · DEFENSIVE SECURITY</div>
      <h1 style="margin:0 0 8px;font-size:28px">${signup ? "Create account" : "Sign in"}</h1>
      <p style="margin:0 0 24px;color:#b8b8ce">${signup ? "Create an account for your security dashboard." : "Sign in to access your security dashboard."}</p>
      <form id="rdrs-login-form">
        ${signup ? `
          <label for="rdrs-full-name" style="${label}">Full name</label>
          <input id="rdrs-full-name" name="full_name" autocomplete="name" required minlength="2" style="${field}">
          <label for="rdrs-email" style="${label}">Email</label>
          <input id="rdrs-email" name="email" type="email" autocomplete="email" required style="${field}">
        ` : ""}
        <label for="rdrs-username" style="${label}">Username</label>
        <input id="rdrs-username" name="username" autocomplete="username" required minlength="3" maxlength="32" style="${field}">
        ${passwordInput("rdrs-password", "password", "Password", signup ? "new-password" : "current-password")}
        ${signup ? `
          <div id="rdrs-password-strength" style="font-size:12px;color:#b8b8ce;margin:-4px 0 12px">Minimum 8 characters</div>
          ${passwordInput("rdrs-confirm-password", "confirm_password", "Confirm password", "new-password")}
        ` : ""}
        <p id="rdrs-login-error" role="alert" style="min-height:20px;color:#ff8585;font-size:13px;margin:0 0 12px">${message}</p>
        <button type="submit" style="width:100%;padding:12px;border:0;border-radius:8px;background:#8057e8;color:white;font-weight:600;cursor:pointer">${signup ? "Create account" : "Sign in"}</button>
      </form>
      <button type="button" id="rdrs-auth-switch" style="width:100%;margin-top:14px;padding:10px;background:transparent;color:#c6b5ff;border:1px solid #44445f;border-radius:8px;cursor:pointer">${signup ? "Already have an account? Sign in" : "New here? Create an account"}</button>
      <p style="font-size:12px;color:#9292aa;margin:20px 0 0">Authorized local sandbox access only.</p>
    </div>`;

  screen.style.display = "flex";
  screen.querySelector("#rdrs-login-form").addEventListener("submit", handleRdrsLogin);

  screen.querySelector("#rdrs-auth-switch").addEventListener("click", () => {
    showLoginScreen("", signup ? "login" : "signup");
  });

  screen.querySelectorAll("[data-toggle-password]").forEach(toggle => {
    toggle.addEventListener("click", () => {
      const input = screen.querySelector(`#${toggle.dataset.togglePassword}`);
      if (!input) return;
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      toggle.textContent = show ? "Hide" : "Show";
    });
  });

  const pass = screen.querySelector("#rdrs-password");
  const strength = screen.querySelector("#rdrs-password-strength");
  pass?.addEventListener("input", () => {
    if (!strength) return;
    const v = pass.value;
    let score = 0;
    if (v.length >= 8) score++;
    if (v.length >= 12) score++;
    if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
    if (/\d/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;
    const levels = ["Weak", "Weak", "Fair", "Good", "Strong", "Strong"];
    strength.textContent = v ? "Password strength: " + levels[score] : "Minimum 8 characters";
    strength.style.color = score >= 4 ? "#75e0a2" : score >= 2 ? "#f0c36a" : "#ff8585";
  });

  screen.querySelector(signup ? "#rdrs-full-name" : "#rdrs-username")?.focus();
}

function hideLoginScreen() {
  document.getElementById("rdrs-login-screen")?.remove();
  const appShell = document.querySelector(".app-shell");
  if (appShell) appShell.style.display = "";
}

async function handleRdrsLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type='submit']");
  const error = document.getElementById("rdrs-login-error");
  const username = form.elements.username.value.trim();
  const password = form.elements.password.value;
  const signup = rdrsAuthMode === "signup";

  if (signup) {
    const fullName = form.elements.full_name.value.trim();
    const email = form.elements.email.value.trim();
    const confirmPassword = form.elements.confirm_password.value;

    if (password.length < 8) {
      error.textContent = "Password must be at least 8 characters.";
      return;
    }
    if (password !== confirmPassword) {
      error.textContent = "Passwords do not match.";
      return;
    }
    if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {
      error.textContent = "Username must be 3–32 letters, numbers, or underscores.";
      return;
    }

    button.disabled = true;
    button.textContent = "Creating account…";
    error.textContent = "";

    try {
      const response = await fetch(`${API_BASE}/api/signup`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        credentials: "include",
        body: JSON.stringify({
          full_name: fullName,
          username,
          email,
          password,
          confirm_password: confirmPassword
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        showLoginScreen(data.detail || "Unable to create account.", "signup");
        return;
      }
      showLoginScreen(data.message || "Account created. Please sign in.", "login");
    } catch (err) {
      console.error("RDRS signup error:", err);
      showLoginScreen("Unable to reach the backend. Check your connection.", "signup");
    } finally {
      const currentButton = document.querySelector("#rdrs-login-form button[type='submit']");
      if (currentButton) currentButton.disabled = false;
    }
    return;
  }

  button.disabled = true;
  button.textContent = "Signing in…";
  error.textContent = "";

  try {
    const response = await fetch(`${API_BASE}/api/login`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      credentials: "include",
      body: JSON.stringify({username, password})
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      showLoginScreen(data.detail || (response.status === 503 ? "Authentication is not configured on the backend." : "Invalid username or password."), "login");
      return;
    }

    rdrsAuthenticated = true;
    hideLoginScreen();
    form.reset();
    bindPageLinks();
    bindRefreshButton();
    renderPage("overview");
    showToast("Login successful.");
  } catch (err) {
    console.error("RDRS login error:", err);
    showLoginScreen("Unable to reach the backend. Check that RDRS API is running.", "login");
  } finally {
    const currentButton = document.querySelector("#rdrs-login-form button[type='submit']");
    if (currentButton) {
      currentButton.disabled = false;
      currentButton.textContent = "Sign in";
    }
  }
}

async function rdrsLogout() {
  try {
    await apiRequest("/api/logout", {
      method: "POST"
    });
  } catch (err) {
    console.warn("RDRS logout request failed:", err);
  }

  rdrsAuthenticated = false;

  showLoginScreen("You have been signed out.");
}


async function checkRdrsSession() {
  const appShell = document.querySelector(".app-shell");

  if (appShell) appShell.style.display = "none";

  try {
    await apiRequest("/api/status");

    rdrsAuthenticated = true;

    hideLoginScreen();

    bindPageLinks();
    bindRefreshButton();

    renderPage("overview");

  } catch (err) {
    rdrsAuthenticated = false;
    showLoginScreen();
  }
}


function addRdrsLogoutButton() {
  return;
}

// ============================================================
// END AUTHENTICATION GATE
// ============================================================
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


async function RecentEvents() {
  const setText = (selector, value) => {
    const element = document.querySelector(selector);
    if (element) element.textContent = value;
  };

  try {
    const [status, eventsResponse, incidentsResponse] = await Promise.all([
      apiRequest("/api/status"),
      apiRequest("/api/events?limit=100"),
      apiRequest("/api/incidents?limit=100")
    ]);

    const events = Array.isArray(eventsResponse)
      ? eventsResponse
      : eventsResponse.events || eventsResponse.records || [];

    const incidents = Array.isArray(incidentsResponse)
      ? incidentsResponse
      : incidentsResponse.incidents || [];

    const highRiskCount = events.filter(event =>
      Number(event.risk_score ?? 0) >= 20
    ).length;

    const openCount = incidents.filter(incident =>
      !["resolved", "closed"].includes(
        String(incident.status ?? "").toLowerCase()
      )
    ).length;

    setText("#overview-critical", highRiskCount);
    setText("#overview-open-alerts", openCount);
    setText("#overview-folders", status.sandbox ? "1" : "0");

    // Check backend, monitor, and sandbox independently.
    const backendConnected = Boolean(status.service);
    const monitoringRunning =
      String(status.monitoring ?? "").toLowerCase() === "running";
    const sandboxAvailable = Boolean(status.sandbox);

    let health = "Check";
    let healthNote = "Backend connected · Review system status";

    if (backendConnected && monitoringRunning && sandboxAvailable) {
      health = "Healthy";
      healthNote = "Backend connected · Monitor running · Sandbox ready";
    } else if (backendConnected && !monitoringRunning) {
      healthNote = sandboxAvailable
        ? "Backend connected · Monitor is not running"
        : "Backend connected · Monitor stopped · Sandbox unavailable";
    } else if (backendConnected && !sandboxAvailable) {
      healthNote = "Backend connected · Sandbox path unavailable";
    }
    setText("#overview-health", health);
    const checkedAt = new Date().toLocaleTimeString();

setText(
  "#overview-health-note",
  monitoringRunning && sandboxAvailable
    ? `Backend connected · Monitor running · Sandbox ready · Last checked: ${checkedAt}`
    : `System check needs attention · Last checked: ${checkedAt}`
);

    const badge = document.querySelector("#api-status");
    if (badge) {
      badge.textContent = "API ONLINE";
      badge.classList.add("online");
      badge.classList.remove("offline");
    }

    console.log("RDRS system health:", {
      backendConnected,
      monitoringRunning,
      sandboxAvailable
    });

  } catch (error) {
    console.error("Overview status error:", error);

    setText("#overview-critical", "—");
    setText("#overview-open-alerts", "—");
    setText("#overview-folders", "—");
    setText("#overview-health", "Offline");
    setText("#overview-health-note", "Backend unavailable");

    const badge = document.querySelector("#api-status");
    if (badge) {
      badge.textContent = "API OFFLINE";
      badge.classList.add("offline");
      badge.classList.remove("online");
    }
  }
}
async function loadRecentOverviewEvents() {
  const tbody = document.querySelector("#overview-events-body");
  if (!tbody) return;

  try {
    const response = await apiRequest("/api/events?limit=5");
    const events = Array.isArray(response)
      ? response
      : response.events || response.records || [];

    if (events.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="4">No events found.</td></tr>';
      return;
    }

    tbody.innerHTML = events.slice(0, 5).map(event => {
      const time = formatTimestamp(event.timestamp);
      const action = event.action ?? event.event_type ?? "File event";
      const path = event.path ?? "Unknown path";
      const risk = Number(event.risk_score ?? 0);
      const severity = String(
        event.severity ?? getRiskLevel(risk)
      ).toLowerCase();

      const tagClass = ["critical", "high", "medium", "low"]
        .includes(severity) ? severity : "low";
return `
  <tr
    class="clickable-event-row"
    style="cursor: pointer;"
    title="Click to view event details"
  >
          <td>${escapeHTML(String(time))}</td>
          <td>${escapeHTML(String(action))}</td>
          <td class="mono">${escapeHTML(String(path))}</td>
        <td>
  <span class="tag ${tagClass}">
    ${escapeHTML(severity.toUpperCase())} · ${risk}
  </span>
</td>
        </tr>
      `;
    }).join("");
    tbody.querySelectorAll(".clickable-event-row").forEach((row, index) => {
  row.addEventListener("click", () => {
    showOverviewEventDetails(events[index]);
  });
});
  } catch (error) {
    console.error("Recent events loading failed:", error);
    tbody.innerHTML =
      '<tr><td colspan="4">Unable to load live events.</td></tr>';
  }
}
function showOverviewEventDetails(event) {
  const existingModal = document.querySelector("#event-details-modal");
  if (existingModal) existingModal.remove();

  const modal = document.createElement("div");
  modal.id = "event-details-modal";

  modal.style.cssText = `
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.75);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    padding: 20px;
  `;

  const details = [
    ["Event ID", event.id ?? "N/A"],
    ["File Path", event.path ?? "Unknown"],
    ["Action", event.action ?? "Unknown"],
    ["Timestamp", formatTimestamp(event.timestamp)],
    ["Risk Score", event.risk_score ?? 0],
    ["Severity", event.severity ?? "Unknown"],
    ["Confidence Score", `${event.confidence_score ?? 10}/100`],
    ["Confidence Level", event.confidence_level ?? "low"],
    [
      "Detection Reasons",
      Array.isArray(event.reasons)
        ? event.reasons.join(", ") || "No reasons recorded"
        : event.reasons ?? "No reasons recorded"
    ]
  ];

  const content = document.createElement("div");

  content.style.cssText = `
    background: #17172b;
    color: white;
    padding: 24px;
    border-radius: 12px;
    width: 100%;
    max-width: 600px;
    max-height: 80vh;
    overflow-y: auto;
  `;

  const heading = document.createElement("h2");
  heading.textContent = "Event Details";
  content.appendChild(heading);

  // Existing event details
  details.forEach(([label, value]) => {
    const item = document.createElement("p");

    const strong = document.createElement("strong");
    strong.textContent = `${label}: `;

    item.appendChild(strong);
    item.appendChild(document.createTextNode(String(value)));

    content.appendChild(item);
  });

  // ============================================================
  // RISK SCORE BREAKDOWN
  // ============================================================

  const breakdown = event.risk_breakdown;

  const breakdownSection = document.createElement("div");

  breakdownSection.style.cssText = `
    margin-top: 24px;
    padding: 16px;
    background: #22223a;
    border: 1px solid #393957;
    border-radius: 10px;
  `;

  const breakdownHeading = document.createElement("h3");
  breakdownHeading.textContent = "Risk Score Breakdown";
  breakdownHeading.style.marginTop = "0";

  breakdownSection.appendChild(breakdownHeading);

  if (breakdown && typeof breakdown === "object") {
    const scoreSummary = document.createElement("div");

    scoreSummary.style.cssText = `
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    `;

    const scoreItems = [
      ["Raw Score", breakdown.raw_score ?? "N/A"],
      ["Final Score", breakdown.final_score ?? event.risk_score ?? "N/A"],
      [
        "Score Cap",
        breakdown.cap_applied ? "Applied (100)" : "Not applied"
      ]
    ];

    scoreItems.forEach(([label, value]) => {
      const card = document.createElement("div");

      card.style.cssText = `
        background: #17172b;
        padding: 12px;
        border-radius: 8px;
        flex: 1;
        min-width: 100px;
      `;

      const cardLabel = document.createElement("div");
      cardLabel.textContent = label;
      cardLabel.style.cssText = `
        color: #a7a7c4;
        font-size: 12px;
        margin-bottom: 6px;
      `;

      const cardValue = document.createElement("strong");
      cardValue.textContent = String(value);

      card.appendChild(cardLabel);
      card.appendChild(cardValue);
      scoreSummary.appendChild(card);
    });

    breakdownSection.appendChild(scoreSummary);

    // Individual scoring contributions
    const contributions = Array.isArray(breakdown.contributions)
      ? breakdown.contributions
      : [];

    const contributionHeading = document.createElement("h4");
    contributionHeading.textContent = "Score Contributions";
    breakdownSection.appendChild(contributionHeading);

    if (contributions.length > 0) {
      contributions.forEach((contribution) => {
        const item = document.createElement("div");

        item.style.cssText = `
          padding: 12px;
          margin-bottom: 8px;
          background: #17172b;
          border-radius: 8px;
          border-left: 3px solid #8b5cf6;
        `;

        const indicator = document.createElement("strong");
        indicator.textContent = String(
          contribution.indicator ?? "Unknown Indicator"
        );

        const points = document.createElement("span");
        points.textContent = `+${contribution.points ?? 0} points`;
        points.style.cssText = `
          float: right;
          color: #c4a5ff;
          font-weight: bold;
        `;

        const description = document.createElement("p");
        description.textContent = String(
          contribution.description ?? "No description available"
        );

        description.style.cssText = `
          margin: 8px 0 0;
          color: #b9b9ce;
          font-size: 13px;
        `;

        item.appendChild(indicator);
        item.appendChild(points);
        item.appendChild(description);

        breakdownSection.appendChild(item);
      });
    } else {
      const noContributions = document.createElement("p");
      noContributions.textContent = "No individual score contributions recorded.";
      breakdownSection.appendChild(noContributions);
    }
  } else {
    const unavailable = document.createElement("p");
    unavailable.textContent = "Risk breakdown is not available for this event.";
    breakdownSection.appendChild(unavailable);
  }

  content.appendChild(breakdownSection);

  // ============================================================
  // CLOSE BUTTON
  // ============================================================

  const closeButton = document.createElement("button");
  closeButton.textContent = "Close";

  closeButton.style.cssText = `
    padding: 10px 20px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    margin-top: 16px;
  `;

  closeButton.addEventListener("click", () => modal.remove());

  content.appendChild(closeButton);
  modal.appendChild(content);

  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.remove();
  });

  // Close modal using Escape key
  const handleEscape = (e) => {
    if (e.key === "Escape" && document.querySelector("#event-details-modal") === modal) {
      modal.remove();
      document.removeEventListener("keydown", handleEscape);
    }
  };

  document.addEventListener("keydown", handleEscape);

  document.body.appendChild(modal);
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

    // Update statistics
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
      // Recreate toolbar on refresh
      const existingToolbar = content.querySelector("#incident-filters");
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
          aria-label="Search events"
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

      const incidentPanel = tbody.closest(".panel");

      if (incidentPanel) {
        incidentPanel.insertBefore(
          toolbar,
          incidentPanel.querySelector(".table-toolbar") ||
            incidentPanel.firstChild
        );
      }

      // Search and severity filtering
      function filterIncidentRows() {
        const query = (
          content.querySelector("#incident-search")?.value || ""
        ).toLowerCase().trim();

        const severityFilter =
          content.querySelector("#incident-severity")?.value || "all";

        tbody.querySelectorAll("tr[data-event-index]").forEach(row => {
          const text = row.textContent.toLowerCase();

          const rowSeverity = row.querySelector(".tag")?.textContent
            .toLowerCase() || "";

          const matchesSearch = text.includes(query);

          const matchesSeverity =
            severityFilter === "all" ||
            rowSeverity.includes(severityFilter);

          row.hidden = !(matchesSearch && matchesSeverity);
        });
      }

      toolbar.querySelector("#incident-search")
        .addEventListener("input", filterIncidentRows);

      toolbar.querySelector("#incident-severity")
        .addEventListener("change", filterIncidentRows);

      // Render events table
      if (events.length === 0) {
        tbody.innerHTML =
          '<tr><td colspan="6">No file events returned by the backend.</td></tr>';
      } else {
        tbody.innerHTML = events.map((event, index) => {
          const timestamp = formatTimestamp(event.timestamp);
          const path = event.path ?? "Unknown path";
          const action = event.action ?? event.event_type ?? "File event";
          const entropy = Number(event.entropy ?? 0).toFixed(2);
          const risk = Number(event.risk_score ?? 0);

          const severity = getSeverityClass(
            event.severity ?? getRiskLevel(risk)
          );

          const confidenceScore = Number(event.confidence_score ?? 10);

          const confidenceLevel = String(
            event.confidence_level ?? "low"
          ).toUpperCase();

          return `
            <tr
              data-event-index="${index}"
              style="cursor:pointer;"
              title="Click to view event details and risk breakdown"
            >
              <td>${escapeHTML(timestamp)}</td>
              <td>${escapeHTML(path)}</td>
              <td>${escapeHTML(action)}</td>
              <td>${escapeHTML(entropy)}</td>
              <td>
                <span class="tag ${severity}">${risk}</span>
              </td>
              <td>
                ${escapeHTML(`${confidenceScore}/100 · ${confidenceLevel}`)}
              </td>
            </tr>
          `;
        }).join("");

        // Click a row to open Risk Score Breakdown
        tbody.querySelectorAll("tr[data-event-index]").forEach(row => {
          row.addEventListener("click", () => {
            const index = Number(row.dataset.eventIndex);

            if (!Number.isInteger(index) || !events[index]) {
              return;
            }

            showOverviewEventDetails(events[index]);
          });
        });
      }
    }

    showToast(`Loaded ${events.length} RDRS event(s).`);

  } catch (error) {
    console.error("RDRS detection API error:", error);

    if (badge) badge.textContent = "API OFFLINE";

    if (tbody) {
      tbody.innerHTML =
        '<tr><td colspan="6">Unable to load events. Check that the backend is running.</td></tr>';
    }

    if (note) {
      note.textContent = "Could not retrieve live detection data.";
    }

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
          '<tr><td colspan="6">No incidents found. Create a test incident inside the sandbox.</td></tr>';
      } else {
        tbody.innerHTML = incidents.map(incident => {
          const id = incident.incident_id ?? incident.id;
          const path = incident.path ?? "Unknown path";
          const risk = Number(incident.risk_score ?? 0);
          const severity = getSeverityClass(incident.severity);
          const confidenceScore = Number(incident.confidence_score ?? 10);
          const confidenceLevel = String(
            incident.confidence_level ?? "low"
          ).toUpperCase();
          const status = incident.incident_status ?? incident.status ?? "Open";
          const timestamp = formatTimestamp(incident.timestamp);
          const notes = incident.notes ?? "";

          return `
            <tr>
              <td>${escapeHTML(id)}</td>
              <td class="mono">${escapeHTML(path)}</td>
              <td>
                <span class="tag ${severity}">
                  ${escapeHTML(incident.severity ?? "unknown")} · ${risk}
                </span>
              </td>
              <td>${confidenceScore}/100 · ${confidenceLevel}</td>
              <td>
                <select class="incident-status" data-incident-id="${escapeHTML(id)}">
                  ${["Open", "Investigating", "Resolved", "False Positive"]
                    .map(option =>
                      `<option value="${option}" ${status === option ? "selected" : ""}>${option}</option>`
                    ).join("")}
                </select>

                <textarea class="incident-notes"
                  data-incident-id="${escapeHTML(id)}"
                  placeholder="Investigation notes">${escapeHTML(notes)}</textarea>

                <button class="btn btn-secondary save-incident"
                  data-incident-id="${escapeHTML(id)}"
                  type="button">Save</button>
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
        '<tr><td colspan="6">Unable to load incidents. Check the backend.</td></tr>';
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

// Stop any previous overview refresh timer.
if (window.overviewRefreshTimer !== null) {
  clearInterval(window.overviewRefreshTimer);
  window.overviewRefreshTimer = null;
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
        ["Time", "File Path", "Event", "Entropy", "Risk", "Confidence"],
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
<div class="incidents-export-actions">
  <button class="btn btn-secondary primary-action" id="export-incidents" type="button">
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
        <div class="settings-logout-panel">
          <div>
            <h2>Account</h2>
            <p class="muted-note">End your current RDRS session.</p>
          </div>
          <button class="btn btn-secondary" id="rdrs-logout-button" type="button">Logout</button>
        </div>
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
  RecentEvents();
  loadRecentOverviewEvents();
window.overviewRefreshTimer = setInterval(async () => {
    if (activePage !== "overview") return;

    await Promise.all([
      RecentEvents(),
      loadRecentOverviewEvents()
    ]);

    console.log("RDRS overview automatically refreshed.");
  }, 10000);
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

  const settingsLogout = content?.querySelector("#rdrs-logout-button");
  if (settingsLogout) {
    settingsLogout.addEventListener("click", rdrsLogout);
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
  await RecentEvents();
  await loadRecentOverviewEvents();
  await loadOverviewStatus();
  showToast("Overview refreshed.");
}else {
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

  addRdrsLogoutButton();
  checkRdrsSession();

  console.log("RDRS frontend initialized.");
});
