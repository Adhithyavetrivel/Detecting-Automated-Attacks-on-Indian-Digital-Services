/**
 * NetSentinel dashboard client.
 *
 * Plain JS + fetch — no build step, so this file can be opened directly
 * or served by FastAPI's StaticFiles with zero tooling.
 */

const TOKEN_KEY = "netsentinel_token";
const token = localStorage.getItem(TOKEN_KEY);

if (!token) {
  window.location.href = "login.html";
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: `Bearer ${token}`,
    },
  });
  if (res.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.href = "login.html";
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${await res.text()}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

// --- Charts -----------------------------------------------------------

const trafficChart = new Chart(document.getElementById("traffic-chart"), {
  type: "line",
  data: {
    labels: [],
    datasets: [
      { label: "Packets/sec", data: [], borderColor: "#3fb6ff", tension: 0.3, pointRadius: 0 },
      { label: "KB/sec", data: [], borderColor: "#2ecc71", tension: 0.3, pointRadius: 0 },
    ],
  },
  options: {
    responsive: true,
    scales: {
      x: { ticks: { color: "#8b98a5" }, grid: { color: "#1f2a37" } },
      y: { ticks: { color: "#8b98a5" }, grid: { color: "#1f2a37" } },
    },
    plugins: { legend: { labels: { color: "#e6edf3" } } },
  },
});

const protocolChart = new Chart(document.getElementById("protocol-chart"), {
  type: "doughnut",
  data: {
    labels: ["TCP", "UDP", "ICMP", "Other"],
    datasets: [{ data: [0, 0, 0, 0], backgroundColor: ["#3fb6ff", "#2ecc71", "#f5a623", "#8b98a5"] }],
  },
  options: { plugins: { legend: { labels: { color: "#e6edf3" } } } },
});

// --- Renderers ----------------------------------------------------------

function renderSummary(summary) {
  document.getElementById("tile-devices").textContent = summary.total_devices;
  document.getElementById("tile-online").textContent = summary.online_devices;
  document.getElementById("tile-offline").textContent = summary.offline_devices;
  document.getElementById("tile-alerts").textContent = summary.open_alerts;
}

function renderDevices(devices) {
  const tbody = document.querySelector("#device-table tbody");
  tbody.innerHTML = "";
  for (const d of devices) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${d.hostname || "—"}</td>
      <td>${d.ip_address}</td>
      <td>${d.mac_address || "—"}</td>
      <td>${d.latency_ms != null ? d.latency_ms.toFixed(1) + " ms" : "—"}</td>
      <td><span class="status-badge status-${d.status}">${d.status}</span></td>
    `;
    tbody.appendChild(tr);
  }
}

function renderAlerts(alerts) {
  const tbody = document.querySelector("#alert-table tbody");
  tbody.innerHTML = "";
  for (const a of alerts) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
      <td>${a.alert_type}</td>
      <td>${a.source_ip || "—"}</td>
      <td>${a.description}</td>
      <td>${new Date(a.timestamp + "Z").toLocaleString()}</td>
      <td>${a.status}</td>
      <td>${a.status === "OPEN" ? `<button class="link-btn" data-id="${a.id}">Resolve</button>` : ""}</td>
    `;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll("button[data-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await api(`/api/alerts/${btn.dataset.id}/resolve`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resolved_by: "dashboard-user" }),
      });
      refreshAll();
    });
  });
}

function renderTrafficChart(records) {
  const ordered = [...records].reverse();
  trafficChart.data.labels = ordered.map((r) => new Date(r.window_start + "Z").toLocaleTimeString());
  trafficChart.data.datasets[0].data = ordered.map((r) => r.packets_per_second);
  trafficChart.data.datasets[1].data = ordered.map((r) => r.bytes_per_second / 1024);
  trafficChart.update();

  const totals = ordered.reduce(
    (acc, r) => {
      acc.tcp += r.tcp_count;
      acc.udp += r.udp_count;
      acc.icmp += r.icmp_count;
      acc.other += r.other_count;
      return acc;
    },
    { tcp: 0, udp: 0, icmp: 0, other: 0 }
  );
  protocolChart.data.datasets[0].data = [totals.tcp, totals.udp, totals.icmp, totals.other];
  protocolChart.update();
}

// --- Actions ------------------------------------------------------------

async function refreshAll() {
  try {
    const [summary, devices, alerts, traffic] = await Promise.all([
      api("/api/metrics/summary"),
      api("/api/devices"),
      api(buildAlertsUrl()),
      api("/api/traffic?limit=30"),
    ]);
    renderSummary(summary);
    renderDevices(devices);
    renderAlerts(alerts);
    renderTrafficChart(traffic);
  } catch (err) {
    console.error("Dashboard refresh failed:", err);
  }
}

function buildAlertsUrl() {
  const status = document.getElementById("alert-status-filter").value;
  const search = document.getElementById("alert-search").value;
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (search) params.set("search", search);
  return `/api/alerts?${params.toString()}`;
}

document.getElementById("scan-btn").addEventListener("click", async () => {
  await api("/api/devices/scan", { method: "POST" });
  refreshAll();
});

document.getElementById("capture-btn").addEventListener("click", async () => {
  await api("/api/monitoring/capture", { method: "POST" });
  refreshAll();
});

let monitoring = false;
document.getElementById("monitor-toggle").addEventListener("click", async () => {
  const result = await api(`/api/monitoring/${monitoring ? "stop" : "start"}`, { method: "POST" });
  monitoring = !monitoring;
  document.getElementById("monitor-toggle").textContent = monitoring ? "Stop Monitoring" : "Start Monitoring";
});

document.getElementById("logout-btn").addEventListener("click", () => {
  localStorage.removeItem(TOKEN_KEY);
  window.location.href = "login.html";
});

document.getElementById("alert-status-filter").addEventListener("change", refreshAll);
document.getElementById("alert-search").addEventListener("input", () => {
  clearTimeout(window._searchDebounce);
  window._searchDebounce = setTimeout(refreshAll, 400);
});

// --- Init ---
api("/api/auth/me").then((user) => {
  document.getElementById("current-user").textContent = `${user.username} (${user.role})`;
});
refreshAll();
setInterval(refreshAll, 10000); // periodic refresh, no full page reload
