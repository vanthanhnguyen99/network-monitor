const params = new URLSearchParams(window.location.search);
const token = params.get("token") || "";

const state = {
  source: localStorage.getItem("netmon-source") || "live",
  integrations: null,
  summary: null,
  devices: [],
  events: [],
  attacks: [],
  deviceTraffic24h: [],
  liveHistory: [],
  lastUpdatedAt: null,
  socket: null,
  fastInFlight: false,
  slowInFlight: false,
};

const HISTORY_LIMIT = 180;
const FAST_REFRESH_MS = 1000;
const SLOW_REFRESH_MS = 8000;
const PALETTE = ["#73bf69", "#5794f2", "#f2cc0c", "#ff9830", "#b877d9", "#56a64b", "#f2495c", "#8ab8ff"];

function apiUrl(path) {
  if (!token) return path;
  const joiner = path.includes("?") ? "&" : "?";
  return `${path}${joiner}token=${encodeURIComponent(token)}`;
}

async function fetchJson(path) {
  const response = await fetch(apiUrl(path), { cache: "no-store" });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

function itemsOf(payload) {
  return Array.isArray(payload) ? payload : payload?.items || [];
}

function sourceQuery() {
  return `source=${encodeURIComponent(state.source)}`;
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function clearNode(node) {
  while (node && node.firstChild) node.removeChild(node.firstChild);
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function emptyCell(text, colSpan) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = colSpan;
  cell.className = "empty";
  cell.textContent = text;
  row.appendChild(cell);
  return row;
}

function emptyNode(text) {
  const node = document.createElement("div");
  node.className = "empty";
  node.textContent = text;
  return node;
}

function formatRate(value) {
  const rate = Number(value || 0);
  if (rate >= 1_000_000_000) return `${(rate / 1_000_000_000).toFixed(2)} Gb/s`;
  if (rate >= 1_000_000) return `${(rate / 1_000_000).toFixed(2)} Mb/s`;
  if (rate >= 1_000) return `${(rate / 1_000).toFixed(1)} Kb/s`;
  return `${Math.round(rate)} b/s`;
}

function axisRate(value) {
  const rate = Number(value || 0);
  if (rate >= 1_000_000) return `${(rate / 1_000_000).toFixed(0)} Mb/s`;
  if (rate >= 1_000) return `${Math.round(rate / 1_000)} Kb/s`;
  return `${Math.round(rate)} b/s`;
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${Math.round(bytes)} B`;
}

function formatTime(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatAge(value) {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unknown";
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

function shortTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function displayName(device) {
  const hostname = device.hostname && device.hostname !== "*" ? device.hostname : "";
  return hostname || device.ip || device.mac || "Unknown";
}

function knownDevices(summary = state.summary || {}) {
  return Number(summary.active_devices || 0) + Number(summary.idle_devices || 0) + Number(summary.offline_devices || 0) + Number(summary.unknown_devices || 0);
}

function addLiveSample(summary) {
  const sample = {
    ts: Date.now(),
    rx: Number(summary.rx_rate_bps || 0),
    tx: Number(summary.tx_rate_bps || 0),
    clients: knownDevices(summary),
  };
  sample.total = sample.rx + sample.tx;
  const last = state.liveHistory[state.liveHistory.length - 1];
  if (last && sample.ts - last.ts < 850) state.liveHistory[state.liveHistory.length - 1] = sample;
  else state.liveHistory.push(sample);
  while (state.liveHistory.length > HISTORY_LIMIT) state.liveHistory.shift();
}

function canvasContext(id) {
  const canvas = document.getElementById(id);
  if (!canvas) return null;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(1, Math.floor(rect.width));
  const height = Math.max(1, Math.floor(rect.height));
  canvas.width = Math.floor(width * dpr);
  canvas.height = Math.floor(height * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, width, height };
}

function drawAxes(ctx, plot, max, labeler) {
  ctx.strokeStyle = cssVar("--grid");
  ctx.fillStyle = cssVar("--muted");
  ctx.font = "10px system-ui, sans-serif";
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";
  for (let i = 0; i <= 5; i += 1) {
    const y = plot.bottom - (plot.height * i) / 5;
    ctx.beginPath();
    ctx.moveTo(plot.left, y);
    ctx.lineTo(plot.right, y);
    ctx.stroke();
    ctx.fillText(labeler((max * i) / 5), plot.left - 8, y);
  }
}

function drawSeries(ctx, plot, history, accessor, color, max, fill) {
  if (!history.length) return;
  ctx.beginPath();
  history.forEach((sample, index) => {
    const x = history.length === 1 ? plot.left : plot.left + (plot.width * index) / Math.max(1, history.length - 1);
    const y = plot.bottom - (Math.max(0, accessor(sample)) / max) * plot.height;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.25;
  ctx.stroke();
  if (fill) {
    ctx.lineTo(plot.right, plot.bottom);
    ctx.lineTo(plot.left, plot.bottom);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
  }
}

function drawChart(id, history, series, labeler = axisRate) {
  const box = canvasContext(id);
  if (!box) return;
  const { ctx, width, height } = box;
  ctx.clearRect(0, 0, width, height);
  const plot = { left: 58, right: width - 12, top: 12, bottom: height - 24 };
  plot.width = Math.max(1, plot.right - plot.left);
  plot.height = Math.max(1, plot.bottom - plot.top);
  const max = Math.max(1, ...series.flatMap((item) => history.map(item.accessor)));
  drawAxes(ctx, plot, max, labeler);
  for (const item of series) drawSeries(ctx, plot, history, item.accessor, item.color, max, item.fill);
  if (history.length > 2) {
    ctx.fillStyle = cssVar("--muted");
    ctx.font = "10px system-ui, sans-serif";
    ctx.textAlign = "left";
    ctx.fillText(shortTime(history[0].ts), plot.left, height - 6);
    ctx.textAlign = "right";
    ctx.fillText(shortTime(history[history.length - 1].ts), plot.right, height - 6);
  }
}

function drawDonut(id, entries) {
  const box = canvasContext(id);
  if (!box) return;
  const { ctx, width, height } = box;
  ctx.clearRect(0, 0, width, height);
  const total = entries.reduce((sum, item) => sum + item.value, 0);
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.max(32, Math.min(width, height) / 2 - 10);
  const lineWidth = Math.max(22, radius * 0.42);
  ctx.lineWidth = lineWidth;
  ctx.strokeStyle = "#2a3037";
  ctx.beginPath();
  ctx.arc(cx, cy, radius - lineWidth / 2, 0, Math.PI * 2);
  ctx.stroke();
  if (!total) return;
  let start = -Math.PI / 2;
  entries.forEach((entry, index) => {
    const angle = (entry.value / total) * Math.PI * 2;
    ctx.strokeStyle = entry.color || PALETTE[index % PALETTE.length];
    ctx.beginPath();
    ctx.arc(cx, cy, radius - lineWidth / 2, start, start + angle);
    ctx.stroke();
    start += angle;
  });
}

function renderLegend(id, entries, emptyText = "No data") {
  const root = document.getElementById(id);
  clearNode(root);
  const total = entries.reduce((sum, item) => sum + item.value, 0) || 1;
  if (!entries.length) {
    root.appendChild(emptyNode(emptyText));
    return;
  }
  entries.slice(0, 8).forEach((entry, index) => {
    const row = document.createElement("div");
    row.className = "legend-item";
    row.style.setProperty("--c", entry.color || PALETTE[index % PALETTE.length]);
    const label = document.createElement("span");
    label.textContent = entry.label;
    const value = document.createElement("strong");
    value.textContent = `${Math.round((entry.value / total) * 100)}%`;
    row.append(label, value);
    root.appendChild(row);
  });
}

function renderSourceButtons() {
  const sqliteAvailable = !!state.integrations?.data_sources?.sqlite_query_enabled;
  if (state.source === "sqlite" && !sqliteAvailable) state.source = "live";
  for (const button of document.querySelectorAll("[data-source]")) {
    const selected = button.dataset.source === state.source;
    button.setAttribute("aria-pressed", selected ? "true" : "false");
    if (button.dataset.source === "sqlite") button.disabled = !sqliteAvailable;
  }
}

function renderSummary() {
  const summary = state.summary || {};
  setText("uniqueClients", knownDevices(summary));
  setText("realtimeSource", `memory / ${summary.rate_interface || summary.rate_source || "devices"}`);
  setText("lastUpdated", state.lastUpdatedAt ? shortTime(state.lastUpdatedAt) : "never");
  setText("inventorySource", "live memory / 1s");
  setText("eventSource", `source: ${state.source}`);
  setText("deviceTrafficSource", state.integrations?.data_sources?.sqlite_query_enabled ? "SQLite" : "unavailable");
}

function setGauge(id, value, max) {
  const node = document.getElementById(id);
  if (!node) return;
  const pct = max > 0 ? Math.max(2, Math.min(100, (Number(value || 0) / max) * 100)) : 0;
  node.style.setProperty("--value", String(pct));
}

function renderTrafficTotals() {
  const upload = state.deviceTraffic24h.reduce((sum, item) => sum + Number(item.tx_bytes || 0), 0);
  const download = state.deviceTraffic24h.reduce((sum, item) => sum + Number(item.rx_bytes || 0), 0);
  const total = upload + download;
  setText("uploadTotal24h", formatBytes(upload));
  setText("downloadTotal24h", formatBytes(download));
  setText("totalTraffic24h", formatBytes(total));
  setGauge("uploadGauge", upload, Math.max(total, 1));
  setGauge("downloadGauge", download, Math.max(total, 1));
  setGauge("totalGauge", total, Math.max(total, 1));
}

function renderTopActiveClients() {
  const root = document.getElementById("topActiveClients");
  clearNode(root);
  const ranked = [...state.devices]
    .map((device) => ({
      ...device,
      rx: Number(device.rx_rate_bps || 0),
      tx: Number(device.tx_rate_bps || 0),
      total: Number(device.rx_rate_bps || 0) + Number(device.tx_rate_bps || 0),
    }))
    .sort((a, b) => b.total - a.total || displayName(a).localeCompare(displayName(b)))
    .slice(0, 6);
  const max = Math.max(1, ...ranked.map((device) => device.total));
  if (!ranked.length) {
    root.appendChild(emptyNode("No active clients"));
    return;
  }
  for (const device of ranked) {
    const row = document.createElement("div");
    row.className = "active-client-row";
    const meta = document.createElement("div");
    meta.className = "active-client-meta";
    const name = document.createElement("strong");
    name.textContent = displayName(device);
    const detail = document.createElement("span");
    detail.textContent = `${device.ip || device.mac || "unknown"} / ${formatRate(device.total)}`;
    meta.append(name, detail);
    const bar = document.createElement("div");
    bar.className = "active-client-bar";
    bar.style.setProperty("--rx", `${Math.max(0, (device.rx / max) * 100)}%`);
    bar.style.setProperty("--tx", `${Math.max(0, (device.tx / max) * 100)}%`);
    row.append(meta, bar);
    root.appendChild(row);
  }
}

function renderDirectionSplit() {
  const upload = state.deviceTraffic24h.reduce((sum, item) => sum + Number(item.tx_bytes || 0), 0);
  const download = state.deviceTraffic24h.reduce((sum, item) => sum + Number(item.rx_bytes || 0), 0);
  const entries = [
    { label: "Download", value: download, color: cssVar("--yellow") },
    { label: "Upload", value: upload, color: cssVar("--green") },
  ].filter((entry) => entry.value > 0);
  drawDonut("directionDonut", entries);
  renderLegend("directionLegend", entries, "No traffic");
}

function renderDeviceTraffic24h() {
  const body = document.getElementById("deviceTrafficBody");
  clearNode(body);
  if (!state.deviceTraffic24h.length) {
    body.appendChild(emptyCell("No SQLite traffic in the last 24h", 6));
    return;
  }
  const max = Math.max(1, ...state.deviceTraffic24h.map((item) => Number(item.total_bytes || 0)));
  for (const item of state.deviceTraffic24h.slice(0, 16)) {
    const row = document.createElement("tr");
    const values = [
      displayName(item),
      item.ip || "-",
      formatBytes(item.rx_bytes),
      formatBytes(item.tx_bytes),
      formatBytes(item.total_bytes),
      formatTime(item.last_ts),
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      if (index === 4) {
        const bar = document.createElement("div");
        bar.className = "traffic-total-cell";
        bar.style.setProperty("--w", `${Math.max(3, (Number(item.total_bytes || 0) / max) * 100)}%`);
        const text = document.createElement("span");
        text.textContent = value;
        bar.appendChild(text);
        cell.appendChild(bar);
      } else {
        cell.textContent = value;
      }
      row.appendChild(cell);
    });
    body.appendChild(row);
  }
}

function renderDevices() {
  const body = document.getElementById("devicesBody");
  clearNode(body);
  if (!state.devices.length) {
    body.appendChild(emptyCell("No devices seen", 8));
    return;
  }
  const sorted = [...state.devices].sort((a, b) =>
    (Number(b.rx_rate_bps || 0) + Number(b.tx_rate_bps || 0)) - (Number(a.rx_rate_bps || 0) + Number(a.tx_rate_bps || 0)) ||
    displayName(a).localeCompare(displayName(b))
  );
  for (const device of sorted.slice(0, 20)) {
    const row = document.createElement("tr");
    const statusCell = document.createElement("td");
    const status = document.createElement("span");
    status.className = `status ${device.status || "unknown"}`;
    status.textContent = device.status || "unknown";
    statusCell.appendChild(status);
    row.appendChild(statusCell);
    const rx = Number(device.rx_rate_bps || 0);
    const tx = Number(device.tx_rate_bps || 0);
    const updatedAt = device.last_traffic || device.last_rate || device.last_seen;
    for (const value of [displayName(device), device.ip || "-", device.mac || "-", formatRate(rx), formatRate(tx), formatRate(rx + tx), formatAge(updatedAt)]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    }
    body.appendChild(row);
  }
}

function renderEvents() {
  const root = document.getElementById("eventStream");
  clearNode(root);
  if (!state.events.length) {
    root.appendChild(emptyNode("No events"));
    return;
  }
  for (const event of state.events.slice(0, 12)) {
    const row = document.createElement("div");
    row.className = "event-row";
    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${event.type || "event"} / ${event.severity || "info"}`;
    const message = document.createElement("span");
    message.textContent = event.message || "";
    text.append(title, message);
    const time = document.createElement("time");
    time.textContent = shortTime(event.ts) || formatTime(event.ts);
    row.append(text, time);
    root.appendChild(row);
  }
}

function renderCharts() {
  drawChart("throughputChart", state.liveHistory, [
    { accessor: (s) => s.tx, color: cssVar("--green"), fill: null },
    { accessor: (s) => s.rx, color: cssVar("--yellow"), fill: "rgba(242, 204, 12, 0.10)" },
    { accessor: (s) => s.total, color: cssVar("--blue"), fill: null },
  ]);
  drawChart("clientsChart", state.liveHistory, [
    { accessor: (s) => s.clients, color: cssVar("--green"), fill: "rgba(115, 191, 105, 0.12)" },
  ], (v) => Math.round(v).toString());
  renderTopActiveClients();
  renderDirectionSplit();
}

function renderAll() {
  renderSourceButtons();
  renderSummary();
  renderTrafficTotals();
  renderDeviceTraffic24h();
  renderDevices();
  renderEvents();
  renderCharts();
}

async function refreshFast() {
  if (state.fastInFlight) return;
  state.fastInFlight = true;
  try {
    const [summary, integrations, devices] = await Promise.all([
      fetchJson("/api/summary"),
      fetchJson("/api/integrations"),
      fetchJson("/api/devices?source=live&limit=1000"),
    ]);
    state.summary = summary;
    state.integrations = integrations;
    state.devices = itemsOf(devices);
    state.lastUpdatedAt = Date.now();
    addLiveSample(summary);
    renderAll();
  } catch (_) {
    setText("lastUpdated", "disconnected");
  } finally {
    state.fastInFlight = false;
  }
}

async function refreshSlow() {
  if (state.slowInFlight) return;
  state.slowInFlight = true;
  try {
    const [events, attacks, deviceTraffic] = await Promise.all([
      fetchJson(`/api/events?${sourceQuery()}&limit=80`),
      fetchJson(`/api/wan-attacks?${sourceQuery()}&limit=100`),
      fetchJson("/api/device-traffic-24h?limit=500"),
    ]);
    state.events = itemsOf(events);
    state.attacks = itemsOf(attacks);
    state.deviceTraffic24h = itemsOf(deviceTraffic);
    renderAll();
  } finally {
    state.slowInFlight = false;
  }
}

function setSource(source) {
  state.source = source;
  localStorage.setItem("netmon-source", source);
  renderSourceButtons();
  refreshFast();
  refreshSlow();
}

function connectSocket() {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const path = token ? `/ws?token=${encodeURIComponent(token)}` : "/ws";
  const socket = new WebSocket(`${scheme}://${window.location.host}${path}`);
  state.socket = socket;
  socket.addEventListener("message", () => refreshFast());
  socket.addEventListener("close", () => window.setTimeout(connectSocket, 2500));
  socket.addEventListener("error", () => socket.close());
}

for (const button of document.querySelectorAll("[data-source]")) {
  button.addEventListener("click", () => setSource(button.dataset.source || "live"));
}

window.addEventListener("resize", renderCharts);
refreshFast();
refreshSlow();
connectSocket();
window.setInterval(refreshFast, FAST_REFRESH_MS);
window.setInterval(refreshSlow, SLOW_REFRESH_MS);
