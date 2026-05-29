const params = new URLSearchParams(window.location.search);
const token = params.get("token") || "";

const state = {
  devices: [],
  events: [],
  attacks: [],
  history: [],
  socket: null,
  lastUpdatedAt: null,
  fastRefreshTimer: null,
  slowRefreshTimer: null,
  fastRefreshInFlight: false,
  slowRefreshInFlight: false,
};

const FAST_REFRESH_MS = 5000;
const SLOW_REFRESH_MS = 30000;
const EVENTS_LIMIT = 40;
const WAN_ATTACKS_LIMIT = 80;
const HISTORY_LIMIT = 180;
const THEME_STORAGE_KEY = "netmon-theme-mode";

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

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function currentThemeMode() {
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  return ["system", "dark", "light"].includes(saved) ? saved : "system";
}

function applyTheme(mode) {
  const selected = ["system", "dark", "light"].includes(mode) ? mode : "system";
  if (selected === "system") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.dataset.theme = selected;
  }

  for (const button of document.querySelectorAll("[data-theme-mode]")) {
    button.setAttribute("aria-pressed", button.dataset.themeMode === selected ? "true" : "false");
  }
  renderCharts();
}

function setupThemeControls() {
  applyTheme(currentThemeMode());
  for (const button of document.querySelectorAll("[data-theme-mode]")) {
    button.addEventListener("click", () => {
      const mode = button.dataset.themeMode || "system";
      localStorage.setItem(THEME_STORAGE_KEY, mode);
      applyTheme(mode);
    });
  }

  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", () => {
    if (currentThemeMode() === "system") applyTheme("system");
  });
}

function formatRate(value) {
  const rate = Number(value || 0);
  if (rate >= 1_000_000_000) return `${(rate / 1_000_000_000).toFixed(2)} Gbps`;
  if (rate >= 1_000_000) return `${(rate / 1_000_000).toFixed(2)} Mbps`;
  if (rate >= 1_000) return `${(rate / 1_000).toFixed(1)} Kbps`;
  return `${Math.round(rate)} bps`;
}

function formatAxisRate(value) {
  const rate = Number(value || 0);
  if (rate >= 1_000_000) return `${(rate / 1_000_000).toFixed(1)}M`;
  if (rate >= 1_000) return `${Math.round(rate / 1_000)}K`;
  return `${Math.round(rate)}`;
}

function formatTime(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatShortTime(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function displayName(device) {
  const hostname = device.hostname && device.hostname !== "*" ? device.hostname : "";
  return hostname || device.ip || device.mac || "Unknown";
}

function clearNode(node) {
  while (node && node.firstChild) node.removeChild(node.firstChild);
}

function emptyNode(message) {
  const node = document.createElement("div");
  node.className = "empty";
  node.textContent = message;
  return node;
}

function emptyRow(message, colSpan) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = colSpan;
  cell.className = "empty";
  cell.textContent = message;
  row.appendChild(cell);
  return row;
}

function addHistorySample(summary) {
  const now = Date.now();
  const sample = {
    ts: now,
    rx: Number(summary.rx_rate_bps || 0),
    tx: Number(summary.tx_rate_bps || 0),
    active: Number(summary.active_devices || 0),
    idle: Number(summary.idle_devices || 0),
    offline: Number(summary.offline_devices || 0),
    wan: Number(summary.wan_attack_5m || 0),
  };

  const last = state.history[state.history.length - 1];
  if (last && now - last.ts < 2500) {
    state.history[state.history.length - 1] = sample;
  } else {
    state.history.push(sample);
  }
  while (state.history.length > HISTORY_LIMIT) state.history.shift();
}

function onlineRatio(summary, devices) {
  const total = devices.length || 0;
  if (total === 0) return 0;
  return Math.round((Number(summary.active_devices || 0) / total) * 100);
}

function topDevice(devices, field) {
  return [...devices].sort((a, b) => Number(b[field] || 0) - Number(a[field] || 0))[0];
}

function renderSummary(summary, devices) {
  const idle = Number(summary.idle_devices || 0);
  const offline = Number(summary.offline_devices || 0);
  const trafficDevices = devices.filter((device) => Number(device.rx_bytes_total || 0) > 0 || Number(device.tx_bytes_total || 0) > 0).length;
  const topDown = topDevice(devices, "rx_rate_bps");
  const topUp = topDevice(devices, "tx_rate_bps");

  setText("activeDevices", summary.active_devices ?? 0);
  setText("deviceTotals", `${idle} idle / ${offline} offline`);
  setText("knownDevices", devices.length);
  setText("trafficDevices", `${trafficDevices} with traffic`);
  setText("wanDrops", summary.wan_attack_5m ?? 0);
  setText("downloadRate", formatRate(summary.rx_rate_bps));
  setText("uploadRate", formatRate(summary.tx_rate_bps));
  setText("onlineRatio", `${onlineRatio(summary, devices)}%`);
  setText("topDownloadName", topDown && Number(topDown.rx_rate_bps || 0) > 0 ? displayName(topDown) : "No active download");
  setText("topUploadName", topUp && Number(topUp.tx_rate_bps || 0) > 0 ? displayName(topUp) : "No active upload");
  setText("lastLog", summary.last_log_ts ? `Last log ${formatTime(summary.last_log_ts)}` : "No logs yet");
}

function renderStatusChips(devices) {
  const chips = document.getElementById("statusChips");
  clearNode(chips);
  if (!devices.length) {
    chips.appendChild(emptyNode("No devices seen"));
    return;
  }

  const sorted = [...devices].sort((a, b) => {
    const rank = { online: 0, idle: 1, unknown: 2, offline: 3 };
    return (rank[a.status] ?? 2) - (rank[b.status] ?? 2) || displayName(a).localeCompare(displayName(b));
  });

  for (const device of sorted.slice(0, 32)) {
    const chip = document.createElement("div");
    chip.className = `device-chip ${device.status || "unknown"}`;
    chip.title = `${displayName(device)} ${device.ip || ""} ${device.mac || ""}`;
    chip.textContent = displayName(device);
    chips.appendChild(chip);
  }
}

function renderDevices(devices) {
  const body = document.getElementById("devicesBody");
  clearNode(body);
  if (!devices.length) {
    body.appendChild(emptyRow("No devices seen", 7));
    return;
  }

  const sorted = [...devices].sort((a, b) => {
    const aRate = Number(a.rx_rate_bps || 0) + Number(a.tx_rate_bps || 0);
    const bRate = Number(b.rx_rate_bps || 0) + Number(b.tx_rate_bps || 0);
    return bRate - aRate || displayName(a).localeCompare(displayName(b));
  });

  for (const device of sorted) {
    const row = document.createElement("tr");
    const statusCell = document.createElement("td");
    const status = document.createElement("span");
    status.className = `status ${device.status || "unknown"}`;
    status.textContent = device.status || "unknown";
    statusCell.appendChild(status);
    row.appendChild(statusCell);

    for (const value of [
      displayName(device),
      device.ip || "unknown",
      device.mac || "unknown",
      formatRate(device.rx_rate_bps),
      formatRate(device.tx_rate_bps),
      formatTime(device.last_seen),
    ]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    }
    body.appendChild(row);
  }
}

function renderRankList(id, devices, field, label) {
  const list = document.getElementById(id);
  clearNode(list);

  const heading = document.createElement("li");
  heading.className = "rank-heading";
  heading.innerHTML = `<span class="rank-name">${label}</span><span class="rank-rate">Rate</span>`;
  list.appendChild(heading);

  const ranked = [...devices]
    .filter((device) => Number(device[field] || 0) > 0)
    .sort((a, b) => Number(b[field] || 0) - Number(a[field] || 0))
    .slice(0, 8);

  if (!ranked.length) {
    const item = document.createElement("li");
    item.appendChild(emptyNode("No traffic samples"));
    list.appendChild(item);
    return;
  }

  for (const device of ranked) {
    const item = document.createElement("li");
    const name = document.createElement("span");
    name.className = "rank-name";
    name.textContent = displayName(device);
    const rate = document.createElement("span");
    rate.className = "rank-rate";
    rate.textContent = formatRate(device[field]);
    item.append(name, rate);
    list.appendChild(item);
  }
}

function renderAttacks(attacks) {
  const latest = attacks[0];
  setText("latestAttack", latest ? `${latest.src_ip || "unknown"} -> ${latest.dst_ip || "unknown"}` : "No recent drops");

  const counts = new Map();
  for (const attack of attacks) {
    const source = attack.src_ip || "unknown";
    counts.set(source, (counts.get(source) || 0) + 1);
  }

  const container = document.getElementById("attackSources");
  clearNode(container);
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (!ranked.length) {
    container.appendChild(emptyNode("No WAN drops"));
    return;
  }

  for (const [source, count] of ranked) {
    const row = document.createElement("div");
    row.className = "source-row";
    const name = document.createElement("span");
    name.textContent = source;
    const number = document.createElement("span");
    number.className = "source-count";
    number.textContent = String(count);
    row.append(name, number);
    container.appendChild(row);
  }
}

function renderEvents(events) {
  const stream = document.getElementById("eventStream");
  clearNode(stream);
  if (!events.length) {
    stream.appendChild(emptyNode("No events"));
    return;
  }

  for (const event of events.slice(0, 14)) {
    const row = document.createElement("div");
    row.className = "event-row";
    const main = document.createElement("div");
    main.className = "event-main";
    const title = document.createElement("strong");
    title.textContent = `${event.type || "event"} / ${event.severity || "info"}`;
    const message = document.createElement("span");
    message.textContent = event.message || "";
    main.append(title, message);
    const time = document.createElement("span");
    time.className = "event-time";
    time.textContent = formatTime(event.ts);
    row.append(main, time);
    stream.appendChild(row);
  }
}

function canvasContext(canvas) {
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

function drawGrid(ctx, plot, yMax, labeler) {
  ctx.strokeStyle = cssVar("--chart-grid") || "rgba(137, 150, 157, 0.36)";
  ctx.lineWidth = 1;
  ctx.fillStyle = cssVar("--chart-label") || "#a5b0b6";
  ctx.font = "12px system-ui, sans-serif";
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";

  for (let i = 0; i <= 4; i += 1) {
    const y = plot.bottom - (plot.height * i) / 4;
    ctx.beginPath();
    ctx.moveTo(plot.left, y);
    ctx.lineTo(plot.right, y);
    ctx.stroke();
    const value = (yMax * i) / 4;
    ctx.fillText(labeler(value), plot.left - 8, y);
  }
}

function drawTimeLabels(ctx, plot, history) {
  if (!history.length) return;
  ctx.fillStyle = cssVar("--chart-label") || "#a5b0b6";
  ctx.font = "12px system-ui, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "top";

  const indexes = [0, Math.floor((history.length - 1) / 2), history.length - 1];
  for (const index of indexes) {
    const sample = history[index];
    if (!sample) continue;
    const x = history.length === 1 ? plot.left : plot.left + (plot.width * index) / (history.length - 1);
    ctx.fillText(formatShortTime(sample.ts), x, plot.bottom + 9);
  }
}

function drawSeries(ctx, plot, history, accessor, color, fillColor) {
  if (!history.length) return;
  const values = history.map(accessor);
  const maxValue = Math.max(1, ...values);

  ctx.beginPath();
  values.forEach((value, index) => {
    const x = history.length === 1 ? plot.left : plot.left + (plot.width * index) / (history.length - 1);
    const y = plot.bottom - (Math.max(0, value) / maxValue) * plot.height;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.stroke();

  if (fillColor) {
    ctx.lineTo(plot.right, plot.bottom);
    ctx.lineTo(plot.left, plot.bottom);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();
  }
}

function drawLineChart(canvasId, series, options = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const { ctx, width, height } = canvasContext(canvas);
  ctx.clearRect(0, 0, width, height);

  const plot = { left: 56, right: width - 18, top: 14, bottom: height - 36 };
  plot.width = Math.max(1, plot.right - plot.left);
  plot.height = Math.max(1, plot.bottom - plot.top);

  const history = state.history;
  const allValues = series.flatMap((item) => history.map(item.accessor));
  const yMax = Math.max(1, ...allValues);
  const labeler = options.labeler || ((value) => Math.round(value).toString());

  drawGrid(ctx, plot, yMax, labeler);
  drawTimeLabels(ctx, plot, history);

  for (const item of series) {
    drawSeries(ctx, plot, history, item.accessor, item.color, item.fill);
  }

  if (options.unit) {
    ctx.save();
    ctx.translate(16, plot.top + plot.height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillStyle = cssVar("--chart-label") || "#a5b0b6";
    ctx.font = "12px system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(options.unit, 0, 0);
    ctx.restore();
  }

  if (series.length > 1) {
    let x = plot.left;
    for (const item of series) {
      ctx.fillStyle = item.color;
      ctx.fillRect(x, height - 13, 10, 10);
      ctx.fillStyle = cssVar("--chart-label") || "#a5b0b6";
      ctx.font = "11px system-ui, sans-serif";
      ctx.textBaseline = "middle";
      ctx.textAlign = "left";
      ctx.fillText(item.label, x + 14, height - 8);
      x += 122;
    }
  }
}

function renderCharts() {
  drawLineChart("downloadChart", [
    { label: "Download", accessor: (sample) => sample.rx, color: "#44d6ee", fill: "rgba(68, 214, 238, 0.24)" },
  ], { unit: "bps", labeler: formatAxisRate });

  drawLineChart("uploadChart", [
    { label: "Upload", accessor: (sample) => sample.tx, color: "#25d48a", fill: "rgba(37, 212, 138, 0.22)" },
  ], { unit: "bps", labeler: formatAxisRate });

  drawLineChart("combinedChart", [
    { label: "In", accessor: (sample) => sample.rx, color: "#44d6ee" },
    { label: "Out", accessor: (sample) => sample.tx, color: "#2ab982" },
  ], { unit: "bps", labeler: formatAxisRate });

  drawLineChart("stateChart", [
    { label: "Online", accessor: (sample) => sample.active, color: "#30cf77", fill: "rgba(48, 207, 119, 0.16)" },
    { label: "Idle", accessor: (sample) => sample.idle, color: "#f5c542" },
    { label: "Offline", accessor: (sample) => sample.offline, color: "#ef5547" },
  ], { unit: "devices" });

  drawLineChart("wanChart", [
    { label: "Drops", accessor: (sample) => sample.wan, color: "#9b5cff", fill: "rgba(155, 92, 255, 0.18)" },
  ], { unit: "drops" });
}

function markUpdated() {
  state.lastUpdatedAt = Date.now();
  updateAgeLabel();
}

function updateAgeLabel() {
  if (!state.lastUpdatedAt) {
    setText("updatedAgo", "Last updated never");
    return;
  }
  const seconds = Math.max(0, Math.round((Date.now() - state.lastUpdatedAt) / 1000));
  setText("updatedAgo", `Last updated ${seconds} seconds ago`);
}

async function refreshFast() {
  if (state.fastRefreshInFlight) return;
  state.fastRefreshInFlight = true;
  try {
    const [summary, devices] = await Promise.all([
      fetchJson("/api/summary"),
      fetchJson("/api/devices"),
    ]);
    state.devices = devices;
    addHistorySample(summary);
    renderSummary(summary, devices);
    renderStatusChips(devices);
    renderDevices(devices);
    renderRankList("topDownload", devices, "rx_rate_bps", "Download");
    renderRankList("topUpload", devices, "tx_rate_bps", "Upload");
    renderCharts();
    setText("connectionState", "Live");
    markUpdated();
  } catch (error) {
    setText("connectionState", `Disconnected: ${error.message}`);
  } finally {
    state.fastRefreshInFlight = false;
  }
}

async function refreshSlow() {
  if (state.slowRefreshInFlight) return;
  state.slowRefreshInFlight = true;
  try {
    const [events, attacks] = await Promise.all([
      fetchJson(`/api/events?limit=${EVENTS_LIMIT}`),
      fetchJson(`/api/wan-attacks?limit=${WAN_ATTACKS_LIMIT}`),
    ]);
    state.events = events;
    state.attacks = attacks;
    renderAttacks(attacks);
    renderEvents(events);
    setText("connectionState", "Live");
  } catch (error) {
    setText("connectionState", `Disconnected: ${error.message}`);
  } finally {
    state.slowRefreshInFlight = false;
  }
}

async function refreshAll() {
  await Promise.all([refreshFast(), refreshSlow()]);
}

function scheduleFastRefresh(delay = 800) {
  if (state.fastRefreshTimer) return;
  state.fastRefreshTimer = window.setTimeout(() => {
    state.fastRefreshTimer = null;
    refreshFast();
  }, delay);
}

function scheduleSlowRefresh(delay = 2500) {
  if (state.slowRefreshTimer) return;
  state.slowRefreshTimer = window.setTimeout(() => {
    state.slowRefreshTimer = null;
    refreshSlow();
  }, delay);
}

function connectSocket() {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const path = token ? `/ws?token=${encodeURIComponent(token)}` : "/ws";
  const socket = new WebSocket(`${scheme}://${window.location.host}${path}`);
  state.socket = socket;

  socket.addEventListener("open", () => setText("connectionState", "Live"));
  socket.addEventListener("message", (event) => {
    let type = "";
    try {
      type = JSON.parse(event.data).type || "";
    } catch (_) {
      type = "";
    }

    if (type === "wan_attack" || type === "event" || type === "connected") {
      scheduleSlowRefresh();
    }
    scheduleFastRefresh();
  });
  socket.addEventListener("close", () => {
    setText("connectionState", "Reconnecting");
    window.setTimeout(connectSocket, 2500);
  });
  socket.addEventListener("error", () => {
    setText("connectionState", "Socket error");
    socket.close();
  });
}

document.getElementById("refreshButton").addEventListener("click", refreshAll);
window.addEventListener("resize", renderCharts);
setupThemeControls();
refreshAll();
connectSocket();
window.setInterval(refreshFast, FAST_REFRESH_MS);
window.setInterval(refreshSlow, SLOW_REFRESH_MS);
window.setInterval(updateAgeLabel, 1000);
