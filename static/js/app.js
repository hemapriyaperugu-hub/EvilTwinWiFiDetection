// Pure offline vanilla JS helpers & Canvas charts (zero external CDN dependency)

function classificationBadgeClass(cls) {
  if (!cls) return "badge-muted";
  const u = cls.trim().toUpperCase();
  if (u === "UNSAFE" || u.includes("HIGH RISK")) return "badge-high";
  if (u === "UNVERIFIED NETWORK AND UNSAFE" || u === "UNVERIFIED / UNSAFE" || u.includes("SUSPICIOUS")) return "badge-suspicious";
  if (u === "SAFE" || u.includes("KNOWN")) return "badge-known";
  if (u === "UNVERIFIED NETWORK BUT SAFE" || u === "UNVERIFIED / SAFE" || u.includes("NEW")) return "badge-new";
  return "badge-new";
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ------------------------------------------------------------
// Offline Canvas Charts for Dashboard
// ------------------------------------------------------------
function drawBarChart(canvasId, items) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !items || items.length === 0) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 360;
  const h = 210;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const maxVal = Math.max(1, ...items.map((i) => i.value));
  const padLeft = 34;
  const padRight = 14;
  const padTop = 18;
  const padBottom = 42;
  const plotW = w - padLeft - padRight;
  const plotH = h - padTop - padBottom;
  const slotW = plotW / items.length;
  const barW = Math.min(48, slotW * 0.55);

  ctx.strokeStyle = "#263248";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padLeft, padTop + plotH);
  ctx.lineTo(w - padRight, padTop + plotH);
  ctx.stroke();

  ctx.font = "11px Segoe UI, sans-serif";
  items.forEach((item, idx) => {
    const barH = (item.value / maxVal) * plotH;
    const x = padLeft + idx * slotW + (slotW - barW) / 2;
    const y = padTop + plotH - barH;

    ctx.fillStyle = item.color || "#38bdf8";
    ctx.fillRect(x, y, barW, barH);

    ctx.fillStyle = "#f1f5f9";
    ctx.textAlign = "center";
    ctx.fillText(String(item.value), x + barW / 2, y - 5);

    ctx.fillStyle = "#94a3b8";
    const label = item.label.length > 14 ? item.label.slice(0, 13) + "…" : item.label;
    ctx.fillText(label, x + barW / 2, padTop + plotH + 16);
  });
}

function drawTimelineChart(canvasId, timeline) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !timeline || timeline.length === 0) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 520;
  const h = 210;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const maxVal = Math.max(1, ...timeline.map((t) => t.total));
  const padLeft = 36;
  const padRight = 18;
  const padTop = 18;
  const padBottom = 36;
  const plotW = w - padLeft - padRight;
  const plotH = h - padTop - padBottom;

  ctx.strokeStyle = "#263248";
  ctx.beginPath();
  ctx.moveTo(padLeft, padTop);
  ctx.lineTo(padLeft, padTop + plotH);
  ctx.lineTo(w - padRight, padTop + plotH);
  ctx.stroke();

  const stepX = timeline.length > 1 ? plotW / (timeline.length - 1) : plotW / 2;

  function drawLine(vals, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    vals.forEach((v, idx) => {
      const x = timeline.length > 1 ? padLeft + idx * stepX : padLeft + plotW / 2;
      const y = padTop + plotH - (v / maxVal) * plotH;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    vals.forEach((v, idx) => {
      const x = timeline.length > 1 ? padLeft + idx * stepX : padLeft + plotW / 2;
      const y = padTop + plotH - (v / maxVal) * plotH;
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(x, y, 3.5, 0, Math.PI * 2);
      ctx.fill();
    });
  }

  drawLine(timeline.map((t) => t.total), "#38bdf8");
  drawLine(timeline.map((t) => t.flagged), "#ef4444");

  ctx.fillStyle = "#94a3b8";
  ctx.font = "11px Segoe UI, sans-serif";
  ctx.textAlign = "center";
  timeline.forEach((t, idx) => {
    const x = timeline.length > 1 ? padLeft + idx * stepX : padLeft + plotW / 2;
    ctx.fillText(t.label || ("#" + t.id), x, padTop + plotH + 18);
  });
}

// ------------------------------------------------------------
// Scanner Page Logic
// ------------------------------------------------------------
let currentScanRows = [];

function initScannerPage(initialRows) {
  currentScanRows = Array.isArray(initialRows) ? initialRows : [];
  const btn = document.getElementById("startScanBtn");
  const searchEl = document.getElementById("filterSearch");
  const classEl = document.getElementById("filterClass");
  const sortEl = document.getElementById("sortSelect");

  if (btn) btn.addEventListener("click", triggerLiveScan);
  if (searchEl) searchEl.addEventListener("input", renderScannerTable);
  if (classEl) classEl.addEventListener("change", renderScannerTable);
  if (sortEl) sortEl.addEventListener("change", renderScannerTable);

  renderScannerTable();
}

async function triggerLiveScan() {
  const btn = document.getElementById("startScanBtn");
  const statusEl = document.getElementById("scanStatusText");
  const errBox = document.getElementById("scanErrorBanner");

  if (!btn) return;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scanning Wi-Fi...';
  if (statusEl) statusEl.textContent = "Running Windows netsh Wi-Fi scan and analyzing results...";
  if (errBox) {
    errBox.style.display = "none";
    errBox.textContent = "";
  }

  try {
    const resp = await fetch("/api/scan", { method: "POST" });
    const data = await resp.json();

    const alertBadge = document.getElementById("sidebarAlertBadge");
    if (alertBadge && typeof data.unack_alerts === "number") {
      alertBadge.textContent = data.unack_alerts;
      alertBadge.style.display = data.unack_alerts > 0 ? "inline-block" : "none";
    }

    if (!data.success) {
      if (errBox) {
        errBox.textContent = "Scan failed: " + (data.error || "Unknown error");
        errBox.style.display = "block";
      }
      if (statusEl) statusEl.textContent = "Scan failed at " + (data.timestamp || "");
      return;
    }

    currentScanRows = data.results || [];
    const scanInfo = data.scan || {};
    const tsEl = document.getElementById("lastScanTs");
    const cntEl = document.getElementById("lastScanCount");
    if (tsEl) tsEl.textContent = scanInfo.timestamp || "Just now";
    if (cntEl) cntEl.textContent = String(currentScanRows.length);

    if (statusEl) {
      statusEl.textContent =
        currentScanRows.length > 0
          ? "Scan completed (" + currentScanRows.length + " APs analyzed)."
          : "Scan completed: No Wi-Fi networks detected in range.";
    }
    renderScannerTable();
  } catch (err) {
    if (errBox) {
      errBox.textContent = "Request error while contacting Flask backend: " + err.message;
      errBox.style.display = "block";
    }
    if (statusEl) statusEl.textContent = "Scan failed.";
  } finally {
    btn.disabled = false;
    btn.textContent = "Start Scan";
  }
}

function renderScannerTable() {
  const tbody = document.getElementById("scannerTableBody");
  if (!tbody) return;

  const q = ((document.getElementById("filterSearch") || {}).value || "").trim().toLowerCase();
  const clsFilter = (document.getElementById("filterClass") || {}).value || "ALL";
  const sortBy = (document.getElementById("sortSelect") || {}).value || "risk_desc";

  let rows = currentScanRows.filter((r) => {
    const matchesSearch =
      !q ||
      (r.ssid || "").toLowerCase().includes(q) ||
      (r.bssid || "").toLowerCase().includes(q) ||
      (r.security || "").toLowerCase().includes(q);
    const matchesCls = clsFilter === "ALL" || r.classification === clsFilter;
    return matchesSearch && matchesCls;
  });

  rows.sort((a, b) => {
    if (sortBy === "risk_desc") return (b.risk_score || 0) - (a.risk_score || 0);
    if (sortBy === "signal_desc") return (b.signal_pct || -1) - (a.signal_pct || -1);
    if (sortBy === "ssid_asc") return (a.ssid || "").localeCompare(b.ssid || "");
    if (sortBy === "channel_asc") return (a.channel || 999) - (b.channel || 999);
    return 0;
  });

  if (rows.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="9"><div class="empty-state">No access points match the current scan or filter. Click <strong>Start Scan</strong> to scan nearby Wi-Fi networks.</div></td></tr>';
    return;
  }

  tbody.innerHTML = rows
    .map((r) => {
      const badgeCls = classificationBadgeClass(r.classification);
      const topReason =
        (r.warnings && r.warnings.length > 0 ? r.warnings[0] : null) ||
        r.final_decision ||
        (r.reasons && r.reasons[0]) ||
        "";
      const detailHref = r.id ? "/network/" + r.id : "/network/lookup?ssid=" + encodeURIComponent(r.ssid) + "&bssid=" + encodeURIComponent(r.bssid);
      return `
        <tr>
          <td><strong>${escapeHtml(r.ssid)}</strong></td>
          <td class="mono">${escapeHtml(r.bssid)}</td>
          <td>${escapeHtml(r.signal_display || "Unavailable")}</td>
          <td>${escapeHtml(r.channel_display || "Unavailable")} <span style="color:var(--text-dim);font-size:11px;">(${escapeHtml(r.band || "Unavail.")})</span></td>
          <td>${escapeHtml(r.security || "Unavailable")}<br><span style="color:var(--text-dim);font-size:11px;">${escapeHtml(r.encryption || "Unavailable")}</span></td>
          <td><span class="badge ${badgeCls}">${escapeHtml(r.classification)}</span></td>
          <td><strong>${escapeHtml(String(r.risk_score))}/100</strong></td>
          <td style="max-width:260px;font-size:12px;color:var(--text-muted);">${escapeHtml(topReason)}</td>
          <td><a class="btn btn-sm" href="${detailHref}">View Details</a></td>
        </tr>
      `;
    })
    .join("");
}

// ------------------------------------------------------------
// Alerts & Trust Helpers
// ------------------------------------------------------------
async function toggleAckAlert(alertId, acknowledged) {
  const resp = await fetch("/api/alerts/" + alertId + "/ack", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ acknowledged: acknowledged })
  });
  if (resp.ok) {
    window.location.reload();
  }
}

async function markApTrusted(ssid, bssid) {
  if (!confirm(`Confirm marking '${ssid}' [${bssid}] as an established TRUSTED_BASELINE?\nOnly confirm if you physically verified this access point.`)) {
    return;
  }
  const resp = await fetch("/api/network/trust", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ssid, bssid })
  });
  const data = await resp.json();
  const msgEl = document.getElementById("trustActionMsg");
  if (msgEl) {
    msgEl.style.display = "block";
    msgEl.className = data.success ? "banner banner-success" : "banner banner-danger";
    msgEl.textContent = data.message || data.error || "Updated.";
  }
  if (data.success) {
    setTimeout(() => window.location.reload(), 700);
  }
}

async function untrustAp(ssid, bssid) {
  if (!confirm(`Revoke manual verification for '${ssid}' [${bssid}]?\nFuture scans will treat this AP as unverified until verified again.`)) {
    return;
  }
  const resp = await fetch("/api/network/untrust", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ssid, bssid })
  });
  const data = await resp.json();
  const msgEl = document.getElementById("trustActionMsg");
  if (msgEl) {
    msgEl.style.display = "block";
    msgEl.className = data.success ? "banner banner-info" : "banner banner-danger";
    msgEl.textContent = data.message || data.error || "Updated.";
  }
  if (data.success) {
    setTimeout(() => window.location.reload(), 700);
  }
}
