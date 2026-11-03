/**
 * VIGIL Real-Time NOC WebSocket Client
 * Network Intelligence Platform — See Everything. Miss Nothing.
 *
 * Connects to /ws/noc/ via Django Channels, maintains a keepalive heartbeat,
 * automatically reconnects with exponential backoff, and updates NOC stat cards,
 * Chart.js canvases, device tables, and incident alert banners in real time.
 */

(function () {
  "use strict";

  let socket = null;
  let reconnectAttempts = 0;
  let heartbeatTimer = null;
  const MAX_RECONNECT_DELAY_MS = 15000;

  function getWebSocketUrl(path) {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}${path}`;
  }

  function updateConnectionIndicator(connected) {
    const dot = document.getElementById("ws-status-dot");
    const label = document.getElementById("ws-status-text");
    const chartBadge = document.getElementById("chart-refresh-indicator");
    if (dot) {
      dot.style.background = connected ? "var(--noc-online)" : "var(--noc-warning)";
    }
    if (label) {
      label.textContent = connected ? "Live WS" : "Reconnecting";
    }
    if (chartBadge && connected) {
      chartBadge.textContent = "WebSocket Live Stream";
      chartBadge.classList.remove("border-secondary");
      chartBadge.classList.add("border-success", "text-success");
    }
  }

  function showNOCToast(title, message, severity) {
    let container = document.getElementById("noc-ws-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "noc-ws-toast-container";
      container.style.cssText =
        "position:fixed;top:3.75rem;right:1.25rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem;max-width:360px;";
      document.body.appendChild(container);
    }

    const borderColors = {
      critical: "var(--noc-offline)",
      warning: "var(--noc-warning)",
      online: "var(--noc-online)",
      info: "var(--noc-accent)",
    };
    const borderColor = borderColors[severity] || borderColors.info;

    const toast = document.createElement("div");
    toast.style.cssText = `
      background: var(--noc-surface);
      border: 1px solid var(--noc-border);
      border-left: 4px solid ${borderColor};
      border-radius: 8px;
      padding: .65rem .9rem;
      color: var(--noc-text);
      box-shadow: 0 8px 24px rgba(0,0,0,.45);
      font-size: .8rem;
      transition: opacity .3s ease;
    `;
    toast.innerHTML = `
      <div class="d-flex justify-content-between align-items-center mb-1">
        <strong style="font-size:.82rem;">${title}</strong>
        <small style="color:var(--noc-muted);font-size:.68rem;">Just now</small>
      </div>
      <div style="color:var(--noc-muted);font-size:.76rem;">${message}</div>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 5000);
  }

  function applyNOCSnapshot(data) {
    if (!data || !data.devices) return;

    const setElText = (id, val) => {
      const el = document.getElementById(id);
      if (el && val !== undefined && val !== null) el.textContent = val;
    };
    const setElHTML = (id, html) => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = html;
    };

    setElText("stat-total-devices", data.devices.total);
    setElText("stat-online-devices", data.devices.online);
    setElText("stat-offline-devices", data.devices.offline);

    if (data.performance) {
      setElHTML(
        "stat-avg-latency",
        `${data.performance.avg_latency_ms} <small style="font-size:.85rem;color:var(--noc-muted);">ms</small>`
      );
      setElHTML(
        "stat-avg-loss",
        `${data.performance.avg_packet_loss_pct}<small style="font-size:.85rem;color:var(--noc-muted);">%</small>`
      );
      setElHTML(
        "stat-uptime",
        `${data.performance.global_uptime_pct}<small style="font-size:.85rem;">%</small>`
      );
      setElText("stat-bandwidth", data.performance.total_bandwidth_display);
    }

    if (data.alerts) {
      setElText("badge-alert-count", data.alerts.active_total);
    }

    if (window.deviceStatusChart) {
      window.deviceStatusChart.data.datasets[0].data = [
        data.devices.online,
        data.devices.warning,
        data.devices.offline,
        data.devices.unknown,
      ];
      window.deviceStatusChart.update();
    }
  }

  function handleDeviceStatusUpdate(event) {
    // Update matching row in overview or device list table if present
    const row = document.querySelector(`tr[data-device-id="${event.device_id}"]`);
    if (row) {
      const statusCell = row.querySelector(".device-status-cell");
      if (statusCell) {
        const displayStatus =
          event.new_status.charAt(0).toUpperCase() + event.new_status.slice(1);
        statusCell.innerHTML = `
          <span class="badge rounded-pill px-2 badge-${event.new_status}" style="font-size:.7rem;">
            ● ${displayStatus}
          </span>
        `;
      }

      const latencyCell = row.querySelector(".device-latency-cell");
      if (latencyCell) {
        if (event.latency !== null && event.latency !== undefined) {
          const lat = parseFloat(event.latency).toFixed(1);
          const cls =
            lat > 300 ? "text-danger" : lat > 100 ? "text-warning" : "text-success";
          latencyCell.innerHTML = `<span class="${cls}">${lat}ms</span>`;
        } else {
          latencyCell.textContent = "—";
        }
      }

      const checkedCell = row.querySelector(".device-checked-cell");
      if (checkedCell) {
        checkedCell.textContent = "Just now";
      }
    }

    if (event.status_changed) {
      const sev =
        event.new_status === "offline"
          ? "critical"
          : event.new_status === "warning"
          ? "warning"
          : "online";
      showNOCToast(
        `Device Status: ${event.device_name}`,
        `${event.ip_address} transitioned from ${event.old_status.toUpperCase()} to ${event.new_status.toUpperCase()}`,
        sev
      );
    }

    // Request fresh NOC aggregate counts
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ action: "request_snapshot" }));
    }
  }

  function handleTrafficSnapshotUpdate(event) {
    const setElText = (id, val) => {
      const el = document.getElementById(id);
      if (el && val !== undefined && val !== null) el.textContent = val;
    };
    setElText("stat-total-devices", event.total_devices);
    setElText("stat-online-devices", event.online_devices);
    setElText("stat-offline-devices", event.offline_devices);
    setElText("stat-bandwidth", event.total_bandwidth_display);

    if (window.bandwidthChart && event.label) {
      const chart = window.bandwidthChart;
      chart.data.labels.push(event.label);
      chart.data.datasets[0].data.push(event.incoming_mbps);
      chart.data.datasets[1].data.push(event.outgoing_mbps);
      if (chart.data.labels.length > 20) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
        chart.data.datasets[1].data.shift();
      }
      chart.update();
    }
  }

  function handleAlertNotification(event) {
    if (event.event === "created") {
      showNOCToast(
        `[${event.severity.toUpperCase()}] ${event.device_name}`,
        event.description,
        event.severity
      );
    } else if (event.event === "resolved") {
      const box = document.getElementById(`alert-box-${event.alert_id}`);
      if (box) box.remove();
      showNOCToast(
        `Resolved: ${event.device_name}`,
        `${event.alert_type_display || event.alert_type} has recovered.`,
        "online"
      );
    } else if (event.event === "acknowledged") {
      const box = document.getElementById(`alert-box-${event.alert_id}`);
      if (box) {
        const btn = box.querySelector(".btn-ack");
        if (btn) {
          const parent = btn.parentElement;
          btn.remove();
          const ackSpan = document.createElement("span");
          ackSpan.className = "text-success mt-1 d-inline-block";
          ackSpan.style.fontSize = ".68rem";
          ackSpan.textContent = `✓ Ack by ${event.acknowledged_by || "Operator"}`;
          parent.appendChild(ackSpan);
        }
      }
    }

    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ action: "request_snapshot" }));
    }
  }

  function connectWebSocket() {
    // Only connect on authenticated dashboard/NOC pages where #topbar exists
    if (!document.getElementById("topbar")) return;

    const wsUrl = getWebSocketUrl("/ws/noc/");
    try {
      socket = new WebSocket(wsUrl);
    } catch (err) {
      return;
    }

    socket.onopen = function () {
      reconnectAttempts = 0;
      updateConnectionIndicator(true);

      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        if (socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ action: "ping" }));
        }
      }, 25000);
    };

    socket.onmessage = function (msgEvent) {
      try {
        const payload = JSON.parse(msgEvent.data);
        switch (payload.type) {
          case "noc_snapshot":
            applyNOCSnapshot(payload);
            break;
          case "device_status_update":
            handleDeviceStatusUpdate(payload);
            break;
          case "traffic_snapshot_update":
            handleTrafficSnapshotUpdate(payload);
            break;
          case "alert_notification":
            handleAlertNotification(payload);
            break;
          default:
            break;
        }
      } catch (err) {
        console.debug("WebSocket message parse error:", err);
      }
    };

    socket.onclose = function (closeEvent) {
      updateConnectionIndicator(false);
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      // Do not auto-reconnect if explicitly rejected for unauthenticated access (4401)
      if (closeEvent.code === 4401) return;

      reconnectAttempts += 1;
      const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), MAX_RECONNECT_DELAY_MS);
      setTimeout(connectWebSocket, delay);
    };
  }

  document.addEventListener("DOMContentLoaded", connectWebSocket);
})();
