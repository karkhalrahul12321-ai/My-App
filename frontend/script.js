const qs = id => document.getElementById(id);

function getServer() {
  const s = qs("server").value.trim();
  return s !== "" ? s : "";
}

// output helper
function renderOutputLoading() {
  const out = qs("output");
  out.innerHTML = `
    <div class="output-card">
      <div class="status-text">Calculating...</div>
    </div>
  `;
}

function renderOutputError(msg) {
  const out = qs("output");
  out.innerHTML = `
    <div class="output-card">
      <div class="output-title">Error</div>
      <div class="status-text">${msg}</div>
    </div>
  `;
}

function renderOutputSuccess(data) {
  const out = qs("output");

  const trend = data.trend || {};
  const strikes = data.strikes || [];
  const meta = data.meta || {};
  const input = data.input || {};

  const bullets = trend.bullets || [];

  // Trend badge का रंग थोड़ा बदलने के लिए (optional)
  const directionText = trend.direction || "No clear bias";

  out.innerHTML = `
    <!-- Market Trend Card -->
    <div class="output-card">
      <div class="trend-header">
        <div class="trend-main">
          <div class="output-title">Market Trend</div>
          <div class="trend-badge">${trend.label || trend.code || "UNKNOWN"}</div>
          ${
            trend.score != null
              ? `<div class="trend-score">Score: ${trend.score.toFixed ? trend.score.toFixed(1) : trend.score} / 10</div>`
              : ""
          }
        </div>
      </div>
      <div class="trend-direction">
        Direction: <strong>${directionText}</strong>
      </div>
      ${
        trend.summary
          ? `<div class="small-text" style="margin-top:6px;">${trend.summary}</div>`
          : ""
      }
    </div>

    <!-- Trend Analysis Card -->
    <div class="output-card">
      <div class="output-title">Trend Analysis</div>
      ${
        bullets.length
          ? `<ul class="bullet-list">
              ${bullets.map(b => `<li>${b}</li>`).join("")}
             </ul>`
          : `<div class="small-text">No detailed bullets available.</div>`
      }
    </div>

    <!-- Recommended Strikes -->
    <div class="output-card">
      <div class="output-title">Recommended Strikes</div>
      <div class="strike-list">
        ${
          strikes.length
            ? strikes
                .map((s, idx) => {
                  const label = s.label || s.type || s.kind || `Strike ${idx + 1}`;
                  const dist = s.distance != null ? `${s.distance}` : "-";
                  return `
                    <div class="strike-item">
                      <div class="strike-header">
                        <div class="strike-title">${idx + 1}) ${label} – ${s.strike}</div>
                        <div class="strike-distance">Δ Spot: ${dist}</div>
                      </div>
                      <div class="strike-row">
                        <span>Entry: ${s.entry ?? "-"}</span>
                        <span>SL: ${s.stopLoss ?? "-"}</span>
                        <span>Target: ${s.target ?? "-"}</span>
                      </div>
                    </div>
                  `;
                })
                .join("")
            : `<div class="small-text">No strikes generated.</div>`
        }
      </div>
    </div>

    <!-- Notes -->
    <div class="output-card">
      <div class="output-title">Notes</div>
      <div class="small-text">
        ${meta.note || "No extra notes."}
      </div>
      <div class="small-text" style="margin-top:4px;">
        Live data flag: <strong>${meta.live_data_used ? "ON" : "OFF"}</strong>
      </div>
    </div>
  `;
}

async function calc() {
  const server = getServer();
  const url = server ? server + "/api/calc" : "/api/calc";

  const payload = {
    ema20: Number(qs("ema20").value) || 0,
    ema50: Number(qs("ema50").value) || 0,
    rsi: Number(qs("rsi").value) || 0,
    vwap: Number(qs("vwap").value) || 0,
    spot: Number(qs("spot").value) || 0,
    market: qs("market").value,
    expiry_days: Number(qs("expiry").value) || 7,
    use_live: qs("useLive").checked,
  };

  renderOutputLoading();

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const j = await r.json();

    if (!j.success) {
      renderOutputError(j.error || "Calculation failed.");
      return;
    }

    renderOutputSuccess(j);
  } catch (e) {
    renderOutputError("Network error: " + e.message);
  }
}

document.getElementById("calc").addEventListener("click", calc);
