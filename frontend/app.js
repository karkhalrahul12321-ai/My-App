/* ============================================================
   Trading Helper — FINAL RESULT UI VERSION
   ============================================================ */

const $ = (id) => document.getElementById(id);

/* -------------------------------
   LOAD THEME + ACCENT ON START
-------------------------------- */
(function initTheme() {
  const th = localStorage.getItem("APP_THEME") || "light";
  const ac = localStorage.getItem("APP_ACCENT") || "blue";

  document.body.setAttribute("data-theme", th);
  document.body.setAttribute("data-accent", ac);

  if ($("themeDropdown")) $("themeDropdown").value = th;
  if ($("accentDropdown")) $("accentDropdown").value = ac;
})();

/* -------------------------------
   THEME & ACCENT HANDLERS
-------------------------------- */
if ($("themeDropdown")) {
  $("themeDropdown").onchange = (e) => {
    const t = e.target.value;
    document.body.setAttribute("data-theme", t);
    localStorage.setItem("APP_THEME", t);
  };
}

if ($("accentDropdown")) {
  $("accentDropdown").onchange = (e) => {
    const a = e.target.value;
    document.body.setAttribute("data-accent", a);
    localStorage.setItem("APP_ACCENT", a);
  };
}

/* -------------------------------
   SERVER URL CHECK
-------------------------------- */
async function checkServer() {
  const url = $("serverUrl").value.trim();
  if (!url) {
    $("serverStatus").innerText = "No server URL";
    return;
  }

  try {
    $("serverStatus").innerText = "Checking…";

    const r = await fetch(url + "/api/login/status");
    const j = await r.json();

    $("serverStatus").innerText = j.logged_in
      ? "SmartAPI Logged-In"
      : "Not Logged-In (Demo Mode)";
  } catch (err) {
    $("serverStatus").innerText = "Server unreachable";
  }
}

$("serverUrl").onchange = checkServer;

/* ============================================================
   MAIN CALCULATE HANDLER
============================================================ */
$("calcBtn").onclick = async () => {
  const server = $("serverUrl").value.trim();
  if (!server) {
    alert("Please enter your Render server URL");
    return;
  }

  $("resultHint").innerText = "Calculating…";

  const payload = {
    ema20: Number($("ema20").value),
    ema50: Number($("ema50").value),
    rsi: Number($("rsi").value),
    vwap: Number($("vwap").value),
    spot: Number($("spot").value),
    market: $("market").value,
    expiry_days: Number($("expiryDays").value),
    use_live: $("useLive").checked
  };

  try {
    const r = await fetch(server + "/api/calc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const j = await r.json();

    renderResult(j);
    renderLiveBox(j);

  } catch (err) {
    $("resultHint").innerText = "Network Error";
    $("resultBox").innerText = err.message;
  }
};

/* ============================================================
   RESULT RENDERER (NEW UI)
============================================================ */
function renderResult(j) {
  if (!j.success) {
    $("resultHint").innerText = "Error";
    $("resultBox").innerHTML = `<div class="result-error">${j.error}</div>`;
    return;
  }

  $("resultHint").innerText = "";

  const t = j.trend;
  const s = j.strikes;

  $("resultBox").innerHTML = `
    <div class="result-section">

      <div class="result-title">Trend Overview</div>

      <div class="result-block">
        <div class="result-row"><strong>Main Trend:</strong> ${t.main}</div>
        <div class="result-row"><strong>Strength:</strong> ${t.strength}</div>
        <div class="result-row"><strong>Bias:</strong> ${t.bias}</div>
        <div class="result-row"><strong>Score:</strong> ${t.score}</div>
      </div>

      <div class="result-title">Strike Suggestions</div>

      <div class="result-strikes">
        ${strikeBox("CE", s[0])}
        ${strikeBox("PE", s[1])}
        ${strikeBox("STRADDLE", s[2])}
      </div>

      <div class="result-title">Input Summary</div>
      <pre class="result-json">${JSON.stringify(j.input, null, 2)}</pre>
    </div>
  `;
}

/* strike card small UI */
function strikeBox(type, o) {
  return `
    <div class="strike-mini">
      <div class="strike-mini-head">${type} — ${o.strike}</div>
      <div class="strike-mini-line">Distance: ${o.distance}</div>
      <div class="strike-mini-line">Entry: ${o.entry}</div>
      <div class="strike-mini-line">SL: ${o.stopLoss}</div>
      <div class="strike-mini-line">Target: ${o.target}</div>
    </div>
  `;
}

/* ============================================================
   SMARTAPI / LIVE INFO RENDER
============================================================ */
function renderLiveBox(j) {
  $("liveBox").innerHTML = `
    Login: ${j.login_status}
    Live Used: ${j.meta.live_data_used}
    Live LTP: ${j.meta.live_ltp}
    Auto Tokens:
${JSON.stringify(j.auto_tokens, null, 2)}
  `;
}
