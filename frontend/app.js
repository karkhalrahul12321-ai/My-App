/* --------------------------------------
   THEME + ACCENT SYSTEM
--------------------------------------- */

const THEME_KEY = "th_theme";
const ACCENT_KEY = "th_accent";
const SERVER_KEY = "th_server_url";

const THEMES = [
  { value: "light", label: "Clean White" },
  { value: "soft", label: "Soft Grey" },
  { value: "warm", label: "Warm Beige" }
];

const ACCENTS = [
  { value: "blue", label: "Blue" },
  { value: "green", label: "Green" },
  { value: "orange", label: "Orange" },
  { value: "pink", label: "Pink" }
];

function applyTheme(theme, accent) {
  if (!theme) theme = "soft";
  if (!accent) accent = "blue";

  const root = document.documentElement;

  // Basic themes
  const themeMap = {
    light: { bg: "#ffffff", card: "#ffffff", text: "#222", sub: "#666" },
    soft: { bg: "#f4f6f8", card: "#ffffff", text: "#222", sub: "#666" },
    warm: { bg: "#f7efe7", card: "#ffffff", text: "#553", sub: "#876" }
  };

  // Accent colors
  const accentMap = {
    blue: "#2b8df0",
    green: "#28a745",
    orange: "#ff7d28",
    pink: "#ff4fa3"
  };

  const t = themeMap[theme];
  const ac = accentMap[accent];

  root.style.setProperty("--bg", t.bg);
  root.style.setProperty("--card", t.card);
  root.style.setProperty("--text", t.text);
  root.style.setProperty("--subtext", t.sub);
  root.style.setProperty("--accent", ac);
  root.style.setProperty("--border", "rgba(0,0,0,0.12)");
}

function loadThemeControls() {
  const tSel = document.getElementById("themeDropdown");
  const aSel = document.getElementById("accentDropdown");

  if (tSel && aSel) {
    tSel.innerHTML = THEMES.map(t => `<option value="${t.value}">${t.label}</option>`).join("");
    aSel.innerHTML = ACCENTS.map(a => `<option value="${a.value}">${a.label}</option>`).join("");

    const savedT = localStorage.getItem(THEME_KEY) || "soft";
    const savedA = localStorage.getItem(ACCENT_KEY) || "blue";

    tSel.value = savedT;
    aSel.value = savedA;

    applyTheme(savedT, savedA);

    tSel.onchange = () => {
      localStorage.setItem(THEME_KEY, tSel.value);
      applyTheme(tSel.value, aSel.value);
    };

    aSel.onchange = () => {
      localStorage.setItem(ACCENT_KEY, aSel.value);
      applyTheme(tSel.value, aSel.value);
    };
  }
}



/* --------------------------------------
   SETTINGS PAGE LOAD
--------------------------------------- */

function loadSettingsPage() {
  if (!location.href.includes("settings.html")) return;

  const tSel = document.getElementById("themeSelect");
  const aSel = document.getElementById("accentSelect");
  const pinInput = document.getElementById("pinInput");

  const apiKeyDiv = document.getElementById("savedApiKey");
  const userIdDiv = document.getElementById("savedUserId");
  const totpDiv = document.getElementById("savedTotp");

  const storedTheme = localStorage.getItem(THEME_KEY) || "soft";
  const storedAccent = localStorage.getItem(ACCENT_KEY) || "blue";

  const pin = localStorage.getItem("trading_pin") || "";
  const k1 = localStorage.getItem("smart_api_key") || "-";
  const k2 = localStorage.getItem("smart_user_id") || "-";
  const k3 = localStorage.getItem("smart_totp") || "-";

  if (tSel) tSel.value = storedTheme;
  if (aSel) aSel.value = storedAccent;

  if (pinInput) pinInput.value = pin;
  if (apiKeyDiv) apiKeyDiv.innerText = k1;
  if (userIdDiv) userIdDiv.innerText = k2;
  if (totpDiv) totpDiv.innerText = k3;
}

function saveSettings() {
  const tSel = document.getElementById("themeSelect");
  const aSel = document.getElementById("accentSelect");
  const pinInput = document.getElementById("pinInput");

  if (tSel) localStorage.setItem(THEME_KEY, tSel.value);
  if (aSel) localStorage.setItem(ACCENT_KEY, aSel.value);
  if (pinInput) localStorage.setItem("trading_pin", pinInput.value.trim());

  alert("Settings saved!");
}



/* --------------------------------------
   LIVE SERVER CHECK
--------------------------------------- */

async function checkServerStatus() {
  const urlBox = document.getElementById("serverUrl");
  const statusBox = document.getElementById("serverStatus");

  if (!urlBox || !statusBox) return;

  const url = urlBox.value.trim();
  if (!url) {
    statusBox.textContent = "Enter Render URL";
    return;
  }

  localStorage.setItem(SERVER_KEY, url);
  statusBox.textContent = "Checking...";

  try {
    const res = await fetch(url + "/status");
    if (!res.ok) throw new Error("Bad");

    const js = await res.json();

    if (js.ok) statusBox.textContent = "Server OK";
    else statusBox.textContent = "Server Not Ready";

  } catch (e) {
    statusBox.textContent = "Cannot connect";
  }
}




/* --------------------------------------
   CALCULATE (MAIN ANALYSIS)
--------------------------------------- */

async function runCalculate() {
  const baseUrl = localStorage.getItem(SERVER_KEY);
  const resultHint = document.getElementById("resultHint");

  if (!baseUrl) {
    if (resultHint) resultHint.textContent = "Enter server URL first!";
    return;
  }

  const ema20 = Number(document.getElementById("ema20").value || 0);
  const ema50 = Number(document.getElementById("ema50").value || 0);
  const rsi = Number(document.getElementById("rsi").value || 0);
  const vwap = Number(document.getElementById("vwap").value || 0);
  const spot = Number(document.getElementById("spot").value || 0);

  const market = document.getElementById("market").value;

  const expiryDays = Number(document.getElementById("expiryDays").value || 0);
  const useLive = document.getElementById("useLive").checked;

  if (resultHint) resultHint.textContent = "Calculating...";

  const payload = {
    ema20,
    ema50,
    rsi,
    vwap,
    spot,
    market,
    expiry_days: expiryDays,
    use_live: useLive
  };

  try {
    const res = await fetch(baseUrl + "/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("HTTP " + res.status);

    const data = await res.json();
    renderResultUI(data);

  } catch (err) {
    renderResultError(err.message);
  }
}



/* --------------------------------------
   RESULT RENDER (NEW UI)
--------------------------------------- */

function renderResultUI(data) {
  const box = document.getElementById("resultBox");
  if (!box) return;

  box.innerHTML = "";

  // ---- Summary Block ----
  const summary = data.summary || {};

  const sDiv = document.createElement("div");
  sDiv.className = "result-box";

  sDiv.innerHTML = `
    <h3>Trend Summary</h3>

    <div class="summary-grid">
      <div class="summary-item">
        <p class="summary-label">Primary Trend</p>
        <p class="summary-value">${summary.trend || "-"}</p>
      </div>

      <div class="summary-item">
        <p class="summary-label">Strength</p>
        <p class="summary-value">${summary.strength || "-"}</p>
      </div>
    </div>
  `;

  box.appendChild(sDiv);

  // ---- Strike Grid ----

  const strikes = data.strikes || {};

  const stDiv = document.createElement("div");
  stDiv.className = "result-box";

  stDiv.innerHTML = `
    <h3>Strikes</h3>

    <div class="strike-grid">
      <div class="strike-card">
        <p class="strike-title">Call Strike</p>
        <p class="strike-val">${strikes.call || "-"}</p>
      </div>

      <div class="strike-card">
        <p class="strike-title">Put Strike</p>
        <p class="strike-val">${strikes.put || "-"}</p>
      </div>
    </div>
  `;

  box.appendChild(stDiv);

  // ---- Meta ----
  const meta = data.meta || {};

  const mDiv = document.createElement("div");
  mDiv.className = "result-box";

  mDiv.innerHTML = `
    <h3>Meta Info</h3>

    <div class="meta-row">Live Used: ${meta.live_data_used}</div>
    <div class="meta-row">Live LTP: ${meta.live_ltp || "-"}</div>
    <div class="meta-row">Reason: ${
      meta.live_error ? meta.live_error.reason : "-"
    }</div>

    <button id="toggleJsonBtn" class="btn-ghost" style="margin-top:12px;">
      Show Raw JSON
    </button>

    <pre id="rawJsonBox" class="json-box" style="display:none;">
${JSON.stringify(data, null, 2)}
    </pre>
  `;

  box.appendChild(mDiv);

  // JSON Toggle
  const btn = document.getElementById("toggleJsonBtn");
  const rawBox = document.getElementById("rawJsonBox");

  btn.onclick = () => {
    const show = rawBox.style.display === "none";
    rawBox.style.display = show ? "block" : "none";
    btn.textContent = show ? "Hide Raw JSON" : "Show Raw JSON";
  };
}



/* --------------------------------------
   RESULT ERROR
--------------------------------------- */

function renderResultError(msg) {
  const box = document.getElementById("resultBox");
  if (!box) return;
  box.innerHTML = `<div class="result-box"><b>Error:</b> ${msg}</div>`;
}



/* --------------------------------------
   INIT
--------------------------------------- */

window.onload = () => {
  loadThemeControls();
  loadSettingsPage();

  const savedServer = localStorage.getItem(SERVER_KEY);
  const serverBox = document.getElementById("serverUrl");
  if (serverBox && savedServer) {
    serverBox.value = savedServer;
    checkServerStatus();
  }

  const calcBtn = document.getElementById("calcBtn");
  if (calcBtn) calcBtn.onclick = runCalculate;
};
