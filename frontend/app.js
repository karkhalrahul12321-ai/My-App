// ---------- THEME & ACCENT ----------
const THEME_KEY = "th_theme";
const ACCENT_KEY = "th_accent";
const SERVER_KEY = "th_server_url";

const THEMES = [
  { value: "light", label: "Clean White" },
  { value: "soft", label: "Soft Grey" },
  { value: "warm", label: "Warm" }
];

const ACCENTS = [
  { value: "blue", label: "Blue" },
  { value: "green", label: "Green" },
  { value: "orange", label: "Orange" },
  { value: "pink", label: "Pink" }
];

// load theme
function loadTheme() {
  const th = localStorage.getItem(THEME_KEY) || "soft";
  const ac = localStorage.getItem(ACCENT_KEY) || "blue";

  document.documentElement.setAttribute("data-theme", th);
  document.documentElement.setAttribute("data-accent", ac);

  const t = document.getElementById("themeDropdown");
  const a = document.getElementById("accentDropdown");
  if (t) t.value = th;
  if (a) a.value = ac;
}

// change theme
function initThemeControls() {
  const t = document.getElementById("themeDropdown");
  const a = document.getElementById("accentDropdown");

  if (!t || !a) return;

  t.innerHTML = THEMES.map(x => `<option value="${x.value}">${x.label}</option>`).join("");
  a.innerHTML = ACCENTS.map(x => `<option value="${x.value}">${x.label}</option>`).join("");

  t.onchange = () => {
    localStorage.setItem(THEME_KEY, t.value);
    loadTheme();
  };
  a.onchange = () => {
    localStorage.setItem(ACCENT_KEY, a.value);
    loadTheme();
  };
}

// ---------- SERVER URL ----------
function initServerUrl() {
  const inp = document.getElementById("serverUrl");
  if (!inp) return;
  inp.value = localStorage.getItem(SERVER_KEY) || "";
  inp.onchange = () => localStorage.setItem(SERVER_KEY, inp.value);
}

// ---------- RESULT UI HELPERS ----------
function renderSummary(meta) {
  if (!meta) return "";

  return `
    <div class="summary-card">
      <h3 class="sec-title">Summary</h3>
      <div class="summary-row">
        <div><strong>Live Data Used:</strong></div>
        <div>${meta.live_data_used ? "Yes" : "No"}</div>

        <div><strong>Live LTP:</strong></div>
        <div>${meta.live_ltp ?? "—"}</div>

        <div><strong>Status:</strong></div>
        <div>${meta.live_error?.reason || "OK"}</div>
      </div>
    </div>
  `;
}

function renderStrikeBox(title, obj) {
  if (!obj) return "";

  return `
    <div class="strike-card">
      <h3 class="sec-title">${title}</h3>
      <div class="strike-grid">
        <div><strong>Symbol</strong></div>
        <div>${obj.symbol || "—"}</div>

        <div><strong>Token</strong></div>
        <div>${obj.token || "—"}</div>

        <div><strong>Expiry</strong></div>
        <div>${obj.expiry || "—"}</div>
      </div>
    </div>
  `;
}

// ---------- MAIN CALCULATE ----------
async function runCalculation() {
  const url = (localStorage.getItem(SERVER_KEY) || "").trim();
  if (!url) {
    alert("Please enter server URL");
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

  const resultHint = document.getElementById("resultHint");
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
    const res = await fetch(url + "/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("HTTP " + res.status);

    const json = await res.json();
    showResult(json);
    showLiveBox(json.meta);

    if (resultHint) resultHint.textContent = "Done";
  } catch (err) {
    showResult({ error: err.message });
    if (resultHint) resultHint.textContent = "Error";
  }
}

// ---------- SHOW RESULT ----------
function showResult(data) {
  const box = document.getElementById("resultBox");
  if (!box) return;

  if (!data || typeof data !== "object") {
    box.textContent = "Invalid data";
    return;
  }

  let html = "";

  html += renderSummary(data.meta);
  html += renderStrikeBox("NIFTY", data.nifty);
  html += renderStrikeBox("BANKNIFTY", data.banknifty);
  html += renderStrikeBox("SENSEX", data.sensex);
  html += renderStrikeBox("NATURAL GAS", data["natural gas"]);

  html += `
    <button class="json-btn" onclick="toggleJson()">Show JSON</button>
    <pre id="jsonRaw" class="json-raw hide">${JSON.stringify(data, null, 2)}</pre>
  `;

  box.innerHTML = html;
}

// toggle JSON
function toggleJson() {
  const el = document.getElementById("jsonRaw");
  if (!el) return;
  el.classList.toggle("hide");
}

// ---------- LIVE BOX ----------
function showLiveBox(meta) {
  const box = document.getElementById("liveBox");
  if (!box) return;
  box.textContent = JSON.stringify(meta, null, 2);
}

// ---------- INIT ----------
window.onload = () => {
  loadTheme();
  initThemeControls();
  initServerUrl();

  const btn = document.getElementById("calcBtn");
  if (btn) btn.onclick = runCalculation;
};
