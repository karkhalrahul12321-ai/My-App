// ========= SHORTCUT =========
const $ = (id) => document.getElementById(id);

// ========= ELEMENTS =========
const serverUrlInput  = $("serverUrl");
const loginStatusPill = $("loginStatusPill");
const loginDot        = $("loginDot");
const loginStatusText = $("loginStatusText");
const openSettingsBtn = $("openSettingsBtn");

const themeSelect     = $("themeSelect");
const accentSelect    = $("accentSelect");

// Inputs
const ema20Input      = $("ema20");
const ema50Input      = $("ema50");
const rsiInput        = $("rsi");
const vwapInput       = $("vwap");
const spotInput       = $("spot");
const marketSelect    = $("market");
const expiryDaysInput = $("expiryDays");
const useLiveCheckbox = $("useLive");
const marketChip      = $("marketChip");

// Buttons
const calcBtn         = $("calcBtn");
const toggleJsonBtn   = $("toggleJsonBtn");

// Output: summary
const resultHint      = $("resultHint");
const summaryRow      = $("summaryRow");
const sumTrend        = $("sumTrend");
const sumBias         = $("sumBias");
const sumStrength     = $("sumStrength");
const sumScore        = $("sumScore");
const sumLiveUsed     = $("sumLiveUsed");
const sumSpot         = $("sumSpot");

// Output: strikes
const strikeCards     = $("strikeCards");
const ceStrike        = $("ceStrike");
const ceDist          = $("ceDist");
const ceEntry         = $("ceEntry");
const ceSL            = $("ceSL");
const ceTarget        = $("ceTarget");

const peStrike        = $("peStrike");
const peDist          = $("peDist");
const peEntry         = $("peEntry");
const peSL            = $("peSL");
const peTarget        = $("peTarget");

const strStrike       = $("strStrike");
const strDist         = $("strDist");
const strEntry        = $("strEntry");
const strSL           = $("strSL");
const strTarget       = $("strTarget");

// Output: meta + JSON
const metaCard        = $("metaCard");
const metaText        = $("metaText");
const metaLoginState  = $("metaLoginState");
const metaLiveFlag    = $("metaLiveFlag");
const metaTokenInfo   = $("metaTokenInfo");
const jsonBox         = $("jsonBox");

// ========= LOCAL STORAGE KEYS =========
const LS = {
  server: "th_server_url",
  theme:  "th_theme",
  accent: "th_accent"
};

// ========= SERVER BASE URL HELPER =========
function getBaseUrl() {
  const raw = (serverUrlInput.value || "").trim();
  if (!raw) return "";
  // आख़िर में लगा / हटा दो
  return raw.replace(/\/+$/, "");
}

function buildUrl(path) {
  const base = getBaseUrl();
  if (!base) return path;
  if (!path.startsWith("/")) path = "/" + path;
  return base + path;
}

// ========= THEME / ACCENT HANDLING =========
function applyTheme(theme, accent) {
  if (theme) {
    document.body.dataset.theme = theme;
  }
  if (accent) {
    document.body.dataset.accent = accent;
  }
}

function loadThemeFromStorage() {
  try {
    const t = localStorage.getItem(LS.theme) || "light";
    const a = localStorage.getItem(LS.accent) || "blue";
    themeSelect.value = t;
    accentSelect.value = a;
    applyTheme(t, a);
  } catch (e) {
    // ignore
  }
}

function saveThemeToStorage() {
  const t = themeSelect.value;
  const a = accentSelect.value;
  try {
    localStorage.setItem(LS.theme, t);
    localStorage.setItem(LS.accent, a);
  } catch (e) {
    // ignore
  }
  applyTheme(t, a);
}

// ========= LOGIN STATUS PILL =========

function setLoginPill(status, text) {
  // status: "idle" | "ok" | "bad"
  loginStatusPill.classList.remove("status-idle", "status-ok", "status-bad");
  loginDot.classList.remove("idle", "ok", "bad");

  if (status === "ok") {
    loginStatusPill.classList.add("status-ok");
    loginDot.classList.add("ok");
  } else if (status === "bad") {
    loginStatusPill.classList.add("status-bad");
    loginDot.classList.add("bad");
  } else {
    loginStatusPill.classList.add("status-idle");
    loginDot.classList.add("idle");
  }

  loginStatusText.textContent = text;
}

async function refreshLoginStatus() {
  setLoginPill("idle", "Checking login…");
  try {
    const resp = await fetch(buildUrl("/api/login/status"));
    const data = await resp.json().catch(() => null);

    if (!data || data.success === false) {
      setLoginPill("bad", "Login status error");
      return;
    }

    if (data.logged_in) {
      setLoginPill("ok", "SmartAPI Logged-In");
    } else {
      setLoginPill("idle", "Not logged-in (demo)");
    }
  } catch (e) {
    setLoginPill("bad", "Server unreachable");
  }
}

// ========= INPUT HELPERS =========
function readInputs() {
  const ema20  = Number(ema20Input.value) || 0;
  const ema50  = Number(ema50Input.value) || 0;
  const rsi    = Number(rsiInput.value)   || 0;
  const vwap   = Number(vwapInput.value)  || 0;
  const spot   = Number(spotInput.value)  || 0;
  const market = marketSelect.value;
  const expiry = Number(expiryDaysInput.value) || 7;
  const useLive = !!useLiveCheckbox.checked;

  return { ema20, ema50, rsi, vwap, spot, market, expiry_days: expiry, use_live: useLive };
}

function updateMarketChip() {
  const m = marketSelect.value;
  if (m === "sensex") {
    marketChip.textContent = "SENSEX · FUT";
  } else if (m === "natural gas") {
    marketChip.textContent = "NAT GAS · FUT";
  } else {
    marketChip.textContent = "NIFTY · FUT";
  }
}

// ========= OUTPUT RENDERING =========
function clearOutput() {
  summaryRow.classList.add("hidden");
  strikeCards.classList.add("hidden");
  metaCard.classList.add("hidden");
  resultHint.textContent = "पहले Calculate दबाएँ";
  jsonBox.textContent = "";
}

function renderSummary(data) {
  const trend = data.trend || {};
  const input = data.input || {};
  const meta  = data.meta  || {};

  summaryRow.classList.remove("hidden");
  resultHint.textContent = data.message || "Result ready";

  // Trend
  sumTrend.textContent = trend.main || "–";

  // Bias tag text + class
  let biasText = "–";
  if (trend.bias === "CE") biasText = "CE (Call side)";
  else if (trend.bias === "PE") biasText = "PE (Put side)";
  else biasText = "Neutral / Range";

  sumBias.textContent = biasText;
  sumBias.classList.remove("ce-bias", "pe-bias", "neutral-bias");
  if (trend.bias === "CE") sumBias.classList.add("ce-bias");
  else if (trend.bias === "PE") sumBias.classList.add("pe-bias");
  else sumBias.classList.add("neutral-bias");

  // Strength + Score
  sumStrength.textContent = trend.strength || "–";
  const score = typeof trend.score === "number" ? trend.score.toFixed(1) : "–";
  sumScore.textContent = "Score: " + score;

  // Live / Manual
  const liveUsed = !!meta.live_data_used;
  sumLiveUsed.textContent = liveUsed ? "Live Future" : "Manual";
  const spotVal = typeof input.spot === "number" ? input.spot : null;
  sumSpot.textContent = spotVal != null ? `Spot: ${spotVal}` : "Spot: –";
}

function renderStrikes(data) {
  const strikes = Array.isArray(data.strikes) ? data.strikes : [];
  if (!strikes.length) {
    strikeCards.classList.add("hidden");
    return;
  }

  // We assume array has CE, PE, STRADDLE in any order
  const ce  = strikes.find((s) => s.type === "CE")        || {};
  const pe  = strikes.find((s) => s.type === "PE")        || {};
  const str = strikes.find((s) => s.type === "STRADDLE")  || {};

  strikeCards.classList.remove("hidden");

  // CE
  ceStrike.textContent  = ce.strike != null ? ce.strike : "–";
  ceDist.textContent    = ce.distance != null ? ce.distance : "–";
  ceEntry.textContent   = ce.entry != null ? ce.entry : "–";
  ceSL.textContent      = ce.stopLoss != null ? ce.stopLoss : "–";
  ceTarget.textContent  = ce.target != null ? ce.target : "–";

  // PE
  peStrike.textContent  = pe.strike != null ? pe.strike : "–";
  peDist.textContent    = pe.distance != null ? pe.distance : "–";
  peEntry.textContent   = pe.entry != null ? pe.entry : "–";
  peSL.textContent      = pe.stopLoss != null ? pe.stopLoss : "–";
  peTarget.textContent  = pe.target != null ? pe.target : "–";

  // STRADDLE
  strStrike.textContent = str.strike != null ? str.strike : "–";
  strDist.textContent   = str.distance != null ? str.distance : "–";
  strEntry.textContent  = str.entry != null ? str.entry : "–";
  strSL.textContent     = str.stopLoss != null ? str.stopLoss : "–";
  strTarget.textContent = str.target != null ? str.target : "–";
}

function renderMeta(data) {
  metaCard.classList.remove("hidden");

  const loginStatus = data.login_status || "Unknown";
  const metaInfo    = data.meta || {};
  const auto        = data.auto_tokens || {};
  const mkt         = (data.input && data.input.market) || marketSelect.value;

  // Top text
  let txt = loginStatus;
  if (metaInfo.live_data_used) {
    txt += " · Live FUT LTP used";
  } else {
    txt += " · Manual spot used";
  }
  if (metaInfo.live_error && metaInfo.live_error.reason) {
    txt += ` · Live error: ${metaInfo.live_error.reason}`;
  }
  metaText.textContent = txt;

  // Tags
  metaLoginState.textContent = "Login: " + loginStatus;
  metaLiveFlag.textContent   = "Live: " + (metaInfo.live_data_used ? "Yes" : "No");

  let tokenLabel = "Tokens: –";
  if (auto && auto[mkt]) {
    const t = auto[mkt];
    if (t.symbol || t.token) {
      tokenLabel = `Token: ${t.symbol || ""} (${t.token || "–"})`;
    }
  }
  metaTokenInfo.textContent = tokenLabel;

  // Full JSON
  jsonBox.textContent = JSON.stringify(data, null, 2);
}

// ========= CALCULATE HANDLER =========
async function handleCalculate() {
  const payload = readInputs();

  // Save server URL
  try {
    const raw = (serverUrlInput.value || "").trim();
    if (raw) localStorage.setItem(LS.server, raw);
    else localStorage.removeItem(LS.server);
  } catch (e) {}

  calcBtn.disabled = true;
  calcBtn.textContent = "Calculating…";

  clearOutput();

  try {
    const resp = await fetch(buildUrl("/api/calc"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await resp.json().catch(() => null);

    if (!data || data.success === false) {
      resultHint.textContent =
        (data && data.error) || "Calculation failed (server error)";
      if (data) {
        metaCard.classList.remove("hidden");
        metaText.textContent = "Error: " + (data.error || "Unknown");
        jsonBox.textContent = JSON.stringify(data, null, 2);
      }
      return;
    }

    // Render sections
    renderSummary(data);
    renderStrikes(data);
    renderMeta(data);

    // After calc, refresh login pill also
    refreshLoginStatus();
  } catch (e) {
    resultHint.textContent = "Network error: " + e.message;
  } finally {
    calcBtn.disabled = false;
    calcBtn.textContent = "⚡ Calculate Trend & Strikes";
  }
}

// ========= JSON TOGGLE =========
let jsonVisible = true;
function toggleJson() {
  jsonVisible = !jsonVisible;
  if (jsonVisible) {
    jsonBox.style.display = "block";
    toggleJsonBtn.textContent = "Hide JSON";
  } else {
    jsonBox.style.display = "none";
    toggleJsonBtn.textContent = "Show JSON";
  }
}

// ========= INIT =========
function loadServerFromStorage() {
  try {
    const s = localStorage.getItem(LS.server);
    if (s) serverUrlInput.value = s;
  } catch (e) {}
}

function initEvents() {
  marketSelect.addEventListener("change", updateMarketChip);
  calcBtn.addEventListener("click", handleCalculate);
  toggleJsonBtn.addEventListener("click", toggleJson);

  themeSelect.addEventListener("change", () => {
    saveThemeToStorage();
  });

  accentSelect.addEventListener("change", () => {
    saveThemeToStorage();
  });

  openSettingsBtn.addEventListener("click", () => {
    // अलग settings.html page पर जाओ
    window.location.href = "settings.html";
  });
}

function init() {
  loadServerFromStorage();
  loadThemeFromStorage();
  updateMarketChip();
  initEvents();
  refreshLoginStatus();

  // JSON default: visible
  jsonVisible = true;
  jsonBox.style.display = "block";
  toggleJsonBtn.textContent = "Hide JSON";
}

// Script body के अंत में है, फिर भी safe रहने के लिए:
document.addEventListener("DOMContentLoaded", init);
