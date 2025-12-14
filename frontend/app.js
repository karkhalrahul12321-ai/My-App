// ============ SHORTCUT ============
const $ = (id) => document.getElementById(id);

// LocalStorage keys
const LS_KEYS = {
  server: "th_server_url",
  theme: "th_theme",
  accent: "th_accent",
};

// Theme + Accent options
const THEMES = [
  { value: "light", label: "Light" },
  { value: "soft", label: "Soft Grey" },
  { value: "blue", label: "Blue Pro" },
  { value: "warm", label: "Warm" },
  { value: "dark", label: "Dark" },
];

const ACCENTS = [
  { value: "blue", label: "Blue" },
  { value: "green", label: "Green" },
  { value: "teal", label: "Teal" },
  { value: "orange", label: "Orange" },
  { value: "purple", label: "Purple" },
];

// ============ THEME INIT ============
function initThemeControls() {
  const themeDrop = $("themeDropdown");
  const accentDrop = $("accentDropdown");

  // Fill options
  themeDrop.innerHTML = THEMES.map(
    (t) => `<option value="${t.value}">${t.label}</option>`
  ).join("");

  accentDrop.innerHTML = ACCENTS.map(
    (a) => `<option value="${a.value}">${a.label}</option>`
  ).join("");

  // Restore from LS
  const savedTheme = localStorage.getItem(LS_KEYS.theme) || "light";
  const savedAccent = localStorage.getItem(LS_KEYS.accent) || "blue";

  document.body.dataset.theme = savedTheme;
  document.body.dataset.accent = savedAccent;

  themeDrop.value = savedTheme;
  accentDrop.value = savedAccent;

  themeDrop.addEventListener("change", () => {
    const v = themeDrop.value;
    document.body.dataset.theme = v;
    localStorage.setItem(LS_KEYS.theme, v);
  });

  accentDrop.addEventListener("change", () => {
    const v = accentDrop.value;
    document.body.dataset.accent = v;
    localStorage.setItem(LS_KEYS.accent, v);
  });
}

// ============ SERVER URL ============
function getServerBase() {
  const input = $("serverUrl");
  const val = (input.value || "").trim();
  if (!val) return "";
  return val.replace(/\/+$/, "");
}

function loadServerUrl() {
  const s = localStorage.getItem(LS_KEYS.server);
  if (s) $("serverUrl").value = s;
}

function saveServerUrl() {
  const v = $("serverUrl").value.trim();
  localStorage.setItem(LS_KEYS.server, v);
}

// ============ LOGIN STATUS PING ============
async function checkLoginStatus() {
  const base = getServerBase();
  const url = base ? base + "/api/login/status" : "/api/login/status";

  const pill = $("loginStatusPill");
  const dot = $("loginDot");
  const txt = $("loginStatusText");
  const serverStatus = $("serverStatus");

  function setState(state, message) {
    pill.classList.remove("status-idle");
    dot.classList.remove("idle", "ok", "bad");

    if (state === "ok") {
      dot.classList.add("ok");
      txt.textContent = "SmartAPI Logged-In";
      serverStatus.textContent = "Server OK";
    } else if (state === "not") {
      dot.classList.add("bad");
      txt.textContent = "Not logged-in (demo mode)";
      serverStatus.textContent = "Server OK";
    } else {
      dot.classList.add("bad");
      txt.textContent = "Server error";
      serverStatus.textContent = message || "Server error";
    }
  }

  try {
    const resp = await fetch(url);
    if (!resp.ok) {
      setState("err", "HTTP " + resp.status);
      return;
    }
    const data = await resp.json().catch(() => null);
    if (!data || data.success === false) {
      setState("err", "Invalid response");
      return;
    }
    if (data.logged_in) {
      setState("ok");
    } else {
      setState("not");
    }
  } catch (e) {
    setState("err", e.message);
  }
}

// ============ MARKET CHIP ============
function updateMarketChip() {
  const m = $("market").value;
  const chip = $("marketChip");
  if (m === "sensex") chip.textContent = "SENSEX · FUT";
  else if (m === "natural gas") chip.textContent = "NATURAL GAS · FUT";
  else chip.textContent = "NIFTY · FUT";
}

// ============ RENDER RESULT ============
function fillSummary(data) {
  const { trend, input, meta, login_status } = data;

  $("summaryRow").classList.remove("hidden");

  $("sumTrend").textContent = trend?.main || "–";
  $("sumStrength").textContent = trend?.strength || "–";

  const bias = trend?.bias || "NONE";
  $("sumBias").textContent = "Bias " + bias;

  const score = typeof trend?.score === "number" ? trend.score.toFixed(1) : "–";
  $("sumScore").textContent = "Score " + score;

  const liveUsed = meta?.live_data_used ? "Live (Future LTP)" : "Manual Inputs";
  $("sumLiveUsed").textContent = liveUsed;

  const spot = input?.spot ? Number(input.spot) : null;
  $("sumSpot").textContent = spot ? "Spot " + spot : "Spot –";

  $("resultHint").textContent = "Last updated just now";
}

function fillStrikes(data) {
  const arr = data.strikes || [];
  if (arr.length < 3) {
    $("strikeCards").classList.add("hidden");
    return;
  }
  $("strikeCards").classList.remove("hidden");

  const ce = arr[0];
  const pe = arr[1];
  const st = arr[2];

  $("ceStrike").textContent = ce.strike || "-";
  $("ceDist").textContent = ce.distance || "-";
  $("ceEntry").textContent = ce.entry || "-";
  $("ceSL").textContent = ce.stopLoss || "-";
  $("ceTarget").textContent = ce.target || "-";

  $("peStrike").textContent = pe.strike || "-";
  $("peDist").textContent = pe.distance || "-";
  $("peEntry").textContent = pe.entry || "-";
  $("peSL").textContent = pe.stopLoss || "-";
  $("peTarget").textContent = pe.target || "-";

  $("strStrike").textContent = st.strike || "-";
  $("strDist").textContent = st.distance || "-";
  $("strEntry").textContent = st.entry || "-";
  $("strSL").textContent = st.stopLoss || "-";
  $("strTarget").textContent = st.target || "-";
}

function summarizeTokens(autoTokens) {
  if (!autoTokens) return "Tokens –";
  const parts = [];
  for (const key of Object.keys(autoTokens)) {
    const item = autoTokens[key];
    if (item && item.symbol) {
      parts.push(`${key}: ${item.symbol}`);
    }
  }
  return parts.length ? parts.join(" | ") : "Tokens –";
}

function fillMetaAndJson(data) {
  const metaCard = $("metaCard");
  metaCard.classList.remove("hidden");

  const loginState = data.login_status || "";
  const liveUsed = data.meta?.live_data_used;
  const liveText = liveUsed ? "Live LTP used" : "Manual Inputs";
  $("metaText").textContent = `${loginState} · ${liveText}`;

  $("metaLoginState").textContent = "Login: " + (loginState || "–");
  $("metaLiveFlag").textContent = "Live: " + (liveUsed ? "YES" : "NO");

  $("metaTokenInfo").textContent = summarizeTokens(data.auto_tokens);

  $("jsonBox").textContent = JSON.stringify(data, null, 2);
}

// ============ CALCULATE ============
async function onCalculate() {
  const base = getServerBase();
  const url = base ? base + "/api/calc" : "/api/calc";

  const payload = {
    ema20: Number($("ema20").value) || 0,
    ema50: Number($("ema50").value) || 0,
    rsi: Number($("rsi").value) || 0,
    vwap: Number($("vwap").value) || 0,
    spot: Number($("spot").value) || 0,
    market: $("market").value.toUpperCase(),
    expiry_days: Number($("expiryDays").value) || 7,
    use_live: $("useLive").checked
  };

  $("calcBtn").disabled = true;
  $("resultHint").textContent = "Calculating…";

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await resp.json().catch(() => null);

    if (!data || data.success === false) {
      $("resultHint").textContent = "Error: " + (data?.error || "Unknown");
      return;
    }

    fillSummary(data);
    fillStrikes(data);
    fillMetaAndJson(data);
  } catch (e) {
    $("resultHint").textContent = "Network error: " + e.message;
  } finally {
    $("calcBtn").disabled = false;
  }
}

// ============ JSON TOGGLE ============
function initJsonToggle() {
  const btn = $("toggleJsonBtn");
  const box = $("jsonBox");
  let visible = true;

  btn.addEventListener("click", () => {
    visible = !visible;
    if (visible) {
      box.classList.remove("hidden");
      btn.textContent = "Hide JSON";
    } else {
      box.classList.add("hidden");
      btn.textContent = "Show JSON";
    }
  });
}

// ============ INIT ============
document.addEventListener("DOMContentLoaded", () => {
  initThemeControls();
  loadServerUrl();
  updateMarketChip();
  checkLoginStatus();
  initJsonToggle();

  $("serverUrl").addEventListener("change", () => {
    saveServerUrl();
    checkLoginStatus();
  });

  $("market").addEventListener("change", updateMarketChip);
  $("calcBtn").addEventListener("click", onCalculate);

  $("openSettingsBtn").addEventListener("click", () => {
    window.location.href = "settings.html";
  });
});
