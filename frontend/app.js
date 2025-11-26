// ===========================
// SHORTCUT
// ===========================
const $ = (id) => document.getElementById(id);

// ===========================
// LOCAL STORAGE KEYS
// ===========================
const LS = {
  server: "th_server",
  theme: "th_theme",
  accent: "th_accent",
  password: "th_pw"
};

// ===========================
// INITIAL LOAD
// ===========================
window.onload = () => {
  loadTheme();
  loadAccent();
  loadServer();
  loadSavedPassword();
  updateLoginStatus();
};

// ===========================
// THEME HANDLING
// ===========================
function loadTheme() {
  const saved = localStorage.getItem(LS.theme) || "light";
  document.documentElement.setAttribute("data-theme", saved);
  $("themeSelect").value = saved;
}

$("themeSelect").onchange = () => {
  const v = $("themeSelect").value;
  document.documentElement.setAttribute("data-theme", v);
  localStorage.setItem(LS.theme, v);
};

// ===========================
// ACCENT HANDLING
// ===========================
function loadAccent() {
  const saved = localStorage.getItem(LS.accent) || "blue";
  document.documentElement.setAttribute("data-accent", saved);
  $("accentSelect").value = saved;
}

$("accentSelect").onchange = () => {
  const v = $("accentSelect").value;
  document.documentElement.setAttribute("data-accent", v);
  localStorage.setItem(LS.accent, v);
};

// ===========================
// SERVER URL
// ===========================
function loadServer() {
  const s = localStorage.getItem(LS.server);
  if (s) $("serverUrl").value = s;
  $("serverUrl").onblur = () => {
    localStorage.setItem(LS.server, $("serverUrl").value.trim());
  };
}

function getServer() {
  const s = $("serverUrl").value.trim();
  return s ? s : "";
}

// ===========================
// PASSWORD LOCAL SAVE
// ===========================
function loadSavedPassword() {
  const pw = localStorage.getItem(LS.password);
  if (pw) $("pwInput").value = pw;
}

$("pwInput")?.addEventListener("input", () => {
  localStorage.setItem(LS.password, $("pwInput").value.trim());
});

// ===========================
// SETTINGS PAGE OPEN/CLOSE
// ===========================
$("openSettingsBtn").onclick = () => {
  window.location.href = "settings.html";
};

// ===========================
// CHECK LOGIN STATUS
// ===========================
async function updateLoginStatus() {
  try {
    const resp = await fetch("/api/login/status");
    const data = await resp.json();

    if (data.logged_in) {
      $("loginStatusPill").className = "status-pill status-ok";
      $("loginDot").className = "status-dot ok";
      $("loginStatusText").textContent = "Logged-In";
    } else {
      $("loginStatusPill").className = "status-pill status-bad";
      $("loginDot").className = "status-dot bad";
      $("loginStatusText").textContent = "Not Logged-In";
    }
  } catch (err) {
    $("loginStatusPill").className = "status-pill status-bad";
    $("loginDot").className = "status-dot bad";
    $("loginStatusText").textContent = "Server Error";
  }
}

// ===========================
// SMARTAPI LOGIN (AUTO WHEN LIVE MODE)
// ===========================
async function smartLogin() {
  const pw = localStorage.getItem(LS.password) || "";

  if (!pw) {
    alert("Please enter Trading Password in Settings page");
    return false;
  }

  try {
    const resp = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw })
    });

    const data = await resp.json();

    if (!data.success) {
      alert("SmartAPI Login Failed");
      return false;
    }

    updateLoginStatus();
    return true;
  } catch (e) {
    alert("Network error during login");
    return false;
  }
}

// ===========================
// CALCULATE BUTTON
// ===========================
$("calcBtn").onclick = () => calc();

async function calc() {
  const server = getServer();
  const url = server ? server + "/api/calc" : "/api/calc";

  const payload = {
    ema20: Number($("ema20").value) || 0,
    ema50: Number($("ema50").value) || 0,
    rsi: Number($("rsi").value) || 0,
    vwap: Number($("vwap").value) || 0,
    spot: Number($("spot").value) || 0,
    market: $("market").value,
    expiry_days: Number($("expiryDays").value) || 7,
    use_live: $("useLive").checked
  };

  // LIVE DATA → auto login
  if (payload.use_live) {
    const ok = await smartLogin();
    if (!ok) payload.use_live = false;
  }

  $("resultHint").textContent = "Calculating...";

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await resp.json();
    renderOutput(data);
  } catch (e) {
    $("resultHint").textContent = "Network Error";
  }
}

// ===========================
// RENDER OUTPUT
// ===========================
function renderOutput(data) {
  if (!data.success) {
    $("resultHint").textContent = "Error: " + (data.error || "");
    return;
  }

  $("summaryRow").classList.remove("hidden");
  $("strikeCards").classList.remove("hidden");
  $("metaCard").classList.remove("hidden");

  // SUMMARY
  $("sumTrend").textContent = data.trend.main;
  $("sumStrength").textContent = data.trend.strength;
  $("sumBias").textContent = data.trend.bias;
  $("sumScore").textContent = Math.round(data.trend.score);

  $("sumLiveUsed").textContent = data.meta.live_data_used ? "Live" : "Manual";
  $("sumSpot").textContent = data.input.spot;

  // MARKET CHIP
  $("marketChip").textContent = data.input.market.toUpperCase();

  // STRIKES
  const ce = data.strikes[0];
  const pe = data.strikes[1];
  const st = data.strikes[2];

  $("ceStrike").textContent = ce.strike;
  $("ceDist").textContent = ce.distance;
  $("ceEntry").textContent = ce.entry;
  $("ceSL").textContent = ce.stopLoss;
  $("ceTarget").textContent = ce.target;

  $("peStrike").textContent = pe.strike;
  $("peDist").textContent = pe.distance;
  $("peEntry").textContent = pe.entry;
  $("peSL").textContent = pe.stopLoss;
  $("peTarget").textContent = pe.target;

  $("strStrike").textContent = st.strike;
  $("strDist").textContent = st.distance;
  $("strEntry").textContent = st.entry;
  $("strSL").textContent = st.stopLoss;
  $("strTarget").textContent = st.target;

  // META
  $("metaText").textContent = data.message;
  $("metaLoginState").textContent = "Login: " + data.login_status;
  $("metaLiveFlag").textContent = "Live: " + data.meta.live_data_used;
  $("metaTokenInfo").textContent = "Tokens Loaded";

  // FULL JSON
  $("jsonBox").textContent = JSON.stringify(data, null, 2);
}

// ===========================
// JSON HIDE / SHOW
// ===========================
$("toggleJsonBtn").onclick = () => {
  const box = $("jsonBox");
  if (box.style.display === "none") {
    box.style.display = "block";
    $("toggleJsonBtn").textContent = "Hide JSON";
  } else {
    box.style.display = "none";
    $("toggleJsonBtn").textContent = "Show JSON";
  }
};
