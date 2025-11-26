/* ======================================================
      Trading Helper – Frontend Logic (Final Build)
   ====================================================== */

const $ = (id) => document.getElementById(id);

// MAIN TABS
const panelMain = $("panel-main");
const panelSettings = $("panel-settings");

// UI ELEMENTS
const loginStatusPill = $("loginStatusPill");
const loginStatusText = $("loginStatusText");
const loginDot = $("loginDot");

const calcBtn = $("calcBtn");
const useLiveSwitch = $("useLiveSwitch");
const marketChip = $("marketChip");

const summaryGrid = $("summaryGrid");
const strikeList = $("strikeList");

// LOCAL STORAGE KEYS
const LS = {
  server: "th_server_url",
  pw: "SMART_PASSWORD"
};

/* ---------------------------------------------------
    Load + Apply Local Settings
---------------------------------------------------- */
function loadSettings() {
  const server = localStorage.getItem(LS.server) || "";
  if (server) $("serverUrl").value = server;

  checkLoginStatus();
}

loadSettings();

/* ---------------------------------------------------
    Login Status Checker
---------------------------------------------------- */
async function checkLoginStatus() {
  try {
    const server = $("serverUrl").value.trim() || "";
    const url = server ? server + "/api/login/status" : "/api/login/status";

    const r = await fetch(url);
    const j = await r.json();

    if (j.logged_in) {
      loginStatusPill.className = "status-pill status-ok";
      loginDot.className = "status-dot ok";
      loginStatusText.textContent = "Logged-in ✔";
    } else {
      loginStatusPill.className = "status-pill status-idle";
      loginDot.className = "status-dot idle";
      loginStatusText.textContent = "Not logged-in";
    }
  } catch (e) {
    loginStatusPill.className = "status-pill status-bad";
    loginDot.className = "status-dot bad";
    loginStatusText.textContent = "Server error";
  }
}

/* ---------------------------------------------------
    SETTINGS PANEL SWITCHING
---------------------------------------------------- */
$("openSettingsBtn").onclick = () => openSettings();
$("tab-settings")?.addEventListener("click", openSettings);

function openSettings() {
  panelMain.classList.add("hidden");
  panelSettings.classList.remove("hidden");
}

$("tab-main")?.addEventListener("click", () => {
  panelSettings.classList.add("hidden");
  panelMain.classList.remove("hidden");
});

/* ---------------------------------------------------
    Toggle Switch
---------------------------------------------------- */
useLiveSwitch.onclick = () => {
  useLiveSwitch.classList.toggle("on");
};

/* ---------------------------------------------------
    SmartAPI LOGIN before calc (if needed)
---------------------------------------------------- */
async function ensureLogin() {
  const pwd = localStorage.getItem(LS.pw);

  if (!pwd) {
    alert("Go to Settings and save your Trading Password.");
    return false;
  }

  const server = $("serverUrl").value.trim() || "";
  const url = server ? server + "/api/login" : "/api/login";

  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: pwd })
  });

  const j = await r.json();
  if (!j.success) {
    alert("Login failed: " + (j.error || "Unknown"));
    return false;
  }

  await checkLoginStatus();
  return true;
}

/* ---------------------------------------------------
    MAIN CALCULATION
---------------------------------------------------- */
calcBtn.onclick = calc;

async function calc() {
  summaryGrid.style.display = "none";
  strikeList.style.display = "none";

  const live = useLiveSwitch.classList.contains("on");

  const payload = {
    ema20: Number($("ema20").value) || 0,
    ema50: Number($("ema50").value) || 0,
    rsi: Number($("rsi").value) || 0,
    vwap: Number($("vwap").value) || 0,
    spot: Number($("spot").value) || 0,
    market: $("market").value,
    expiry_days: Number($("expiryDays").value) || 7,
    use_live: live
  };

  // If live data is ON → must login
  if (live) {
    const ok = await ensureLogin();
    if (!ok) payload.use_live = false;
  }

  const server = $("serverUrl").value.trim() || "";
  const url = server ? server + "/api/calc" : "/api/calc";

  calcBtn.disabled = true;
  calcBtn.innerHTML = "⏳ Calculating…";

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const j = await r.json();

    showResult(j);
  } catch (err) {
    alert("Network error: " + err.message);
  }

  calcBtn.disabled = false;
  calcBtn.innerHTML = "⚡ CALCULATE TREND & STRIKES";
}

/* ---------------------------------------------------
    RENDER RESULT IN UI
---------------------------------------------------- */
function showResult(j) {
  if (!j.success) {
    alert("Error: " + j.error);
    return;
  }

  // Summary
  $("sumTrend").textContent = j.trend.main || "-";
  $("sumStrength").textContent = j.trend.strength || "-";
  $("sumBiasBadge").textContent = j.trend.bias || "-";
  $("sumScoreBadge").textContent = "Score " + Math.round(j.trend.score);

  $("sumLiveUsed").textContent = j.meta.live_data_used ? "Live" : "Manual";
  $("sumLtpBadge").textContent =
    "Spot " + (j.meta.live_ltp || j.input.spot || "-");

  summaryGrid.style.display = "grid";

  // Strikes
  $("strikeCELabel").textContent = j.strikes[0].type + " " + j.strikes[0].strike;
  $("strikeCEValues").textContent =
    "Entry " +
    j.strikes[0].entry +
    " • SL " +
    j.strikes[0].stopLoss +
    " • Target " +
    j.strikes[0].target;

  $("strikePELabel").textContent = j.strikes[1].type + " " + j.strikes[1].strike;
  $("strikePEValues").textContent =
    "Entry " +
    j.strikes[1].entry +
    " • SL " +
    j.strikes[1].stopLoss +
    " • Target " +
    j.strikes[1].target;

  $("strikeSTRLabel").textContent =
    j.strikes[2].type + " " + j.strikes[2].strike;
  $("strikeSTRValues").textContent =
    "Entry " +
    j.strikes[2].entry +
    " • SL " +
    j.strikes[2].stopLoss +
    " • Target " +
    j.strikes[2].target;

  strikeList.style.display = "block";
}

/* ---------------------------------------------------
    Auto Mode Chip
---------------------------------------------------- */
$("market").onchange = () => {
  const m = $("market").value.toUpperCase();
  marketChip.textContent = m + " • FUT";
};

/* ---------------------------------------------------
    Auto Save Server URL
---------------------------------------------------- */
$("serverUrl").onchange = () => {
  const v = $("serverUrl").value.trim();
  if (v) localStorage.setItem(LS.server, v);
};
