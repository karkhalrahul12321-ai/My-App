// ==========================
// Trading Helper – Final JS
// Fully matched with new UI
// ==========================

// QUICK SELECTOR
const $ = (id) => document.getElementById(id);

// ELEMENTS
const serverInput = $("server");
const calcBtn = $("calc");
const outputBox = $("outputBox");
const toggleOut = $("toggleOut");

const ema20 = $("ema20");
const ema50 = $("ema50");
const rsi = $("rsi");
const vwap = $("vwap");
const spot = $("spot");
const market = $("market");
const expiry = $("expiry");
const useLive = $("useLive");

const themeSelect = $("themeSelect");
const colorPick = $("colorPick");

const openSettings = $("openSettings");

// ========================
// SAVE / LOAD LOCAL SETTINGS
// ========================
(function loadInitial() {
  // Load theme
  const th = localStorage.getItem("th_theme");
  if (th) {
    themeSelect.value = th;
    applyTheme(th);
  }

  // Load accent
  const ac = localStorage.getItem("th_accent");
  if (ac) {
    colorPick.value = ac;
    document.documentElement.style.setProperty("--accent", ac);
  }

  // Load server URL
  const su = localStorage.getItem("th_server");
  if (su) serverInput.value = su;
})();

themeSelect.onchange = () => {
  const th = themeSelect.value;
  applyTheme(th);
  localStorage.setItem("th_theme", th);
};

colorPick.onchange = () => {
  const val = colorPick.value;
  document.documentElement.style.setProperty("--accent", val);
  localStorage.setItem("th_accent", val);
};

function applyTheme(t) {
  document.body.className = "";
  if (t === "dark") document.body.classList.add("theme-dark");
  if (t === "light") document.body.classList.add("theme-light");
  if (t === "neon") document.body.classList.add("theme-neon");
  if (t === "glass") document.body.classList.add("theme-glass");
}

// ========================
// SETTINGS BUTTON
// ========================
openSettings.onclick = () => {
  window.location.href = "settings.html";
};

// ========================
// TOGGLE OUTPUT
// ========================
toggleOut.onclick = () => {
  if (outputBox.classList.contains("hidden")) {
    outputBox.classList.remove("hidden");
    toggleOut.textContent = "▲ Hide Output";
  } else {
    outputBox.classList.add("hidden");
    toggleOut.textContent = "▼ Show Output";
  }
};

// ========================
// SMARTAPI LOGIN
// ========================
async function ensureLogin() {
  const pwd = localStorage.getItem("SMART_PASSWORD") || "";
  if (!pwd) {
    alert("पहले Settings में password save करो।");
    return false;
  }

  const server = getServer() + "/api/login";

  try {
    const r = await fetch(server, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pwd })
    });

    const j = await r.json();

    if (!j.success) {
      alert("SmartAPI Login failed: " + (j.error || "Unknown"));
      return false;
    }
    return true;
  } catch (err) {
    alert("Login network error: " + err.message);
    return false;
  }
}

// ========================
// SERVER URL HANDLER
// ========================
function getServer() {
  const s = serverInput.value.trim();
  if (s === "") return "";
  localStorage.setItem("th_server", s);
  return s;
}

// ========================
// CALCULATE (MAIN)
// ========================
calcBtn.onclick = async () => {
  const server = getServer();
  const url = (server ? server : "") + "/api/calc";

  const payload = {
    ema20: Number(ema20.value) || 0,
    ema50: Number(ema50.value) || 0,
    rsi: Number(rsi.value) || 0,
    vwap: Number(vwap.value) || 0,
    spot: Number(spot.value) || 0,
    market: market.value,
    expiry_days: Number(expiry.value) || 7,
    use_live: useLive.checked
  };

  outputBox.classList.remove("hidden");
  toggleOut.textContent = "▲ Hide Output";
  outputBox.textContent = "Calculating…";

  try {
    // If using LIVE
    if (payload.use_live) {
      const ok = await ensureLogin();
      if (!ok) payload.use_live = false;
    }

    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const json = await resp.json();
    outputBox.textContent = JSON.stringify(json, null, 2);
  } catch (err) {
    outputBox.textContent = "Network Error: " + err.message;
  }
};
