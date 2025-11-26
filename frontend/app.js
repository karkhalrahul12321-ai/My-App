// =============================
// Trading Helper Frontend (FINAL)
// Themes + Color Picker + Big Output Box
// =============================

// Shortcuts
const $ = (id) => document.getElementById(id);

// UI Elements
const serverUrl = $("server");
const ema20 = $("ema20");
const ema50 = $("ema50");
const rsi = $("rsi");
const vwap = $("vwap");
const spot = $("spot");
const market = $("market");
const expiry = $("expiry");
const useLive = $("useLive");
const outputBox = $("out");

// Theme Elements
const themeSelector = $("themeSelect");
const colorPicker = $("themeColor");

// =============================
// Local Storage Load
// =============================
window.onload = () => {
  // Load Server
  const s = localStorage.getItem("server");
  if (s) serverUrl.value = s;

  // Load Theme
  const th = localStorage.getItem("theme") || "dark";
  themeSelector.value = th;
  applyTheme(th);

  // Load Custom Color
  const col = localStorage.getItem("themeColor");
  if (col) {
    colorPicker.value = col;
    document.documentElement.style.setProperty("--accent", col);
  }
};

// =============================
// Theme Handler
// =============================
function applyTheme(t) {
  document.body.setAttribute("data-theme", t);
  localStorage.setItem("theme", t);
}

themeSelector.onchange = () => {
  applyTheme(themeSelector.value);
};

// =============================
// Color Picker Handler
// =============================
colorPicker.oninput = () => {
  const c = colorPicker.value;
  document.documentElement.style.setProperty("--accent", c);
  localStorage.setItem("themeColor", c);
};

// =============================
// Server Save on Change
// =============================
serverUrl.onchange = () => {
  localStorage.setItem("server", serverUrl.value.trim());
};

// =============================
// SmartAPI Login Helper
// =============================
async function ensureSmartLogin() {
  const pwd = localStorage.getItem("SMART_PASSWORD") || "";

  if (!pwd) {
    alert("पहले Settings में जाकर password डालकर Save करो.");
    return false;
  }

  try {
    const r = await fetch(
      (serverUrl.value || "") + "/api/login",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pwd })
      }
    );

    const j = await r.json();

    if (!j.success) {
      alert("Login failed: " + (j.error || "Unknown"));
      return false;
    }

    return true;
  } catch (e) {
    alert("Network error: " + e.message);
    return false;
  }
}

// =============================
// Main Calculate Function
// =============================
$("calc").onclick = async () => {
  const server = serverUrl.value.trim();
  const url = server ? server + "/api/calc" : "/api/calc";

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

  outputBox.textContent = "⏳ Calculating...";

  try {
    // LIVE MODE → LOGIN REQUIRED
    if (payload.use_live) {
      const ok = await ensureSmartLogin();
      if (!ok) payload.use_live = false;
    }

    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const json = await r.json();
    outputBox.textContent = JSON.stringify(json, null, 2);
  } catch (e) {
    outputBox.textContent = "❌ ERROR: " + e.message;
  }
};

// =============================
// Settings Navigation
// =============================
$("openSettings").onclick = () => {
  window.location.href = "settings.html";
};
