/* ============================================================
   SHORTCUTS
============================================================ */
const el = (id) => document.getElementById(id);

/* ============================================================
   THEME & ACCENT INIT
============================================================ */
function initThemeControls() {
  const themeDD = el("themeDropdown");
  const accentDD = el("accentDropdown");

  const themes = ["light", "soft", "blue", "warm", "dark"];
  const accents = ["blue", "green", "teal", "orange", "purple"];

  themeDD.innerHTML = themes.map(t => `<option value="${t}">${t}</option>`).join("");
  accentDD.innerHTML = accents.map(a => `<option value="${a}">${a}</option>`).join("");

  const savedTheme = localStorage.getItem("theme") || "light";
  const savedAccent = localStorage.getItem("accent") || "blue";

  document.body.dataset.theme = savedTheme;
  document.body.dataset.accent = savedAccent;

  themeDD.value = savedTheme;
  accentDD.value = savedAccent;

  themeDD.onchange = () => {
    document.body.dataset.theme = themeDD.value;
    localStorage.setItem("theme", themeDD.value);
  };

  accentDD.onchange = () => {
    document.body.dataset.accent = accentDD.value;
    localStorage.setItem("accent", accentDD.value);
  };
}

/* ============================================================
   SERVER URL + STATUS
============================================================ */
async function checkServerStatus() {
  const server = el("serverUrl").value.trim();
  const status = el("serverStatus");

  if (!server) {
    status.textContent = "Enter Render URL";
    return;
  }

  status.textContent = "Checking…";

  try {
    const r = await fetch(server + "/api/login/status");
    const j = await r.json();

    if (j.logged_in) {
      status.textContent = "SmartAPI Logged-In";
    } else {
      status.textContent = "Not Logged-In (demo mode)";
    }
  } catch {
    status.textContent = "Server Offline / Wrong URL";
  }
}

/* ============================================================
   SMARTAPI LOGIN HELPER
============================================================ */
async function attemptSmartLogin(server) {
  const pwd = localStorage.getItem("SMART_PASSWORD") || "";

  if (!pwd) {
    alert("⚠️ Settings में SmartAPI password सेव करें");
    return false;
  }

  try {
    const r = await fetch(server + "/api/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ password: pwd })
    });

    const j = await r.json();
    if (!j.success) {
      alert("SmartAPI Login Failed");
      return false;
    }

    return true;
  } catch {
    alert("Network Error during login");
    return false;
  }
}

/* ============================================================
   MAIN CALCULATE
============================================================ */
async function calculateNow() {
  const server = el("serverUrl").value.trim();
  if (!server) return alert("Server URL डालो");

  const useLive = el("useLive").checked;

  const payload = {
    ema20: Number(el("ema20").value),
    ema50: Number(el("ema50").value),
    rsi: Number(el("rsi").value),
    vwap: Number(el("vwap").value),
    spot: Number(el("spot").value),
    market: el("market").value,
    expiry_days: Number(el("expiryDays").value),
    use_live: useLive
  };

  el("resultBox").textContent = "Processing...";
  el("liveBox").textContent = "";

  // LOGIN FIRST IF LIVE MODE
  if (useLive) {
    const ok = await attemptSmartLogin(server);
    if (!ok) payload.use_live = false;
  }

  try {
    const r = await fetch(server + "/api/calc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const j = await r.json();

    // Show JSON result
    el("resultHint").textContent = "Done";
    el("resultBox").textContent = JSON.stringify(j, null, 2);

    // Live box
    el("liveBox").textContent = JSON.stringify(j.meta || {}, null, 2);

  } catch (err) {
    el("resultBox").textContent = "Network Error: " + err.message;
  }
}

/* ============================================================
   PAGE INIT
============================================================ */
window.onload = () => {
  initThemeControls();

  // Restore last server URL
  const savedServer = localStorage.getItem("serverUrl") || "";
  if (savedServer) el("serverUrl").value = savedServer;

  // Check server automatically
  if (savedServer) checkServerStatus();

  // Save server URL on change
  el("serverUrl").oninput = () => {
    localStorage.setItem("serverUrl", el("serverUrl").value.trim());
  };

  // Calculate button
  el("calcBtn").onclick = calculateNow;
};
