/* ============================================================
   LOCAL STORAGE HELPERS
============================================================ */
function saveLocal(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function loadLocal(key, fallback = null) {
  const raw = localStorage.getItem(key);
  if (!raw) return fallback;
  try { return JSON.parse(raw); } catch { return fallback; }
}

/* ============================================================
   LOAD SAVED THEME + ACCENT
============================================================ */
(function applySavedTheme() {
  const theme = loadLocal("theme", "soft");
  const accent = loadLocal("accent", "blue");

  document.body.setAttribute("data-theme", theme);
  document.body.setAttribute("data-accent", accent);

  const themeSel = document.getElementById("themeSelector");
  const accentSel = document.getElementById("accentSelector");

  if (themeSel) themeSel.value = theme;
  if (accentSel) accentSel.value = accent;
})();

/* ============================================================
   THEME + ACCENT EVENT LISTENERS
============================================================ */
document.addEventListener("DOMContentLoaded", () => {

  const themeSelector = document.getElementById("themeSelector");
  const accentSelector = document.getElementById("accentSelector");

  if (themeSelector) {
    themeSelector.addEventListener("change", () => {
      document.body.setAttribute("data-theme", themeSelector.value);
      saveLocal("theme", themeSelector.value);
    });
  }

  if (accentSelector) {
    accentSelector.addEventListener("change", () => {
      document.body.setAttribute("data-accent", accentSelector.value);
      saveLocal("accent", accentSelector.value);
    });
  }
});

/* ============================================================
   SETTINGS PAGE (SmartAPI Keys)
============================================================ */
document.addEventListener("DOMContentLoaded", () => {
  const apiKeyInput = document.getElementById("apiKey");
  const userIdInput = document.getElementById("userId");
  const totpInput = document.getElementById("totpSecret");
  const pinInput = document.getElementById("tradingPin");
  const saveBtn = document.getElementById("saveSettings");

  if (apiKeyInput && userIdInput && totpInput && pinInput && saveBtn) {
    // Load saved values
    apiKeyInput.value = loadLocal("smartapi_key", "");
    userIdInput.value = loadLocal("smartapi_user", "");
    totpInput.value = loadLocal("smartapi_totp", "");
    pinInput.value = loadLocal("trade_pin", "");

    saveBtn.addEventListener("click", () => {
      saveLocal("smartapi_key", apiKeyInput.value.trim());
      saveLocal("smartapi_user", userIdInput.value.trim());
      saveLocal("smartapi_totp", totpInput.value.trim());
      saveLocal("trade_pin", pinInput.value.trim());

      alert("✅ Settings Saved Successfully!");
    });
  }
});

/* ============================================================
   SERVER URL VALIDATION (Render Backend)
============================================================ */
const serverURLInput = document.getElementById("serverURL");
const serverStatus = document.getElementById("serverStatus");

async function validateServer() {
  const url = serverURLInput.value.trim();
  saveLocal("server_url", url);

  if (!url) {
    serverStatus.textContent = "❌ Invalid URL";
    return false;
  }

  try {
    serverStatus.textContent = "Checking...";
    const res = await fetch(url + "/ping");
    const data = await res.json();

    if (data.status === "ok") {
      serverStatus.textContent = "✅ Server Connected";
      return true;
    } else {
      serverStatus.textContent = "❌ Server Not Responding";
      return false;
    }
  } catch {
    serverStatus.textContent = "❌ Failed to connect";
    return false;
  }
}

if (serverURLInput) {
  serverURLInput.value = loadLocal("server_url", "");
  if (serverURLInput.value) validateServer();
  serverURLInput.addEventListener("change", validateServer);
}

/* ============================================================
   CALCULATE BUTTON
============================================================ */
const calcBtn = document.getElementById("calcBtn");
if (calcBtn) {
  calcBtn.addEventListener("click", async () => {
    const url = loadLocal("server_url", "");
    if (!url) return alert("❗ पहले Server URL सेट करो");

    const req = {
      ema20: Number(document.getElementById("ema20").value),
      ema50: Number(document.getElementById("ema50").value),
      rsi: Number(document.getElementById("rsi").value),
      vwap: Number(document.getElementById("vwap").value),
      ltp: Number(document.getElementById("spotLtp").value),
      market: document.getElementById("market").value,
      expiry: Number(document.getElementById("expiryDays").value)
    };

    try {
      const res = await fetch(url + "/calculate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req)
      });

      const data = await res.json();
      updateUI(data);

    } catch (e) {
      alert("❌ Server Error!");
    }
  });
}

/* ============================================================
   UPDATE UI AFTER CALCULATION
============================================================ */
function updateUI(data) {
  if (!data) return;

  // Trend Overview
  document.getElementById("trendText").textContent = data.trend;
  document.getElementById("strengthText").textContent = data.strengthWord;
  document.getElementById("strengthNum").textContent = data.strength;
  document.getElementById("sourceText").textContent = data.source;
  document.getElementById("sourceLtp").textContent = data.price;

  // Smart Strikes
  const strikeBox = document.getElementById("strikeBox");
  strikeBox.innerHTML = "";

  data.strikes.forEach(s => {
    strikeBox.innerHTML += `
      <div class="card">
        <div class="card-header">
          <div class="card-title">${s.type}</div>
          <div class="tag">${s.strike}</div>
        </div>
        <div>Distance: ${s.distance}</div>
        <div>Premium: ${s.premium}</div>
      </div>
    `;
  });

  // Meta Info
  document.getElementById("metaLogin").textContent = data.login;
  document.getElementById("metaLtp").textContent = data.price;
  document.getElementById("metaToken").textContent = data.tokens;

  // Raw JSON
  document.getElementById("jsonBox").textContent =
    JSON.stringify(data, null, 2);
}

/* END OF FINAL app.js */
