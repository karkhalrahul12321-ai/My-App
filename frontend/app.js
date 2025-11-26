/* =======================================================
   Trading Helper — Final Stable Version
   Themes + Accents + Trend + Strikes + JSON Toggle
========================================================== */

/* ---------------------------
   Load Stored Settings
---------------------------- */
function loadThemeSettings() {
  const savedTheme = localStorage.getItem("theme") || "light";
  const savedAccent = localStorage.getItem("accent") || "blue";

  document.body.classList.remove(
    "theme-light",
    "theme-soft",
    "theme-blue",
    "theme-warm",
    "theme-dark",
    "accent-blue",
    "accent-green",
    "accent-teal",
    "accent-orange",
    "accent-purple"
  );

  document.body.classList.add(`theme-${savedTheme}`);
  document.body.classList.add(`accent-${savedAccent}`);

  document.getElementById("themeSelect").value = savedTheme;
  document.getElementById("accentSelect").value = savedAccent;
}

/* ---------------------------
   Save Theme
---------------------------- */
function saveTheme(type, value) {
  localStorage.setItem(type, value);
  loadThemeSettings();
}

/* ---------------------------
   Load When Page Opens
---------------------------- */
window.addEventListener("load", () => {
  loadThemeSettings();
  loadServerURL();
});

/* ---------------------------
   SERVER URL Handling
---------------------------- */
function loadServerURL() {
  const saved = localStorage.getItem("server_url") || "";
  document.getElementById("serverUrl").value = saved;
}

function saveServerURL() {
  const url = document.getElementById("serverUrl").value.trim();
  localStorage.setItem("server_url", url);
}

/* ---------------------------
   THEME DROPDOWN EVENTS
---------------------------- */
document.getElementById("themeSelect").addEventListener("change", e => {
  saveTheme("theme", e.target.value);
});

document.getElementById("accentSelect").addEventListener("change", e => {
  saveTheme("accent", e.target.value);
});

/* ---------------------------
   SETTINGS PAGE Redirect
---------------------------- */
document.getElementById("openSettingsBtn").addEventListener("click", () => {
  window.location.href = "settings.html";
});

/* ---------------------------
   CALCULATE BUTTON
---------------------------- */
document.getElementById("calcBtn").addEventListener("click", async () => {
  const server = localStorage.getItem("server_url") || "";
  if (!server) {
    alert("❗ पहले Server URL सेट करो (SmartAPI backend)");
    return;
  }

  const payload = {
    ema20: Number(ema20.value),
    ema50: Number(ema50.value),
    rsi: Number(rsi.value),
    vwap: Number(vwap.value),
    spot: Number(spot.value),
    market: market.value,
    expiryDays: Number(expiryDays.value),
    useLive: useLive.checked
  };

  try {
    const res = await fetch(server + "/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    renderOutput(data);

  } catch (e) {
    alert("Server error ❌\n" + e.message);
  }
});

/* ---------------------------
   RENDER OUTPUT
---------------------------- */
function renderOutput(d) {
  if (!d.success) {
    alert("❌ " + d.message);
    return;
  }

  // SUMMARY
  document.getElementById("summaryRow").classList.remove("hidden");
  sumTrend.innerText = d.trend.main;
  sumBias.innerText = d.trend.bias;
  sumStrength.innerText = d.trend.strength;
  sumScore.innerText = d.trend.score;
  sumLiveUsed.innerText = d.meta.live_data_used ? "LIVE" : "Manual";
  sumSpot.innerText = d.meta.live_ltp ?? d.input.spot;

  // STRIKES
  strikeCards.classList.remove("hidden");
  ceStrike.innerText = d.strikes.call.strike;
  ceDist.innerText = d.strikes.call.distance;
  ceEntry.innerText = d.strikes.call.entry;
  ceSL.innerText = d.strikes.call.sl;
  ceTarget.innerText = d.strikes.call.target;

  peStrike.innerText = d.strikes.put.strike;
  peDist.innerText = d.strikes.put.distance;
  peEntry.innerText = d.strikes.put.entry;
  peSL.innerText = d.strikes.put.sl;
  peTarget.innerText = d.strikes.put.target;

  strStrike.innerText = d.strikes.straddle.strike;
  strDist.innerText = d.strikes.straddle.distance;
  strEntry.innerText = d.strikes.straddle.entry;
  strSL.innerText = d.strikes.straddle.sl;
  strTarget.innerText = d.strikes.straddle.target;

  // META + JSON
  metaCard.classList.remove("hidden");
  metaLoginState.innerText = "Login: " + d.login_status;
  metaLiveFlag.innerText = d.meta.live_data_used ? "Live: Yes" : "Live: No";
  metaTokenInfo.innerText = "Tokens OK";

  metaText.innerText = d.message;

  jsonBox.textContent = JSON.stringify(d, null, 2);
}

/* ---------------------------
   JSON HIDE / SHOW
---------------------------- */
document.getElementById("toggleJsonBtn").addEventListener("click", () => {
  if (jsonBox.classList.contains("hidden")) {
    jsonBox.classList.remove("hidden");
    toggleJsonBtn.textContent = "Hide JSON";
  } else {
    jsonBox.classList.add("hidden");
    toggleJsonBtn.textContent = "Show JSON";
  }
});
