// app.js  (FINAL – main page + settings page)

/* ==========================
   LOCAL STORAGE KEYS
   ========================== */
const LS_KEYS = {
  theme: "th_theme_v1",
  accent: "th_accent_v1",
  serverUrl: "th_server_url_v1",
  pin: "th_trading_pin_v1",
  savePin: "th_save_pin_flag_v1"
};

/* ==========================
   COMMON HELPERS
   ========================== */
function safeEl(id) {
  return document.getElementById(id);
}

function showEl(el) {
  if (!el) return;
  el.classList.remove("hidden");
  el.style.display = "";
}

function hideEl(el) {
  if (!el) return;
  el.classList.add("hidden");
  el.style.display = "none";
}

function getBaseUrl() {
  const input = safeEl("serverUrl");
  let url = (input && input.value.trim()) || localStorage.getItem(LS_KEYS.serverUrl) || "";
  if (!url) {
    // डिफ़ॉल्ट – वही origin जिस पर ऐप चल रहा है
    url = window.location.origin;
  }
  return url.replace(/\/+$/, "");
}

function applyThemeFromStorage() {
  const body = document.body;
  const theme = localStorage.getItem(LS_KEYS.theme) || "soft";
  const accent = localStorage.getItem(LS_KEYS.accent) || "blue";

  body.setAttribute("data-theme", theme);
  body.setAttribute("data-accent", accent);

  const themeSel = safeEl("themeSelect") || safeEl("settingsThemeSelect");
  const accentSel = safeEl("accentSelect") || safeEl("settingsAccentSelect");

  if (themeSel) themeSel.value = theme;
  if (accentSel) accentSel.value = accent;
}

/* ==========================
   MAIN PAGE INIT
   ========================== */
function initMainPage() {
  applyThemeFromStorage();

  const themeSelect = safeEl("themeSelect");
  const accentSelect = safeEl("accentSelect");
  const openSettingsBtn = safeEl("openSettingsBtn");
  const serverUrlInput = safeEl("serverUrl");
  const calcBtn = safeEl("calcBtn");
  const useLiveCheckbox = safeEl("useLive");

  const resultHint = safeEl("resultHint");
  const summaryRow = safeEl("summaryRow");
  const strikeCards = safeEl("strikeCards");
  const metaCard = safeEl("metaCard");
  const toggleJsonBtn = safeEl("toggleJsonBtn");
  const jsonBox = safeEl("jsonBox");
  const metaText = safeEl("metaText");
  const metaLoginState = safeEl("metaLoginState");
  const metaLiveFlag = safeEl("metaLiveFlag");
  const metaTokenInfo = safeEl("metaTokenInfo");

  const sumTrend = safeEl("sumTrend");
  const sumBias = safeEl("sumBias");
  const sumStrength = safeEl("sumStrength");
  const sumScore = safeEl("sumScore");
  const sumLiveUsed = safeEl("sumLiveUsed");
  const sumSpot = safeEl("sumSpot");

  const ceStrike = safeEl("ceStrike");
  const ceDist = safeEl("ceDist");
  const ceEntry = safeEl("ceEntry");
  const ceSL = safeEl("ceSL");
  const ceTarget = safeEl("ceTarget");

  const peStrike = safeEl("peStrike");
  const peDist = safeEl("peDist");
  const peEntry = safeEl("peEntry");
  const peSL = safeEl("peSL");
  const peTarget = safeEl("peTarget");

  const strStrike = safeEl("strStrike");
  const strDist = safeEl("strDist");
  const strEntry = safeEl("strEntry");
  const strSL = safeEl("strSL");
  const strTarget = safeEl("strTarget");

  // थीम / एक्सेंट change
  if (themeSelect) {
    themeSelect.addEventListener("change", () => {
      const val = themeSelect.value || "soft";
      document.body.setAttribute("data-theme", val);
      localStorage.setItem(LS_KEYS.theme, val);
    });
  }

  if (accentSelect) {
    accentSelect.addEventListener("change", () => {
      const val = accentSelect.value || "blue";
      document.body.setAttribute("data-accent", val);
      localStorage.setItem(LS_KEYS.accent, val);
    });
  }

  // Settings बटन
  if (openSettingsBtn) {
    openSettingsBtn.addEventListener("click", () => {
      window.location.href = "settings.html";
    });
  }

  // Server URL को localStorage में रखो
  if (serverUrlInput) {
    const savedServer = localStorage.getItem(LS_KEYS.serverUrl);
    if (savedServer) {
      serverUrlInput.value = savedServer;
    }

    serverUrlInput.addEventListener("change", () => {
      localStorage.setItem(LS_KEYS.serverUrl, serverUrlInput.value.trim());
    });
  }

  // JSON toggle
  if (toggleJsonBtn && jsonBox) {
    toggleJsonBtn.addEventListener("click", () => {
      const isHidden = jsonBox.style.display === "none" || jsonBox.classList.contains("hidden");
      if (isHidden) {
        showEl(jsonBox);
        toggleJsonBtn.textContent = "Hide JSON";
      } else {
        hideEl(jsonBox);
        toggleJsonBtn.textContent = "Show JSON";
      }
    });
    // शुरू में JSON hidden रखेंगे
    hideEl(jsonBox);
    if (toggleJsonBtn) toggleJsonBtn.textContent = "Show JSON";
  }

  // Calculate बटन
  if (calcBtn) {
    calcBtn.addEventListener("click", async () => {
      const ema20 = parseFloat(safeEl("ema20")?.value || "0") || 0;
      const ema50 = parseFloat(safeEl("ema50")?.value || "0") || 0;
      const rsi = parseFloat(safeEl("rsi")?.value || "0") || 0;
      const vwap = parseFloat(safeEl("vwap")?.value || "0") || 0;
      const spot = parseFloat(safeEl("spot")?.value || "0") || 0;
      const market = safeEl("market")?.value || "nifty";
      const expiryDays = parseInt(safeEl("expiryDays")?.value || "7", 10) || 7;
      const useLive = !!(useLiveCheckbox && useLiveCheckbox.checked);

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

      if (resultHint) {
        resultHint.textContent = "Calculating...";
      }
      hideEl(summaryRow);
      hideEl(strikeCards);
      hideEl(metaCard);

      const url = getBaseUrl() + "/analyze";

      try {
        const res = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        if (!res.ok) {
          throw new Error("HTTP " + res.status);
        }

        const data = await res.json();

        // Trend summary
        const trend = data.trend || data.trend_result || {};
        const mainTrend =
          trend.main_trend || trend.main || trend.trend || data.main_trend || "–";
        const strength =
          trend.strength || trend.category || data.strength || "–";
        const bias =
          trend.bias || trend.view || data.bias || "–";
        const score =
          trend.score ?? trend.trend_score ?? data.score ?? "–";

        const usingLive = data.meta?.live_data_used ?? data.live_data_used;
        const usedSpot =
          (data.meta && data.meta.live_ltp) ||
          data.used_spot ||
          spot ||
          "–";

        if (sumTrend) sumTrend.textContent = String(mainTrend);
        if (sumStrength) sumStrength.textContent = String(strength);
        if (sumBias) sumBias.textContent = String(bias);
        if (sumScore) sumScore.textContent = score === "–" ? "–" : String(score);
        if (sumLiveUsed)
          sumLiveUsed.textContent = usingLive ? "Live (SmartAPI)" : "Manual";
        if (sumSpot) sumSpot.textContent = String(usedSpot);

        showEl(summaryRow);

        // Strike cards
        const strikes = data.strikes || data.smart_strikes || {};
        const ce = strikes.ce || strikes.call || {};
        const pe = strikes.pe || strikes.put || {};
        const straddle = strikes.straddle || strikes.str || {};

        if (ceStrike) ceStrike.textContent = ce.strike ?? "–";
        if (ceDist) ceDist.textContent = ce.distance ?? ce.dist ?? "–";
        if (ceEntry) ceEntry.textContent = ce.entry ?? "–";
        if (ceSL) ceSL.textContent = ce.sl ?? ce.stoploss ?? "–";
        if (ceTarget) ceTarget.textContent = ce.target ?? "–";

        if (peStrike) peStrike.textContent = pe.strike ?? "–";
        if (peDist) peDist.textContent = pe.distance ?? pe.dist ?? "–";
        if (peEntry) peEntry.textContent = pe.entry ?? "–";
        if (peSL) peSL.textContent = pe.sl ?? pe.stoploss ?? "–";
        if (peTarget) peTarget.textContent = pe.target ?? "–";

        if (strStrike) strStrike.textContent = straddle.strike ?? "–";
        if (strDist) strDist.textContent = straddle.distance ?? straddle.dist ?? "–";
        if (strEntry) strEntry.textContent = straddle.entry ?? "–";
        if (strSL) strSL.textContent = straddle.sl ?? straddle.stoploss ?? "–";
        if (strTarget) strTarget.textContent = straddle.target ?? "–";

        showEl(strikeCards);

        // Meta / JSON
        const loginStatus = data.login_status || data.meta?.login_status || "";
        const liveInfo = usingLive ? "Live FUT LTP used" : "Manual inputs";
        const tokenInfo =
          data.meta?.live_error?.reason ||
          data.meta?.token_status ||
          "Tokens –";

        if (metaText) {
          metaText.textContent =
            data.message ||
            data.meta?.note ||
            "SmartAPI / Live data meta info.";
        }
        if (metaLoginState) {
          metaLoginState.textContent = "Login: " + (loginStatus || "Unknown");
        }
        if (metaLiveFlag) {
          metaLiveFlag.textContent = "Live: " + (usingLive ? "Yes" : "No");
        }
        if (metaTokenInfo) {
          metaTokenInfo.textContent = tokenInfo;
        }
        if (jsonBox) {
          jsonBox.textContent = JSON.stringify(data, null, 2);
          // JSON default hidden, यूज़र चाहे तो Show JSON दबाए
          hideEl(jsonBox);
          if (toggleJsonBtn) toggleJsonBtn.textContent = "Show JSON";
        }
        showEl(metaCard);

        if (resultHint) {
          resultHint.textContent = "Result updated.";
        }
      } catch (err) {
        console.error("Analyze error:", err);
        if (resultHint) {
          resultHint.textContent = "Error: server से डेटा नहीं मिला।";
        }
        if (metaText) {
          metaText.textContent =
            "Request failed: " + (err.message || "Unknown error");
        }
        if (jsonBox) {
          jsonBox.textContent = "";
          hideEl(jsonBox);
        }
        showEl(metaCard);
      }
    });
  }
}

/* ==========================
   SETTINGS PAGE INIT
   ========================== */
function initSettingsPage() {
  applyThemeFromStorage();

  const themeSelect = safeEl("settingsThemeSelect");
  const accentSelect = safeEl("settingsAccentSelect");
  const pinInput = safeEl("pinInput");
  const savePinCheckbox = safeEl("savePinCheckbox");
  const saveBtn = safeEl("saveSettingsBtn");
  const backBtn = safeEl("backToAppBtn");

  // थीम / एक्सेंट
  if (themeSelect) {
    const storedTheme = localStorage.getItem(LS_KEYS.theme) || "soft";
    themeSelect.value = storedTheme;
    themeSelect.addEventListener("change", () => {
      const val = themeSelect.value || "soft";
      document.body.setAttribute("data-theme", val);
      localStorage.setItem(LS_KEYS.theme, val);
    });
  }

  if (accentSelect) {
    const storedAccent = localStorage.getItem(LS_KEYS.accent) || "blue";
    accentSelect.value = storedAccent;
    accentSelect.addEventListener("change", () => {
      const val = accentSelect.value || "blue";
      document.body.setAttribute("data-accent", val);
      localStorage.setItem(LS_KEYS.accent, val);
    });
  }

  // PIN + checkbox
  if (savePinCheckbox && pinInput) {
    const savedFlag = localStorage.getItem(LS_KEYS.savePin) === "1";
    const savedPin = localStorage.getItem(LS_KEYS.pin) || "";
    savePinCheckbox.checked = savedFlag;
    if (savedFlag && savedPin) {
      pinInput.value = savedPin;
    }
  }

  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      const pin = pinInput ? pinInput.value.trim() : "";
      const savePin = !!(savePinCheckbox && savePinCheckbox.checked);

      if (savePin) {
        localStorage.setItem(LS_KEYS.savePin, "1");
        localStorage.setItem(LS_KEYS.pin, pin);
      } else {
        localStorage.removeItem(LS_KEYS.savePin);
        localStorage.removeItem(LS_KEYS.pin);
      }

      // बैकएंड को PIN भेजकर SmartAPI login करा दो (अगर PIN भरा है)
      if (pin) {
        const baseUrl = getBaseUrl();
        const url = baseUrl + "/smartapi/login";
        try {
          await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pin })
          });
        } catch (e) {
          console.warn("Login request failed (ignored):", e);
        }
      }

      alert("Settings saved ✅");
    });
  }

  if (backBtn) {
    backBtn.addEventListener("click", () => {
      window.location.href = "index.html";
    });
  }
}

/* ==========================
   BOOTSTRAP
   ========================== */
document.addEventListener("DOMContentLoaded", () => {
  // settings.html में settingsThemeSelect होता है
  if (safeEl("settingsThemeSelect")) {
    initSettingsPage();
  } else {
    initMainPage();
  }
});
