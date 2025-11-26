// =====================================
// Trading Helper Frontend
// Theme + Server URL + SmartAPI calc
// =====================================

(function () {
  // ---------- DOM refs ----------
  const body = document.body;

  const themeSelect = document.getElementById("themeSelect");
  const accentSelect = document.getElementById("accentSelect");
  const openSettingsBtn = document.getElementById("openSettingsBtn");

  const serverInput = document.getElementById("serverUrl");
  const loginStatusPill = document.getElementById("loginStatusPill");
  const loginDot = document.getElementById("loginDot");
  const loginStatusText = document.getElementById("loginStatusText");

  const ema20Input = document.getElementById("ema20");
  const ema50Input = document.getElementById("ema50");
  const rsiInput = document.getElementById("rsi");
  const vwapInput = document.getElementById("vwap");
  const spotInput = document.getElementById("spot");
  const marketSelect = document.getElementById("market");
  const expiryInput = document.getElementById("expiryDays");
  const useLiveCheckbox = document.getElementById("useLive");

  const marketChip = document.getElementById("marketChip");
  const calcBtn = document.getElementById("calcBtn");

  const resultHint = document.getElementById("resultHint");
  const summaryRow = document.getElementById("summaryRow");
  const sumTrend = document.getElementById("sumTrend");
  const sumBias = document.getElementById("sumBias");
  const sumStrength = document.getElementById("sumStrength");
  const sumScore = document.getElementById("sumScore");
  const sumLiveUsed = document.getElementById("sumLiveUsed");
  const sumSpot = document.getElementById("sumSpot");

  const strikeCardsWrap = document.getElementById("strikeCards");
  const ceStrike = document.getElementById("ceStrike");
  const ceDist = document.getElementById("ceDist");
  const ceEntry = document.getElementById("ceEntry");
  const ceSL = document.getElementById("ceSL");
  const ceTarget = document.getElementById("ceTarget");

  const peStrike = document.getElementById("peStrike");
  const peDist = document.getElementById("peDist");
  const peEntry = document.getElementById("peEntry");
  const peSL = document.getElementById("peSL");
  const peTarget = document.getElementById("peTarget");

  const strStrike = document.getElementById("strStrike");
  const strDist = document.getElementById("strDist");
  const strEntry = document.getElementById("strEntry");
  const strSL = document.getElementById("strSL");
  const strTarget = document.getElementById("strTarget");

  const metaCard = document.getElementById("metaCard");
  const metaText = document.getElementById("metaText");
  const metaLoginState = document.getElementById("metaLoginState");
  const metaLiveFlag = document.getElementById("metaLiveFlag");
  const metaTokenInfo = document.getElementById("metaTokenInfo");

  const toggleJsonBtn = document.getElementById("toggleJsonBtn");
  const jsonBox = document.getElementById("jsonBox");

  // ---------- Helpers ----------

  function normalizeBaseUrl(raw) {
    const v = (raw || "").trim();
    if (!v) return "";
    if (!/^https?:\/\//i.test(v)) {
      return "https://" + v;
    }
    return v;
  }

  function loadBaseUrl() {
    const stored = normalizeBaseUrl(localStorage.getItem("TH_SERVER_URL") || "");
    if (stored) return stored;
    // default – same render backend
    return window.location.origin;
  }

  function getBaseUrlAndSyncInput() {
    // 1) try from input
    const fromInput = normalizeBaseUrl(serverInput.value);
    if (fromInput) {
      localStorage.setItem("TH_SERVER_URL", fromInput);
      return fromInput;
    }

    // 2) try from storage
    const stored = normalizeBaseUrl(localStorage.getItem("TH_SERVER_URL") || "");
    if (stored) {
      serverInput.value = stored;
      return stored;
    }

    // 3) fallback same origin
    const origin = window.location.origin;
    serverInput.value = origin;
    localStorage.setItem("TH_SERVER_URL", origin);
    return origin;
  }

  function setLoginStatus(state, text) {
    loginStatusPill.classList.remove(
      "status-ok",
      "status-warn",
      "status-error",
      "status-idle"
    );
    loginDot.classList.remove("ok", "warn", "error", "idle");

    if (state === "ok") {
      loginStatusPill.classList.add("status-ok");
      loginDot.classList.add("ok");
    } else if (state === "warn") {
      loginStatusPill.classList.add("status-warn");
      loginDot.classList.add("warn");
    } else if (state === "error") {
      loginStatusPill.classList.add("status-error");
      loginDot.classList.add("error");
    } else {
      loginStatusPill.classList.add("status-idle");
      loginDot.classList.add("idle");
    }
    loginStatusText.textContent = text;
  }

  function applyTheme(theme, accent) {
    const t = theme || "soft";
    const a = accent || "blue";

    // remove old classes
    [
      "theme-light",
      "theme-soft",
      "theme-blue",
      "theme-warm",
      "theme-dark",
    ].forEach((c) => body.classList.remove(c));
    [
      "accent-blue",
      "accent-green",
      "accent-teal",
      "accent-orange",
      "accent-purple",
    ].forEach((c) => body.classList.remove(c));

    body.classList.add("theme-" + t);
    body.classList.add("accent-" + a);

    localStorage.setItem("TH_THEME", t);
    localStorage.setItem("TH_ACCENT", a);
  }

  function initThemeControls() {
    const savedTheme = localStorage.getItem("TH_THEME") || "soft";
    const savedAccent = localStorage.getItem("TH_ACCENT") || "blue";

    if (themeSelect) themeSelect.value = savedTheme;
    if (accentSelect) accentSelect.value = savedAccent;

    applyTheme(savedTheme, savedAccent);

    if (themeSelect) {
      themeSelect.addEventListener("change", () => {
        applyTheme(themeSelect.value, accentSelect.value);
      });
    }
    if (accentSelect) {
      accentSelect.addEventListener("change", () => {
        applyTheme(themeSelect.value, accentSelect.value);
      });
    }
  }

  function updateMarketChip() {
    const m = (marketSelect.value || "nifty").toLowerCase();
    let txt = "NIFTY · FUT";
    if (m === "sensex") txt = "SENSEX · FUT";
    else if (m === "natural gas") txt = "NATURAL GAS · FUT";
    marketChip.textContent = txt;
  }

  function openSettingsPage() {
    const baseUrl = getBaseUrlAndSyncInput();
    // front-end settings page है, same host पर
    window.location.href = baseUrl.replace(/\/+$/, "") + "/settings.html";
  }

  // ---------- Backend calls ----------

  async function checkLoginStatus() {
    try {
      setLoginStatus("idle", "Checking…");
      const baseUrl = getBaseUrlAndSyncInput();
      const resp = await fetch(baseUrl.replace(/\/+$/, "") + "/api/login/status");
      const data = await resp.json().catch(() => null);
      if (!data || data.success === false) {
        setLoginStatus("warn", "Demo mode");
      } else {
        if (data.logged_in) {
          setLoginStatus("ok", "SmartAPI Logged-In");
        } else {
          setLoginStatus("warn", "Not logged-in (demo)");
        }
      }
    } catch (e) {
      setLoginStatus("error", "Backend offline");
    }
  }

  function clearOutput() {
    summaryRow.classList.add("hidden");
    strikeCardsWrap.classList.add("hidden");
    metaCard.classList.add("hidden");
    jsonBox.textContent = "";
    resultHint.textContent = "पहले Calculate दबाएँ";
  }

  function renderOutput(payload) {
    if (!payload || payload.success === false) {
      clearOutput();
      alert("❌ Calculation error: " + (payload && payload.error ? payload.error : ""));
      return;
    }

    const { trend, strikes, meta, input, login_status, auto_tokens } = payload;

    // Summary
    summaryRow.classList.remove("hidden");
    strikeCardsWrap.classList.remove("hidden");
    metaCard.classList.remove("hidden");

    resultHint.textContent = payload.message || "Calculation complete";

    sumTrend.textContent = trend?.main || "-";
    sumBias.textContent = "Bias: " + (trend?.bias || "-");
    sumStrength.textContent = trend?.strength || "-";
    sumScore.textContent = "Score " + (trend?.score != null ? trend.score.toFixed(1) : "-");

    const usedLive = meta && meta.live_data_used;
    sumLiveUsed.textContent = usedLive ? "Live FUT LTP" : "Manual / Spot";
    sumSpot.textContent =
      (input && input.spot != null ? input.spot : "-") +
      (usedLive ? " (live)" : "");

    // Strikes
    function fillStrikeCard(obj, prefix) {
      if (!obj) {
        document.getElementById(prefix + "Strike").textContent = "-";
        document.getElementById(prefix + "Dist").textContent = "-";
        document.getElementById(prefix + "Entry").textContent = "-";
        document.getElementById(prefix + "SL").textContent = "-";
        document.getElementById(prefix + "Target").textContent = "-";
        return;
      }
      document.getElementById(prefix + "Strike").textContent = obj.strike ?? "-";
      document.getElementById(prefix + "Dist").textContent =
        (obj.distance != null ? obj.distance : "-");
      document.getElementById(prefix + "Entry").textContent =
        (obj.entry != null ? obj.entry : "-");
      document.getElementById(prefix + "SL").textContent =
        (obj.stopLoss != null ? obj.stopLoss : "-");
      document.getElementById(prefix + "Target").textContent =
        (obj.target != null ? obj.target : "-");
    }

    fillStrikeCard(strikes && strikes[0], "ce");
    fillStrikeCard(strikes && strikes[1], "pe");
    fillStrikeCard(strikes && strikes[2], "str");

    // Meta text
    metaText.textContent = meta && meta.live_error && meta.live_error.ok === false
      ? "Live FUT LTP में दिक्कत: " + (meta.live_error.reason || "Unknown")
      : usedLive
      ? "Live FUT LTP used successfully."
      : "Manual mode / demo data.";

    metaLoginState.textContent = "Login: " + (login_status || "Unknown");
    metaLiveFlag.textContent =
      "Live: " + (usedLive ? "Yes" : "No");

    const autoInfo =
      auto_tokens && auto_tokens[input.market]
        ? auto_tokens[input.market].symbol || "Token ok"
        : "Tokens not resolved";
    metaTokenInfo.textContent = "Tokens: " + autoInfo;

    // JSON (full)
    jsonBox.textContent = JSON.stringify(payload, null, 2);
    jsonBox.classList.remove("hidden");
    toggleJsonBtn.textContent = "Hide JSON";
  }

  async function handleCalc() {
    // हमेशा base URL resolve + save करेगा, alert नहीं देगा
    const baseUrl = getBaseUrlAndSyncInput();

    const payload = {
      ema20: Number(ema20Input.value || 0),
      ema50: Number(ema50Input.value || 0),
      rsi: Number(rsiInput.value || 0),
      vwap: Number(vwapInput.value || 0),
      spot: Number(spotInput.value || 0),
      market: marketSelect.value,
      expiry_days: Number(expiryInput.value || 7),
      use_live: !!useLiveCheckbox.checked,
    };

    resultHint.textContent = "Calculating…";
    calcBtn.disabled = true;

    try {
      const resp = await fetch(
        baseUrl.replace(/\/+$/, "") + "/api/calc",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );

      const data = await resp.json().catch(() => null);
      if (!data) {
        clearOutput();
        alert("❌ Backend से invalid response मिला");
      } else {
        renderOutput(data);
      }
    } catch (e) {
      clearOutput();
      alert("❌ Request failed: " + e.message);
    } finally {
      calcBtn.disabled = false;
    }
  }

  function initJsonToggle() {
    toggleJsonBtn.addEventListener("click", () => {
      if (jsonBox.classList.contains("hidden")) {
        jsonBox.classList.remove("hidden");
        toggleJsonBtn.textContent = "Hide JSON";
      } else {
        jsonBox.classList.add("hidden");
        toggleJsonBtn.textContent = "Show JSON";
      }
    });
  }

  // ---------- INIT ----------

  function initServerBar() {
    const url = loadBaseUrl();
    serverInput.value = url;
  }

  function initMarketChipAndInputs() {
    updateMarketChip();
    marketSelect.addEventListener("change", updateMarketChip);
  }

  function init() {
    initThemeControls();
    initServerBar();
    initMarketChipAndInputs();
    clearOutput();
    checkLoginStatus();
    initJsonToggle();

    if (calcBtn) {
      calcBtn.addEventListener("click", handleCalc);
    }
    if (openSettingsBtn) {
      openSettingsBtn.addEventListener("click", openSettingsPage);
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
