// =====================================
// Trading Helper Frontend (FINAL)
// - Calculate button
// - SmartAPI Settings button
// - Live login + pretty output
// =====================================

const $ = (id) => document.getElementById(id);

// ---------- SERVER BASE ----------
function getServerBase() {
  const raw = $("server") ? $("server").value.trim() : "";
  if (!raw) return "";
  return raw.endsWith("/") ? raw.slice(0, -1) : raw;
}

function loadSavedServer() {
  try {
    const s = localStorage.getItem("TH_SERVER_URL");
    if (s && $("server")) $("server").value = s;
  } catch (_) {}
}

function saveServer() {
  try {
    const s = $("server").value.trim();
    if (s) localStorage.setItem("TH_SERVER_URL", s);
  } catch (_) {}
}

// ---------- SMARTAPI LOGIN ----------
async function ensureSmartLogin() {
  const pwd = localStorage.getItem("SMART_PASSWORD") || "";

  if (!pwd) {
    alert("पहले SmartAPI Settings में जाकर trading password save करो.");
    return false;
  }

  const base = getServerBase();
  const url = base ? base + "/api/login" : "/api/login";

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pwd })
    });

    const data = await resp.json();
    if (!data.success) {
      alert(
        "SmartAPI login failed: " +
          (data.error || "Unknown error (password / TOTP / env चेक करो)")
      );
      return false;
    }
    return true;
  } catch (err) {
    alert("SmartAPI login network error: " + err.message);
    return false;
  }
}

// ---------- NICE OUTPUT RENDER ----------
function resetVisual() {
  const ids = [
    "trendMain",
    "trendStrength",
    "trendScore",
    "trendBias",
    "trendNotes",
    "ceStrike",
    "ceEntry",
    "ceSL",
    "ceTarget",
    "peStrike",
    "peEntry",
    "peSL",
    "peTarget",
    "strStrike",
    "strEntry",
    "strSL",
    "strTarget",
    "metaLive",
    "metaLtp",
    "metaStatus"
  ];
  ids.forEach((id) => {
    if ($(id)) $(id).textContent = "–";
  });
}

function renderNiceOutput(resp) {
  const visual = $("visualOutput");
  if (!visual) return;

  resetVisual();

  if (!resp) {
    visual.style.display = "none";
    return;
  }

  visual.style.display = "block";

  if (resp.success === false) {
    $("trendMain").textContent = "ERROR";
    $("trendStrength").textContent = "";
    $("trendNotes").textContent = resp.error || "Unknown error";
    $("metaStatus").textContent = "ERROR";
    return;
  }

  const t = resp.trend || {};
  $("trendMain").textContent = t.main || "SIDEWAYS";
  $("trendStrength").textContent = t.strength || "RANGE";
  $("trendScore").textContent =
    typeof t.score === "number" ? t.score.toFixed(1) : "–";
  $("trendBias").textContent = t.bias || "NONE";

  const comp = t.components || {};
  const notes = [];
  if (comp.ema_gap) notes.push(comp.ema_gap);
  if (comp.rsi) notes.push(comp.rsi);
  if (comp.vwap) notes.push(comp.vwap);
  if (comp.price_structure) notes.push(comp.price_structure);
  if (comp.expiry) notes.push(comp.expiry);
  if (t.comment && notes.length === 0) notes.push(t.comment);
  $("trendNotes").textContent = notes.join(" • ");

  const strikes = resp.strikes || [];

  function fillStrike(idx, prefix) {
    const s = strikes[idx] || {};
    if ($(prefix + "Strike"))
      $(prefix + "Strike").textContent =
        s.strike !== undefined && s.strike !== null ? s.strike : "–";
    if ($(prefix + "Entry"))
      $(prefix + "Entry").textContent =
        s.entry !== undefined && s.entry !== null ? s.entry : "–";
    if ($(prefix + "SL"))
      $(prefix + "SL").textContent =
        s.stopLoss !== undefined && s.stopLoss !== null ? s.stopLoss : "–";
    if ($(prefix + "Target"))
      $(prefix + "Target").textContent =
        s.target !== undefined && s.target !== null ? s.target : "–";
  }

  fillStrike(0, "ce");
  fillStrike(1, "pe");
  fillStrike(2, "str");

  const meta = resp.meta || {};
  $("metaLive").textContent = meta.live_data_used ? "Yes" : "No";
  $("metaLtp").textContent =
    meta.live_ltp !== undefined && meta.live_ltp !== null
      ? meta.live_ltp
      : "–";
  $("metaStatus").textContent =
    resp.login_status ||
    (meta.live_error && meta.live_error.reason) ||
    "OK";
}

// ---------- CALCULATE ----------
async function doCalc() {
  const base = getServerBase();
  saveServer();

  const url = base ? base + "/api/calc" : "/api/calc";

  const payload = {
    ema20: Number($("ema20").value) || 0,
    ema50: Number($("ema50").value) || 0,
    rsi: Number($("rsi").value) || 0,
    vwap: Number($("vwap").value) || 0,
    spot: Number($("spot").value) || 0,
    market: $("market").value,
    expiry_days: Number($("expiry").value) || 7,
    use_live: $("useLive").checked
  };

  if ($("out")) {
    $("out").style.display = "block";
    $("out").textContent = "Calculating...";
  }
  renderNiceOutput(null);

  try {
    if (payload.use_live) {
      const ok = await ensureSmartLogin();
      if (!ok) {
        payload.use_live = false;
      }
    }

    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await resp.json();
    if ($("out")) {
      $("out").textContent = JSON.stringify(data, null, 2);
    }
    renderNiceOutput(data);
  } catch (err) {
    if ($("out")) {
      $("out").textContent = "Network error: " + err.message;
    }
    renderNiceOutput({
      success: false,
      error: "Network error: " + err.message
    });
  }
}

// ---------- INIT ----------
window.addEventListener("DOMContentLoaded", () => {
  loadSavedServer();

  const calcBtn = $("calc");
  if (calcBtn) calcBtn.onclick = doCalc;

  const settingsBtn = $("openSettings");
  if (settingsBtn) {
    settingsBtn.onclick = () => {
      // अलग settings.html पेज पर ले जाओ
      window.location.href = "settings.html";
    };
  }
});
