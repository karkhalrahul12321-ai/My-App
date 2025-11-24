// -------------
// SMALL HELPERS
// -------------
const qs = (id) => document.getElementById(id);

// ----------------------
// SETTINGS PAGE HANDLING
// ----------------------
const mainApp      = qs("mainApp");
const settingsPage = qs("settingsPage");

qs("openSettings").onclick = () => {
  // main छुपाओ, settings दिखाओ
  mainApp.style.display = "none";
  settingsPage.style.display = "block";

  // saved password load करो
  const savedPwd = localStorage.getItem("smartPwd") || "";
  qs("password").value = savedPwd;
  qs("savePwd").checked = !!savedPwd;

  // backend से env-based SmartAPI details दिखाओ
  fetch("/api/settings")
    .then((r) => r.json())
    .then((s) => {
      qs("apiKey").value = s.apiKey || "";
      qs("userId").value = s.userId || "";
      qs("totp").value   = s.totp   || "";
    })
    .catch(() => {
      // कुछ भी error आये तो fields खाली रहने दो
    });
};

qs("closeSettings").onclick = () => {
  // settings छुपाओ, main दिखाओ
  mainApp.style.display = "block";
  settingsPage.style.display = "none";
};

qs("saveSettings").onclick = () => {
  const pwd = qs("password").value || "";

  if (qs("savePwd").checked) {
    localStorage.setItem("smartPwd", pwd);
  } else {
    localStorage.removeItem("smartPwd");
  }

  alert("Settings saved!");
};

// ----------------------
// SMARTAPI LOGIN HELPER
// ----------------------
async function ensureSmartLogin() {
  // password हमेशा localStorage से उठेगा
  const pwd = localStorage.getItem("smartPwd") || "";

  if (!pwd) {
    alert("पहले Settings में जाकर password डालकर Save करो.");
    return false;
  }

  try {
    const resp = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pwd })
    });

    const data = await resp.json();

    if (!data.success) {
      alert(
        "SmartAPI login failed: " +
          (data.error || "Unknown error (password / TOTP / key चेक करो)")
      );
      return false;
    }

    // लॉगिन success
    console.log("SmartAPI login OK", data);
    return true;
  } catch (err) {
    alert("SmartAPI login network error: " + err.message);
    return false;
  }
}

// ----------------------
// MAIN CALCULATE FUNCTION
// ----------------------
function getServer() {
  const s = qs("server").value.trim();
  return s !== "" ? s : "";
}

async function calc() {
  const server = getServer();
  const url = server ? server + "/api/calc" : "/api/calc";

  const payload = {
    ema20:       Number(qs("ema20").value) || 0,
    ema50:       Number(qs("ema50").value) || 0,
    rsi:         Number(qs("rsi").value)   || 0,
    vwap:        Number(qs("vwap").value)  || 0,
    spot:        Number(qs("spot").value)  || 0,
    market:      qs("market").value,
    expiry_days: Number(qs("expiry").value) || 7,
    use_live:    qs("useLive").checked
  };

  qs("out").textContent = "Calculating...";

  try {
    // अगर user ने live data चुना है → पहले SmartAPI login try करो
    if (payload.use_live) {
      const ok = await ensureSmartLogin();
      if (!ok) {
        // login fail हुआ → demo mode में चला जाओ
        payload.use_live = false;
      }
    }

    // अब backend calc API call
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const json = await r.json();
    qs("out").textContent = JSON.stringify(json, null, 2);
  } catch (e) {
    qs("out").textContent = "Network error: " + e.message;
  }
}

qs("calc").onclick = calc;
