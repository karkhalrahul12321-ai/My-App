const qs = id => document.getElementById(id);

/* ----------------------
   SETTINGS PAGE HANDLING
----------------------- */

const mainApp = qs("mainApp");
const settingsPage = qs("settingsPage");

qs("openSettings").onclick = () => {
  mainApp.style.display = "none";
  settingsPage.style.display = "block";

  qs("password").value = localStorage.getItem("smartPwd") || "";
  qs("savePwd").checked = !!localStorage.getItem("smartPwd");

  fetch("/api/settings")
    .then(r => r.json())
    .then(s => {
      qs("apiKey").value = s.apiKey;
      qs("userId").value = s.userId;
      qs("totp").value = s.totp;
    });
};

qs("closeSettings").onclick = () => {
  mainApp.style.display = "block";
  settingsPage.style.display = "none";
};

qs("saveSettings").onclick = () => {
  const pwd = qs("password").value;
  if (qs("savePwd").checked) {
    localStorage.setItem("smartPwd", pwd);
  } else {
    localStorage.removeItem("smartPwd");
  }
  alert("Settings saved!");
};

/* ----------------------
   MAIN CALCULATE FUNCTION
----------------------- */

function getServer() {
  const s = qs("server").value.trim();
  return s !== "" ? s : "";
}

async function calc() {
  const server = getServer();
  const url = server ? server + "/api/calc" : "/api/calc";

  const payload = {
    ema20: Number(qs("ema20").value),
    ema50: Number(qs("ema50").value),
    rsi: Number(qs("rsi").value),
    vwap: Number(qs("vwap").value),
    spot: Number(qs("spot").value),
    market: qs("market").value,
    expiry_days: Number(qs("expiry").value),
    use_live: qs("useLive").checked
  };

  qs("out").textContent = "Calculating...";

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    qs("out").textContent = JSON.stringify(await r.json(), null, 2);

  } catch (e) {
    qs("out").textContent = "Network error: " + e.message;
  }
}

qs("calc").onclick = calc;
