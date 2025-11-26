// ----------------------------------------
// Short helper
// ----------------------------------------
const qs = (id) => document.getElementById(id);

// ----------------------------------------
// SETTINGS PAGE OPEN
// ----------------------------------------
qs("openSettings").onclick = () => {
  window.location.href = "settings.html";
};

// ----------------------------------------
// SMARTAPI LOGIN (Auto when use_live = true)
// ----------------------------------------
async function smartLogin() {
  const pwd = localStorage.getItem("SMART_PASSWORD") || "";

  if (!pwd) {
    alert("पहले Settings में जाकर Password Save करो।");
    return false;
  }

  try {
    const r = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pwd }),
    });

    const data = await r.json();
    if (!data.success) {
      alert("Login Failed: " + data.error);
      return false;
    }

    return true;
  } catch (e) {
    alert("Network Error: " + e.message);
    return false;
  }
}

// ----------------------------------------
// MAIN CALCULATE
// ----------------------------------------
async function calc() {
  const server = qs("server").value.trim();
  const url = server ? server + "/api/calc" : "/api/calc";

  const payload = {
    ema20: Number(qs("ema20").value) || 0,
    ema50: Number(qs("ema50").value) || 0,
    rsi: Number(qs("rsi").value) || 0,
    vwap: Number(qs("vwap").value) || 0,
    spot: Number(qs("spot").value) || 0,
    market: qs("market").value,
    expiry_days: Number(qs("expiry").value) || 7,
    use_live: qs("useLive").checked,
  };

  qs("out").textContent = "Calculating...";

  // If live mode → ensure login first
  if (payload.use_live) {
    const ok = await smartLogin();
    if (!ok) {
      payload.use_live = false;
    }
  }

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await r.json();
    qs("out").textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    qs("out").textContent = "Network Error: " + e.message;
  }
}

qs("calc").onclick = calc;
