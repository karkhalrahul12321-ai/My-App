// -------------------------------
// QUICK SELECTOR
// -------------------------------
const $ = (id) => document.getElementById(id);

// DOM Elements
const calcBtn = $("calcBtn");
const jsonOut = $("jsonOut");
const toggleJsonBtn = $("toggleJsonBtn");
const resultBox = $("resultBox");

// -------------------------------
// THEME SYSTEM (5 THEMES)
// -------------------------------
const themeDots = document.querySelectorAll(".th-dot");

themeDots.forEach(dot => {
  dot.onclick = () => {
    const t = dot.getAttribute("data-theme");
    document.body.setAttribute("data-theme", t);
    localStorage.setItem("th_theme", t);
  };
});

// Load last theme
(function(){
  const saved = localStorage.getItem("th_theme") || "t1";
  document.body.setAttribute("data-theme", saved);
})();

// -------------------------------
// ACCENT COLOR
// -------------------------------
const accentPicker = $("accentPicker");

accentPicker.onchange = () => {
  document.documentElement.style.setProperty("--accent", accentPicker.value);
  localStorage.setItem("th_accent", accentPicker.value);
};

// Load saved accent
(function(){
  const saved = localStorage.getItem("th_accent");
  if (saved) {
    document.documentElement.style.setProperty("--accent", saved);
    accentPicker.value = saved;
  }
})();

// -------------------------------
// SETTINGS PAGE (OPEN / CLOSE)
// -------------------------------
$("openSettings").onclick = () => {
  window.location.href = "settings.html";
};

// -------------------------------
// JSON HIDE / SHOW
// -------------------------------
toggleJsonBtn.onclick = () => {
  if (jsonOut.style.display === "none") {
    jsonOut.style.display = "block";
    toggleJsonBtn.innerText = "Hide JSON";
  } else {
    jsonOut.style.display = "none";
    toggleJsonBtn.innerText = "Show JSON";
  }
};

// -------------------------------
// LOGIN STATUS CHECK
// -------------------------------
async function checkLoginStatus() {
  try {
    let sUrl = $("serverUrl").value.trim();
    if (!sUrl) sUrl = "";

    const url = sUrl ? sUrl + "/api/login/status" : "/api/login/status";

    const r = await fetch(url);
    const j = await r.json();

    if (j.logged_in) {
      $("loginStatus").innerHTML = "🟢 Logged-In";
    } else {
      $("loginStatus").innerHTML = "🟠 Demo Mode";
    }
  } catch (e) {
    $("loginStatus").innerHTML = "🔴 Offline";
  }
}

setTimeout(checkLoginStatus, 600);

// -------------------------------
// CALCULATE FUNCTION
// -------------------------------
calcBtn.onclick = async function () {
  let server = $("serverUrl").value.trim();
  if (!server) server = "";

  const url = server ? server + "/api/calc" : "/api/calc";

  const payload = {
    ema20: Number($("ema20").value) || 0,
    ema50: Number($("ema50").value) || 0,
    rsi: Number($("rsi").value) || 0,
    vwap: Number($("vwap").value) || 0,
    spot: Number($("spot").value) || 0,
    market: $("market").value,
    expiry_days: Number($("expiryDays").value) || 7,
    use_live: $("useLive").checked
  };

  calcBtn.innerText = "Calculating...";
  calcBtn.disabled = true;

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });

    const json = await r.json();

    // show box
    resultBox.style.display = "block";

    // Fill values
    $("rMain").innerText = json.trend.main;
    $("rStrength").innerText = json.trend.strength;
    $("rBias").innerText = json.trend.bias;
    $("rScore").innerText = json.trend.score;

    $("ceStrike").innerText =
      `${json.strikes[0].strike} | Entry ${json.strikes[0].entry} | SL ${json.strikes[0].stopLoss} | Target ${json.strikes[0].target}`;

    $("peStrike").innerText =
      `${json.strikes[1].strike} | Entry ${json.strikes[1].entry} | SL ${json.strikes[1].stopLoss} | Target ${json.strikes[1].target}`;

    $("strStrike").innerText =
      `${json.strikes[2].strike} | Entry ${json.strikes[2].entry} | SL ${json.strikes[2].stopLoss} | Target ${json.strikes[2].target}`;

    // Show JSON
    jsonOut.textContent = JSON.stringify(json, null, 2);

  } catch (err) {
    alert("Network error: " + err.message);
  }

  calcBtn.innerText = "CALCULATE";
  calcBtn.disabled = false;
};
