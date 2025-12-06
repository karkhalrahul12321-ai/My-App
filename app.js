// ==========================================================
// GLOBALS
// ==========================================================

let SERVER_URL = "";
let isLoggedIn = false;

// Load saved server URL
document.addEventListener("DOMContentLoaded", () => {
  SERVER_URL = localStorage.getItem("serverUrl") || "";
  document.getElementById("serverUrl").value = SERVER_URL;

  updateServerStatus();
});

// Update server URL from input
function saveServerUrl() {
  SERVER_URL = document.getElementById("serverUrl").value.trim();
  localStorage.setItem("serverUrl", SERVER_URL);
  updateServerStatus();
}



// ==========================================================
// SERVER STATUS CHECK
// ==========================================================

async function updateServerStatus() {
  if (!SERVER_URL) return;

  try {
    const res = await fetch(`${SERVER_URL}/`);
    const data = await res.json();

    document.getElementById("serverStatus").innerHTML = "Server OK";
  } catch (err) {
    document.getElementById("serverStatus").innerHTML = "Server Error";
  }
}



// ==========================================================
// LOGIN
// ==========================================================

async function loginSmartAPI() {
  const password = prompt("Enter your SmartAPI password:");

  if (!password) {
    alert("Password required");
    return;
  }

  try {
    const res = await fetch(`${SERVER_URL}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    const data = await res.json();

    if (data.success) {
      isLoggedIn = true;
      document.getElementById("loginStatus").innerHTML = "SmartAPI Logged-In";
    } else {
      alert("Login Failed: " + (data.error || "Unknown"));
    }
  } catch (err) {
    alert("Login Error: " + err.message);
  }
}



// ==========================================================
// CALCULATE TREND & STRIKES  (ALPHA ENGINE)
// ==========================================================

async function calculateTrend() {
  const ema20 = parseFloat(document.getElementById("ema20").value);
  const ema50 = parseFloat(document.getElementById("ema50").value);
  const rsi = parseFloat(document.getElementById("rsi").value);
  const vwap = parseFloat(document.getElementById("vwap").value);
  const spot = parseFloat(document.getElementById("spot").value);

  const market = document.getElementById("market").value || "NIFTY";
  const expiry = parseInt(document.getElementById("expiry").value || "7");

  if (!ema20 || !ema50 || !rsi || !vwap || !spot) {
    alert("Please fill all inputs!");
    return;
  }

  try {
    const res = await fetch(`${SERVER_URL}/analysis/manual`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        market,
        expiry,
        ema20,
        ema50,
        rsi,
        vwap,
        spot,
      }),
    });

    const data = await res.json();

    if (!data.success) {
      alert("Error: " + (data.error || "Unknown"));
      return;
    }

    updateResultUI(data);
  } catch (err) {
    alert("Analysis Error: " + err.message);
  }
}



// ==========================================================
// UPDATE UI WITH ALPHA BACKEND OUTPUT
// ==========================================================

function updateResultUI(data) {
  // Trend
  document.getElementById("mainTrend").innerHTML = data.trend || "-";

  // Bias (auto-calc from trend)
  let bias = "NONE";
  if (data.trend === "UP") bias = "BULLISH";
  if (data.trend === "DOWN") bias = "BEARISH";
  document.getElementById("bias").innerHTML = bias;

  // Strength (backend does not provide → keep blank)
  document.getElementById("strengthScore").innerHTML = "-";

  // Reason
  document.getElementById("reasonText").innerHTML = data.reason || "-";

  // Values JSON box
  document.getElementById("jsonBox").textContent = JSON.stringify(data, null, 2);
}



// ==========================================================
// HELPER UI FUNCTIONS
// ==========================================================

function toggleJSON() {
  const box = document.getElementById("jsonBoxContainer");
  box.style.display = box.style.display === "none" ? "block" : "none";
}
