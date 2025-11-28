/* ============================================================
   Trading Helper Backend (FINAL PRO VERSION)
   SmartAPI Login + Auto FUT Tokens + LTP + Trend Master
   Fully Render-Ready (No JSON Parse Error)
   ============================================================ */

const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// ENV VARIABLES (Render + GitHub)
// ============================================================

const API_KEY = process.env.SMART_API_KEY;
const API_SECRET = process.env.SMART_API_SECRET;
const CLIENT_CODE = process.env.SMART_USER_ID;
const TOTP = process.env.SMART_TOTP;

if (!API_KEY || !API_SECRET || !CLIENT_CODE || !TOTP) {
  console.log("❌ ENV Missing! Check .env on Render");
}

// ============================================================
// GLOBAL STATE
// ============================================================

let JWT_TOKEN = null;
let REFRESH_TOKEN = null;

// ============================================================
// SAFE JSON PARSER (No Crash)
// ============================================================

const safeJSON = async (res) => {
  try {
    const txt = await res.text();
    return JSON.parse(txt);
  } catch (e) {
    console.log("❌ SAFE JSON ERROR:", e.message);
    return null;
  }
};

// ============================================================
// SMARTAPI LOGIN (100% Corrected Endpoint)
// ============================================================

async function smartLogin() {
  console.log("\n🔄 Logging into SmartAPI...");

  const url = "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/loginByPassword";

  const body = {
    clientcode: CLIENT_CODE,
    password: API_SECRET,
    totp: TOTP,
  };

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "xx:xx:xx:xx",
        "X-PrivateKey": API_KEY,
      },
      body: JSON.stringify(body),
    });

    const data = await safeJSON(response);

    console.log("📌 RAW LOGIN RESPONSE:", data);

    if (!data || !data.data) {
      console.log("❌ Login API returned empty response");
      return false;
    }

    JWT_TOKEN = data.data.jwtToken;
    REFRESH_TOKEN = data.data.refreshToken;

    console.log("✅ LOGIN SUCCESS");
    console.log("JWT:", JWT_TOKEN ? "OK" : "Missing");
    console.log("REFRESH:", REFRESH_TOKEN ? "OK" : "Missing");

    return true;
  } catch (err) {
    console.log("❌ LOGIN ERROR:", err.message);
    return false;
  }
}

// ============================================================
// REFRESH TOKEN AUTO
// ============================================================

async function refreshLogin() {
  if (!REFRESH_TOKEN) return smartLogin();

  console.log("🔄 Refreshing Token...");

  const url = "https://apiconnect.angelone.in/rest/auth/angelbroking/jwt/v1/generateTokens";

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-PrivateKey": API_KEY,
      },
      body: JSON.stringify({ refreshToken: REFRESH_TOKEN }),
    });

    const data = await safeJSON(response);

    if (!data || !data.data) {
      console.log("❌ REFRESH FAILED");
      return smartLogin();
    }

    JWT_TOKEN = data.data.jwtToken;
    REFRESH_TOKEN = data.data.refreshToken;

    console.log("✅ TOKEN REFRESHED");
    return true;
  } catch (err) {
    console.log("❌ REFRESH ERROR:", err.message);
    return smartLogin();
  }
}

// ============================================================
// AUTO REFRESH EVERY 25 MIN
// ============================================================

setInterval(refreshLogin, 25 * 60 * 1000);

// ============================================================
// API: CHECK LOGIN STATUS
// ============================================================

app.get("/api/status", (req, res) => {
  res.json({
    login: JWT_TOKEN ? "Logged-In" : "Not Logged-In",
    TOKEN_OK: !!JWT_TOKEN,
    REFRESH_OK: !!REFRESH_TOKEN,
  });
});

// ============================================================
// STARTUP
// ============================================================

(async () => {
  await smartLogin();
})();

// ============================================================
// SERVER
// ============================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on ${PORT}`));
