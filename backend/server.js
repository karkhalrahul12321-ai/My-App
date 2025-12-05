require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const axios = require("axios");
const totp = require("totp-generator");

const app = express();
app.use(express.json());
app.use(cors());

// =========================
//  SMART API LOGIN SECTION
// =========================

let SMART_SESSION = null;

async function smartLogin() {
  try {
    const { SMART_API_KEY, SMART_API_SECRET, SMART_TOTP, SMART_USER_ID } =
      process.env;

    if (!SMART_API_KEY || !SMART_API_SECRET || !SMART_TOTP || !SMART_USER_ID) {
      console.log("❌ Missing SmartAPI ENV variables");
      return null;
    }

    const generatedTOTP = totp(SMART_TOTP);

    const loginUrl =
      "https://apiconnect.angelbroking.com/rest/auth/angelbroking/user/v1/loginByPassword";

    const payload = {
      clientcode: SMART_USER_ID,
      password: SMART_API_SECRET,
      totp: generatedTOTP,
    };

    const headers = {
      "X-ClientLocalIP": "127.0.0.1",
      "X-ClientPublicIP": "127.0.0.1",
      "X-MACAddress": "AA-BB-CC-11-22-33",
      "X-PrivateKey": SMART_API_KEY,
      "Content-Type": "application/json",
    };

    const res = await axios.post(loginUrl, payload, { headers });

    if (res.data && res.data.data && res.data.data.jwtToken) {
      SMART_SESSION = res.data.data;
      console.log("✅ SmartAPI Logged-In");
      return SMART_SESSION;
    } else {
      console.log("❌ SmartAPI login failed");
      return null;
    }
  } catch (err) {
    console.log("❌ SmartAPI Login ERROR:", err.message);
    return null;
  }
}

// Login API (called from app settings page)
app.post("/api/login", async (req, res) => {
  const session = await smartLogin();
  if (!session)
    return res.status(500).json({ success: false, message: "Login failed" });

  res.json({ success: true, message: "Logged-In", session });
});

// =========================
//  LIVE LTP FETCH
// =========================

app.post("/api/live-ltp", async (req, res) => {
  try {
    if (!SMART_SESSION) {
      return res.json({ success: false, message: "Not logged-in" });
    }

    const { symbol } = req.body;

    const url =
      "https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/ltp";

    const headers = {
      "X-PrivateKey": process.env.SMART_API_KEY,
      Authorization: `Bearer ${SMART_SESSION.jwtToken}`,
      "Content-Type": "application/json",
    };

    const payload = {
      exchange: "NSE",
      tradingsymbol: symbol,
      symboltoken: "00000",
    };

    const response = await axios.post(url, payload, { headers });

    res.json({
      success: true,
      ltp: response.data.data.ltp,
    });
  } catch (e) {
    res.json({ success: false, message: "LTP fetch error", error: e.message });
  }
});

// =========================
//  SMART STRIKE ENGINE
// =========================

const suggest = require("./engines/apiSuggest");

app.post("/api/suggest-strikes", async (req, res) => {
  try {
    const output = await suggest.handler(req.body);
    res.json(output);
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// =========================
//  FRONTEND SERVE SETTINGS
// =========================

const frontendPath = path.join(__dirname, "../frontend");

// Serve static files
app.use(express.static(frontendPath));

// Any unknown route → serve index.html
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =========================
//  START SERVER
// =========================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Full App LIVE on PORT:", PORT);
});
