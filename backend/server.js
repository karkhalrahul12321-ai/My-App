// =====================================================
// Trading Helper Backend (FINAL STABLE VERSION)
// SmartAPI Login + Auto FUT Token + Live LTP + Trend Engine
// Markets: Nifty, Sensex, Natural Gas
// =====================================================

require("dotenv").config(); // Load .env

const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// =====================================================
// ENV VARIABLES
// =====================================================
const API_KEY = process.env.SMART_API_KEY;
const API_SECRET = process.env.SMART_API_SECRET;
const CLIENT_CODE = process.env.SMART_USER_ID;
const TOTP_SECRET = process.env.SMART_TOTP;

// Session storage
let SESSION = {
  authToken: null,
  refreshToken: null,
  feedToken: null,
  loginTime: null,
};

// =====================================================
// TOTP GENERATOR
// =====================================================
function generateTOTP(secret) {
  const time = Math.floor(Date.now() / 1000 / 30);
  const key = Buffer.from(secret, "ascii");
  const msg = Buffer.alloc(8);
  msg.writeUIntBE(time, 0, 8);

  const hmac = crypto.createHmac("sha1", key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, "0");
}

// =====================================================
// SMARTAPI LOGIN FUNCTION
// =====================================================
async function smartLogin() {
  console.log("📌 Starting SmartAPI Login...");

  const totp = generateTOTP(TOTP_SECRET);

  const body = {
    clientcode: CLIENT_CODE,
    password: API_SECRET,
    totp: totp,
  };

  const resp = await fetch(
    "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/loginByPassword",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ClientLocalIP": "192.168.0.1",
        "X-ClientPublicIP": "106.0.0.1",
        "X-PrivateKey": API_KEY,
        Accept: "application/json",
      },
      body: JSON.stringify(body),
    }
  );

  const raw = await resp.text();
  console.log("RAW LOGIN:", raw);

  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    console.log("❌ JSON Parse Error:", err.message);
    return false;
  }

  if (!data.status) {
    console.log("❌ Login failed:", data.message);
    return false;
  }

  SESSION.authToken = data.data.jwtToken;
  SESSION.refreshToken = data.data.refreshToken;
  SESSION.feedToken = data.data.feedToken;
  SESSION.loginTime = Date.now();

  console.log("✅ SmartAPI Logged In Successfully");
  return true;
}

// =====================================================
// FUTURE TOKENS STATIC MAP
// =====================================================
const FUT_MAP = {
  nifty: { symbol: "NIFTY26DECFUT", token: 113063 },
  sensex: { symbol: "SENSEX26DECFUT", token: 113268 },
  "natural gas": { symbol: "NATURALGAS26DECFUT", token: 26009 },
};

// =====================================================
// API: LOGIN
// =====================================================
app.get("/api/login", async (req, res) => {
  const ok = await smartLogin();

  if (!ok) return res.json({ success: false, message: "Login failed" });

  res.json({
    success: true,
    message: "SmartAPI Logged In",
    session: SESSION,
  });
});

// =====================================================
// API: GET LIVE LTP
// =====================================================
app.get("/api/ltp/:market", async (req, res) => {
  const market = req.params.market.toLowerCase();

  if (!SESSION.authToken) {
    return res.json({ success: false, error: "Not logged in" });
  }

  const tok = FUT_MAP[market];
  if (!tok) return res.json({ success: false, error: "Invalid market" });

  const body = {
    mode: "LTP",
    exchangeTokens: {
      NFO: [tok.token.toString()],
    },
  };

  const resp = await fetch(
    "https://apiconnect.angelone.in/rest/marketdata/v1/market/ltp",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: SESSION.authToken,
        "X-PrivateKey": API_KEY,
        Accept: "application/json",
      },
      body: JSON.stringify(body),
    }
  );

  const raw = await resp.text();
  console.log("LTP RAW:", raw);

  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    return res.json({ success: false, error: "Invalid LTP JSON" });
  }

  if (!data.status) {
    return res.json({ success: false, error: data.message });
  }

  res.json({
    success: true,
    ltp: data.data?.ltp,
  });
});

// =====================================================
// API: HEALTH CHECK
// =====================================================
app.get("/", (req, res) => {
  res.send("Backend running OK");
});

// =====================================================
// START SERVER
// =====================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 SERVER STARTED ON", PORT);
});
