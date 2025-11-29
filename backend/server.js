Blame
/* ============================================================
   FINAL BACKEND – LIVE FUT LTP FIXED
   SmartAPI Login + Auto Token + Live LTP + Trend + Strikes
   Markets: Nifty, Sensex, Natural Gas
============================================================ */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

/* ============================================================
   APP INIT
============================================================ */
const app = express();
app.use(express.json());

// FRONTEND PATH (same as before)
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ============================================================
   ENV CONFIG
============================================================ */
const SMART_API_KEY = process.env.SMART_API_KEY;
const SMART_API_SECRET = process.env.SMART_API_SECRET;
const SMART_USER_ID = process.env.SMART_USER_ID;
const SMART_TOTP = process.env.SMART_TOTP;

const BASE_URL = "https://apiconnect.angelbroking.com";

/* ============================================================
   SESSION (TOKENS IN MEMORY)
============================================================ */
let SESSION = {
  jwt: null,
  refresh: null,
  feed: null,
  expires: 0
};

/* ============================================================
   HELPERS – BASE32 → TOTP
============================================================ */
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const output = [];

  input = input.replace(/=+$/, "").toUpperCase();
  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTOTP(secret) {
  const decoded = base32Decode(secret);
  const time = Math.floor(Date.now() / 30000); // 30s window
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(0, 0);
  buffer.writeUInt32BE(time, 4);
  const hmac = crypto.createHmac("sha1", decoded).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;

  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, "0");
}

/* ============================================================
   SMARTAPI LOGIN
============================================================ */
async function smartLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_API_SECRET || !SMART_USER_ID || !SMART_TOTP) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP);

    const resp = await fetch(
      `${BASE_URL}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY,
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: totp
        })
      }
    );

    const data = await resp.json().catch(() => null);
    console.log("SMARTAPI LOGIN RAW:", JSON.stringify(data));

    if (!data || data.status === false) {
    expiry_days = num(expiry_days, 7);

    let liveUsed = false;
    let liveLTP = null;
    let liveErr = null;

    if (use_live) {
      const r = await getFutureLTP(market);
      if (r.ok) {
        spot = r.ltp;
        liveUsed = true;
        liveLTP = spot;
      } else {
        liveErr = r;
      }
    }

    const trend = computeTrend({
      ema20,
      ema50,
      rsi,
      vwap,
      spot,
      expiry_days,
      market
    });

    const strikes = buildStrikes(
      { ema20, ema50, rsi, vwap, spot, expiry_days, market },
      trend
    );

    res.json({
      success: true,
      login_status: SESSION.jwt ? "SmartAPI Logged-In" : "Not logged-in",
      input: {
        ema20,
        ema50,
        rsi,
        vwap,
        spot,
        market,
        expiry_days,
        use_live
      },
      trend,
      strikes,
      auto_tokens: AUTO,
      meta: {
        live_data_used: liveUsed,
        live_ltp: liveLTP,
        live_error: liveErr
      }
    });
  } catch (e) {
    console.log("CALC ERROR:", e);
    res.json({ success: false, error: e.message });
  }
});

/* ============================================================
   SPA FALLBACK
============================================================ */
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ============================================================
   START SERVER
============================================================ */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER RUNNING on PORT", PORT);
});
/* ============================================================
   TEMP TEST — DIRECT TOKEN LTP CHECK
   This checks if LTP fetch works for fixed tokens
============================================================ */

app.get("/api/test-ltp", async (req, res) => {
  if (!SESSION.jwt) {
    return res.json({ ok: false, reason: "NOT_LOGGED_IN" });
  }

  // Manually extracted tokens from official ScripMaster
  const tests = [
    {
      name: "NIFTY FUTURE",
      exch: "NFO",
      token: "113063",
      symbol: "NIFTY26DECFUT"
    },
    {
      name: "SENSEX FUTURE",
      exch: "BFO",
      token: "50000000000007",
      symbol: "SENSEX19DECFUT"
    },
    {
      name: "NATURAL GAS FUT",
      exch: "MCX",
      token: "243887",
      symbol: "NATURALGAS26DECFUT"
    }
  ];

  const results = [];

  for (const t of tests) {
    try {
      const r = await fetch(
        "https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${SESSION.jwt}`,
            "X-PrivateKey": SMART_API_KEY,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            mode: "LTP",
            exchange: t.exch,
            tradingsymbol: t.symbol,
            symboltoken: t.token
          })
        }
      );

      const out = await r.json().catch(() => null);

      results.push({
        name: t.name,
        request: {
          exchange: t.exch,
          tradingsymbol: t.symbol,
          token: t.token
        },
        response: out
      });
    } catch (err) {
      results.push({
        name: t.name,
        error: err.message
      });
    }
  }

  res.json({
    ok: true,
    message: "LTP test complete",
    results
  });
});
