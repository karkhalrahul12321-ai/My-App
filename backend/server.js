/* ============================================================
   FINAL BACKEND – VERSION A (TEST LTP + MANUAL CALC)
   SmartAPI Login + Manual Trend & Strikes + LTP Test Endpoint
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
const SMART_API_SECRET = process.env.SMART_API_SECRET; // अभी use नहीं हो रहा, future के लिए रखा है
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
  if (!SMART_API_KEY || !SMART_USER_ID || !SMART_TOTP) {
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
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    SESSION.jwt = d.jwtToken || null;
    SESSION.refresh = d.refreshToken || null;
    SESSION.feed = d.feedToken || null;
    SESSION.expires = Date.now() + 20 * 60 * 60 * 1000; // ~20 hours

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

/* ============================================================
   LOGIN ROUTES
============================================================ */
app.post("/api/login", async (req, res) => {
  const pass = (req.body && req.body.password) || "";
  const r = await smartLogin(pass);

  if (!r.ok) {
    return res.json({
      success: false,
      error: r.reason,
      raw: r.raw || null
    });
  }

  res.json({
    success: true,
    message: "Login success",
    expires: SESSION.expires
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!SESSION.jwt,
    expires: SESSION.expires || null
  });
});

/* ============================================================
   GENERIC HELPERS
============================================================ */
function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}
function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}
function roundToStep(v, step) {
  if (!step) return v;
  return Math.round(v / step) * step;
}

/* ============================================================
   MARKET CONFIG (for strikes)
============================================================ */
const MRKT = {
  nifty: {
    step: 50,
    base: { far: 250, mid: 200, near: 150 }
  },
  sensex: {
    step: 100,
    base: { far: 500, mid: 400, near: 300 }
  },
  "natural gas": {
    step: 5,
    base: { far: 80, mid: 60, near: 50 }
  }
};

/* ============================================================
   AUTO DETECT MARKET (backup)
============================================================ */
function detectMarket(spot, raw) {
  const m = (raw || "").toString().trim().toLowerCase();
  if (MRKT[m]) return m;

  const s = num(spot);
  if (s > 20 && s < 2000) return "natural gas";
  if (s >= 10000 && s < 40000) return "nifty";
  if (s >= 40000) return "sensex";

  return "nifty";
}

/* ============================================================
   TREND ENGINE
============================================================ */
function computeTrend(input) {
  const ema20 = num(input.ema20);
  const ema50 = num(input.ema50);
  const rsi = num(input.rsi);
  const vwap = num(input.vwap);
  const spot = num(input.spot);
  const expiry = num(input.expiry_days, 7);

  const comp = {};
  let score = 50;
  let main = "SIDEWAYS";
  let strength = "NEUTRAL";
  let bias = "NONE";

  if (!ema20 || !ema50 || !rsi || !vwap || !spot) {
    comp.warning = "Inputs missing (approx trend)";
    return {
      main,
      strength,
      score,
      bias,
      components: comp,
      comment: "Incomplete data — flat trend"
    };
  }

  const emaMid = (ema20 + ema50) / 2;
  const emaPct = ((ema20 - ema50) / emaMid) * 100;
  const emaScore = clamp(emaPct * 1.5, -25, 25);
  comp.ema = emaPct.toFixed(2) + "%";

  const rsiScore = clamp((rsi - 50) * 1.2, -25, 25);
  comp.rsi = rsi;

  const vwapPct = ((spot - vwap) / vwap) * 100;
  const vwapScore = clamp(vwapPct * 1.5, -20, 20);
  comp.vwap = vwapPct.toFixed(2) + "%";

  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) structScore = 10;
  else if (spot < ema20 && ema20 < ema50) structScore = -10;
  comp.structure = structScore;

  let expScore = 0;
  if (expiry <= 2) expScore = -5;
  else if (expiry >= 10) expScore = 3;
  comp.expiry = expScore;

  score =
    50 +
    emaScore * 0.4 +
    rsiScore * 0.3 +
    vwapScore * 0.2 +
    structScore * 0.2 +
    expScore;

  score = clamp(score, 0, 100);

  if (score >= 80) {
    main = "UPTREND";
    strength = "STRONG";
    bias = "CE";
  } else if (score >= 60) {
    main = "UPTREND";
    strength = "MODERATE";
    bias = "CE";
  } else if (score <= 20) {
    main = "DOWNTREND";
    strength = "STRONG";
    bias = "PE";
  } else if (score <= 40) {
    main = "DOWNTREND";
    strength = "MODERATE";
    bias = "PE";
  }

  return { main, strength, score, bias, components: comp };
}

/* ============================================================
   STRIKE ENGINE
============================================================ */
function scaleExpiry(expDays, base, step) {
  const d = Math.max(0, num(expDays, 7));
  let f = 0.2 + d * 0.05;
  if (f > 1) f = 1;

  return {
    near: Math.max(step / 2, base.near * f),
    mid: Math.max(step / 2, base.mid * f),
    far: Math.max(step / 2, base.far * f)
  };
}

function buildStrikes(input, trend) {
  const cfg = MRKT[input.market] || MRKT["nifty"];
  const scaled = scaleExpiry(input.expiry_days, cfg.base, cfg.step);

  const atm = roundToStep(input.spot, cfg.step);
  let ceDist, peDist;

  if (trend.main === "UPTREND") {
    ceDist = scaled.near;
    peDist = scaled.far;
  } else if (trend.main === "DOWNTREND") {
    ceDist = scaled.far;
    peDist = scaled.near;
  } else {
    ceDist = scaled.mid;
    peDist = scaled.mid;
  }

  const ce = atm + ceDist;
  const pe = atm - peDist;
  const str = atm;

  function make(strike, type, diff) {
    const steps = Math.max(1, Math.round(Math.abs(diff) / cfg.step));
    const base = Math.max(5, steps * 5);
    return {
      type,
      strike,
      distance: Math.abs(diff),
      entry: base,
      stopLoss: Math.round(base * 0.6),
      target: Math.round(base * 1.5)
    };
  }

  return [
    make(ce, "CE", ce - input.spot),
    make(pe, "PE", pe - input.spot),
    make(str, "STRADDLE", str - input.spot)
  ];
}

/* ============================================================
   MAIN CALC API  (ONLY MANUAL / NO LIVE LTP IN VERSION A)
============================================================ */
app.post("/api/calc", async (req, res) => {
  try {
    let {
      ema20,
      ema50,
      rsi,
      vwap,
      spot,
      market,
      expiry_days,
      use_live
    } = req.body || {};

    ema20 = num(ema20);
    ema50 = num(ema50);
    rsi = num(rsi);
    vwap = num(vwap);
    spot = num(spot);
    expiry_days = num(expiry_days, 7);
    market = detectMarket(spot, market);

    // VERSION A: live LTP disable – सिर्फ़ debug info के लिए reason भेज रहे हैं
    let liveUsed = false;
    let liveLTP = null;
    let liveErr = null;

    if (use_live) {
      liveErr = {
        ok: false,
        reason: "LIVE_DISABLED_IN_TEST_BACKEND"
      };
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
      login_status: SESSION.jwt ? "SmartAPI Logged-In" : "Not logged-in (demo mode)",
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
      auto_tokens: {
        nifty: { symbol: null, token: null, expiry: null },
        sensex: { symbol: null, token: null, expiry: null },
        "natural gas": { symbol: null, token: null, expiry: null }
      },
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
   TEMP TEST — DIRECT TOKEN LTP CHECK
   This checks if LTP fetch works for fixed tokens
============================================================ */
app.get("/api/test-ltp", async (req, res) => {
  if (!SESSION.jwt) {
    return res.json({ ok: false, reason: "NOT_LOGGED_IN" });
  }

  // Tokens from ScripMaster (as you shared)
  const tests = [
    {
      name: "NIFTY FUTURE",
      exch: "NFO",
      token: "113063",
      symbol: "NIFTY26DECFUT"
    },
    {
      name: "SENSEX FUTURE",
      exch: "BFO", // F&O segment for Sensex
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
        `${BASE_URL}/rest/secure/angelbroking/market/v1/quote`,
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
