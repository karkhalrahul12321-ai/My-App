/* ============================================================
   FINAL BACKEND – LIVE FUT LTP (PLAN A: NIFTY + SENSEX + NATGAS)
   SmartAPI Login + Auto Token + Live LTP + Trend + Strikes
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

// FRONTEND PATH
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
  const time = Math.floor(Date.now() / 30000); // 30 sec window
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
   UTILS
============================================================ */
function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}
function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}
function roundToStep(v, step) {
  return Math.round(v / step) * step;
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
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    const d = data.data || {};
    SESSION.jwt = d.jwtToken;
    SESSION.refresh = d.refreshToken;
    SESSION.feed = d.feedToken;
    SESSION.expires = Date.now() + 20 * 60 * 60 * 1000; // ~20h

    return { ok: true };
  } catch (e) {
    console.log("LOGIN ERROR:", e);
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

/* ============================================================
   LOGIN ROUTES
============================================================ */
app.post("/api/login", async (req, res) => {
  const pass = req.body?.password || "";
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
    logged_in: !!SESSION.jwt,
    expires: SESSION.expires || null
  });
});

/* ============================================================
   MARKET CONFIG (STRIKES ENGINE)
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

function detectMarket(spot, raw) {
  const m = (raw || "").trim().toLowerCase();
  if (MRKT[m]) return m;

  const s = num(spot);
  if (s > 20 && s < 2000) return "natural gas";
  if (s >= 10000 && s < 40000) return "nifty";
  if (s >= 40000) return "sensex";

  return "nifty";
}

/* ============================================================
   FUTURE SEARCH RULES (AUTO TOKEN)
============================================================ */
const FUT_RULES = {
  nifty: { search: "NIFTY", exch: "NFO", inst: "FUTIDX" },
  sensex: { search: "SENSEX", exch: "BFO", inst: "FUTIDX" },
  "natural gas": { search: "NATURALGAS", exch: "MCX", inst: "FUTCOM" }
};

const AUTO = {
  nifty: { symbol: null, token: null, expiry: null, exch: "NFO", inst: "FUTIDX" },
  sensex: { symbol: null, token: null, expiry: null, exch: "BFO", inst: "FUTIDX" },
  "natural gas": {
    symbol: null,
    token: null,
    expiry: null,
    exch: "MCX",
    inst: "FUTCOM"
  }
};

function parseExpiry(str) {
  if (!str) return null;
  // Angel अक्सर "27JAN2026" या "2025-12-30" जैसा देता है
  if (/^\d{2}[A-Z]{3}\d{4}$/.test(str)) {
    const d = parseInt(str.slice(0, 2), 10);
    const mStr = str.slice(2, 5).toUpperCase();
    const y = parseInt(str.slice(5), 10);
    const months = {
      JAN: 0,
      FEB: 1,
      MAR: 2,
      APR: 3,
      MAY: 4,
      JUN: 5,
      JUL: 6,
      AUG: 7,
      SEP: 8,
      OCT: 9,
      NOV: 10,
      DEC: 11
    };
    const m = months[mStr];
    if (m === undefined) return null;
    return new Date(y, m, d);
  }

  const t = Date.parse(str);
  if (!Number.isNaN(t)) return new Date(t);

  return null;
}

async function smartSearch(keyword) {
  if (!SESSION.jwt) return [];

  try {
    const r = await fetch(
      `${BASE_URL}/rest/secure/angelbroking/order/v1/searchScrip`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${SESSION.jwt}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ searchtext: keyword })
      }
    );

    const d = await r.json().catch(() => null);
    return d?.data || [];
  } catch (e) {
    console.log("SEARCH ERROR:", e);
    return [];
  }
}

async function autoFetch(market) {
  const rule = FUT_RULES[market];
  if (!rule || !SESSION.jwt) return null;

  const all = await smartSearch(rule.search);
  if (!all.length) return null;

  const today = new Date();
  let best = null;
  let bestDt = null;

  for (const s of all) {
    const sameExch = s.exch_seg === rule.exch;
    const sameInst = s.instrumenttype === rule.inst;
    if (!sameExch || !sameInst) continue;

    const dt = parseExpiry(s.expirydate);
    if (!dt || dt < today) continue;

    if (!bestDt || dt < bestDt) {
      bestDt = dt;
      best = s;
    }
  }

  if (!best) return null;

  AUTO[market] = {
    symbol: best.tradingsymbol,
    token: best.symboltoken,
    expiry: best.expirydate,
    exch: rule.exch,
    inst: rule.inst
  };

  console.log("AUTO TOKEN UPDATED:", market, AUTO[market]);
  return AUTO[market];
}

/* ============================================================
   LIVE LTP FETCH – NEW ENDPOINT (quote/instruments)
============================================================ */
async function getFutureLTP(market) {
  const cfg = AUTO[market];
  if (!cfg) return { ok: false, reason: "BAD_MARKET" };
  if (!SESSION.jwt) return { ok: false, reason: "NOT_LOGGED_IN" };

  let info = cfg;

  if (!info.token) {
    const a = await autoFetch(market);
    if (!a || !a.token) {
      return { ok: false, reason: "TOKEN_NOT_FOUND" };
    }
    info = a;
  }

  try {
    const body = {
      mode: "LTP",
      exchangeTokens: {
        [info.exch]: [String(info.token)]
      }
    };

    const r = await fetch(
      `${BASE_URL}/rest/secure/angelbroking/market/v1/quote/instruments`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${SESSION.jwt}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      }
    );

    const data = await r.json().catch(() => null);
    console.log("LTP RAW:", JSON.stringify(data));

    if (!data || data.status === false || !data.data) {
      return { ok: false, reason: "LTP_FAILED", raw: data };
    }

    // response structure flexible तरीके से पकड़ने की कोशिश
    let ltp = null;

    if (Array.isArray(data.data) && data.data.length) {
      ltp = num(data.data[0].ltp || data.data[0].Ltp || data.data[0].lastPrice);
    } else if (data.data[info.exch]) {
      const arr = data.data[info.exch];
      if (Array.isArray(arr) && arr.length) {
        const it = arr[0];
        ltp = num(it.ltp || it.Ltp || it.lastPrice);
      }
    }

    if (!ltp) {
      return { ok: false, reason: "NO_LTP_IN_RESPONSE", raw: data };
    }

    return { ok: true, ltp };
  } catch (e) {
    console.log("LTP ERROR:", e);
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
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

  let rsiScore = clamp((rsi - 50) * 1.2, -25, 25);
  comp.rsi = rsi;

  const vwapPct = ((spot - vwap) / vwap) * 100;
  const vwapScore = clamp(vwapPct * 1.5, -20, 20);
  comp.vwap = vwapPct.toFixed(2) + "%";

  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) structScore = 10;
  else if (spot < ema20 && ema20 < ema50) structScore = -10;
  comp.structure = structScore;

  const expiry = num(input.expiry_days);
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
  let f = 0.2 + expDays * 0.05;
  if (f > 1) f = 1;

  return {
    near: Math.max(step / 2, base.near * f),
    mid: Math.max(step / 2, base.mid * f),
    far: Math.max(step / 2, base.far * f)
  };
}

function buildStrikes(input, trend) {
  const cfg = MRKT[input.market];
  const scaled = scaleExpiry(num(input.expiry_days, 7), cfg.base, cfg.step);

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

  function mk(strike, type, diff) {
    const steps = Math.max(1, Math.round(Math.abs(diff) / cfg.step));
    const base = steps * 5;
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
    mk(ce, "CE", ce - input.spot),
    mk(pe, "PE", pe - input.spot),
    mk(str, "STRADDLE", str - input.spot)
  ];
}

/* ============================================================
   MAIN CALC API
============================================================ */
app.post("/api/calc", async (req, res) => {
  try {
    let { ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live } =
      req.body || {};

    spot = num(spot);
    expiry_days = num(expiry_days, 7);
    market = detectMarket(spot, market);

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
   TEST ROUTE – SEE RAW LTP RESPONSE
============================================================ */
app.get("/api/test-ltp", async (req, res) => {
  const results = {};

  for (const mkt of ["nifty", "sensex", "natural gas"]) {
    results[mkt] = await getFutureLTP(mkt);
  }

  res.json({
    ok: true,
    message: "LTP test complete",
    results
  });
});

/* ============================================================
   SPA FALLBACK (KEEP LAST)
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
