/* ============================================================
   FINAL BACKEND (NIFTY + SENSEX + NATGAS FUTURE AUTO-TOKEN)

   Features:
   - SmartAPI Login (TOTP) via ENV
   - Auto Nearest FUT Token from OpenAPIScripMaster.json
   - Live F&O Future LTP (Nifty, Sensex, Natural Gas)
   - Trend Engine + Strike Engine
   - Frontend served from ../frontend
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

const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ============================================================
   ENV CONFIG
============================================================ */
const SMART_API_KEY = process.env.SMART_API_KEY;
const SMART_API_SECRET = process.env.SMART_API_SECRET; // अभी उपयोग नहीं, future use के लिए
const SMART_USER_ID = process.env.SMART_USER_ID;
const SMART_TOTP = process.env.SMART_TOTP;

const BASE_URL = "https://apiconnect.angelbroking.com";
const SCRIP_MASTER_URL =
  "https://margincalculator.angelone.in/OpenAPI_File/files/OpenAPIScripMaster.json";

/* ============================================================
   SESSION
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
  const time = Math.floor(Date.now() / 30000);
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

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    const d = data.data || {};
    SESSION.jwt = d.jwtToken;
    SESSION.refresh = d.refreshToken;
    SESSION.feed = d.feedToken;
    SESSION.expires = Date.now() + 20 * 60 * 60 * 1000;

    console.log("SmartAPI login success, jwt stored.");
    return { ok: true };
  } catch (e) {
    console.log("SmartAPI login exception:", e.message);
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
   BASIC HELPERS
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
   MARKET CONFIG (NIFTY, SENSEX, NATGAS)
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

const FUT_META = {
  nifty: { exch: "NFO", instType: "FUTIDX" },
  sensex: { exch: "BFO", instType: "FUTIDX" }, // कुछ में BSE भी हो सकता, नीचे हैंडल किया है
  "natural gas": { exch: "MCX", instType: "FUTCOM" }
};

/* ============================================================
   AUTO TOKEN STORE
============================================================ */
const AUTO = {
  nifty: { symbol: null, token: null, expiry: null },
  sensex: { symbol: null, token: null, expiry: null },
  "natural gas": { symbol: null, token: null, expiry: null }
};

/* ============================================================
   SCRIP MASTER CACHE (FILTERED)
============================================================ */
const SCRIP_CACHE = {
  lastLoaded: 0,
  markets: {
    nifty: [],
    sensex: [],
    "natural gas": []
  }
};

// 26DEC2025  या  26-12-2025  या 2025-12-26
function parseAngelExpiry(str) {
  if (!str || typeof str !== "string") return null;
  str = str.trim();

  // 2025-12-26 or 2025/12/26
  if (/^\d{4}[-/]\d{2}[-/]\d{2}$/.test(str)) {
    return new Date(str.replace(/\//g, "-"));
  }

  // 26DEC2025
  const m = str.match(/^(\d{1,2})([A-Z]{3})(\d{4})$/i);
  if (m) {
    const day = parseInt(m[1], 10);
    const monStr = m[2].toUpperCase();
    const year = parseInt(m[3], 10);
    const months = [
      "JAN",
      "FEB",
      "MAR",
      "APR",
      "MAY",
      "JUN",
      "JUL",
      "AUG",
      "SEP",
      "OCT",
      "NOV",
      "DEC"
    ];
    const month = months.indexOf(monStr);
    if (month >= 0) {
      return new Date(year, month, day);
    }
  }

  // fallback
  const d = new Date(str);
  if (!isNaN(d.getTime())) return d;
  return null;
}

/* ============================================================
   LOAD & FILTER OpenAPIScripMaster.json
   (only NIFTY + SENSEX + NATGAS FUTURES)
============================================================ */
async function ensureScripMasterLoaded() {
  const now = Date.now();
  // हर 1 घंटे में रीलोड करेंगे
  if (now - SCRIP_CACHE.lastLoaded < 60 * 60 * 1000 && SCRIP_CACHE.lastLoaded) {
    return;
  }

  try {
    console.log("Loading ScripMaster (filtered)...");
    const resp = await fetch(SCRIP_MASTER_URL);
    const all = await resp.json();

    const niftyList = [];
    const sensexList = [];
    const natgasList = [];

    for (const s of all) {
      const symbol = s.symbol || s.tradingsymbol || "";
      const inst = s.instrumenttype || s.instrumentType || "";
      const exch = s.exch_seg || s.exchange || "";
      const token = s.symboltoken || s.token || s.tokenno || "";
      const expiryStr = s.expiry || s.expirydate || s.expiryDate || "";
      const expiry = parseAngelExpiry(expiryStr);
      if (!symbol || !inst || !exch || !token || !expiry) continue;

      // NIFTY FUTURE (NFO FUTIDX)
      if (
        symbol.toUpperCase().startsWith("NIFTY") &&
        inst.toUpperCase().includes("FUT") &&
        exch.toUpperCase() === "NFO"
      ) {
        niftyList.push({ symbol, token, expiry, exch, inst });
        continue;
      }

      // SENSEX FUTURE (BFO/BSE FUTIDX)
      if (
        symbol.toUpperCase().includes("SENSEX") &&
        inst.toUpperCase().includes("FUT") &&
        (exch.toUpperCase() === "BFO" || exch.toUpperCase() === "BSE")
      ) {
        sensexList.push({ symbol, token, expiry, exch, inst });
        continue;
      }

      // NATURAL GAS FUTURE (MCX FUTCOM)
      if (
        symbol.toUpperCase().startsWith("NATURALGAS") &&
        inst.toUpperCase().includes("FUT") &&
        exch.toUpperCase() === "MCX"
      ) {
        natgasList.push({ symbol, token, expiry, exch, inst });
        continue;
      }
    }

    SCRIP_CACHE.markets.nifty = niftyList;
    SCRIP_CACHE.markets.sensex = sensexList;
    SCRIP_CACHE.markets["natural gas"] = natgasList;
    SCRIP_CACHE.lastLoaded = now;

    console.log("ScripMaster loaded. Counts:", {
      nifty: niftyList.length,
      sensex: sensexList.length,
      natgas: natgasList.length
    });
  } catch (e) {
    console.log("Error loading ScripMaster:", e.message);
  }
}

/* ============================================================
   GET NEAREST FUTURE (per market) FROM CACHE
============================================================ */
function getNearestFutureFromCache(market) {
  const list = SCRIP_CACHE.markets[market] || [];
  if (!list.length) return null;

  const today = new Date();
  let best = null;
  let bestDiff = Infinity;

  for (const s of list) {
    const exp = s.expiry;
    if (!(exp instanceof Date) || isNaN(exp.getTime())) continue;

    const diff = exp.getTime() - today.getTime();
    // केवल आज या आने वाले expiry (पुराने ignore)
    if (diff < -24 * 60 * 60 * 1000) continue;

    if (diff >= 0 && diff < bestDiff) {
      bestDiff = diff;
      best = s;
    }
  }
  return best;
}

/* ============================================================
   ENSURE AUTO TOKEN (with expiry rollover)
============================================================ */
async function ensureAutoToken(market) {
  await ensureScripMasterLoaded();

  const cfg = FUT_META[market];
  if (!cfg) return null;

  const current = AUTO[market];
  const now = new Date();

  if (current && current.expiry) {
    const expDate = parseAngelExpiry(current.expiry.toString());
    if (expDate && expDate.getTime() - now.getTime() > 0) {
      // अभी वाला contract valid है
      return current;
    }
  }

  // नया nearest FUT उठाओ
  const fut = getNearestFutureFromCache(market);
  if (!fut) return null;

  AUTO[market] = {
    symbol: fut.symbol,
    token: fut.token,
    expiry: fut.expiry.toISOString().slice(0, 10),
    exch: fut.exch,
    inst: fut.inst
  };

  console.log("Auto token updated:", market, AUTO[market]);
  return AUTO[market];
}

/* ============================================================
   LIVE LTP FETCH (using auto tokens)
============================================================ */
async function getFutureLTP(market) {
  if (!SESSION.jwt) {
    return { ok: false, reason: "NOT_LOGGED_IN" };
  }

  const meta = FUT_META[market];
  if (!meta) return { ok: false, reason: "BAD_MARKET" };

  const auto = await ensureAutoToken(market);
  if (!auto || !auto.token || !auto.symbol) {
    return { ok: false, reason: "TOKEN_NOT_FOUND" };
  }

  const exch = auto.exch || meta.exch;

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
          exchange: exch,
          tradingsymbol: auto.symbol,
          symboltoken: auto.token
        })
      }
    );

    const data = await r.json().catch(() => null);

    if (!data || data.status === false) {
      return { ok: false, reason: "LTP_FAILED", raw: data };
    }

    const ltp = num(data.data?.ltp);
    if (!ltp) return { ok: false, reason: "BAD_LTP", raw: data };

    return { ok: true, ltp, auto };
  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

/* ============================================================
   DETECT MARKET
============================================================ */
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
    make(ce, "CE", ce - input.spot),
    make(pe, "PE", pe - input.spot),
    make(str, "STRADDLE", str - input.spot)
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
    market = detectMarket(spot, market);
    expiry_days = num(expiry_days, 5);

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
        liveErr = { ok: false, reason: r.reason, raw: r.raw || null };
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
    console.log("Calc error:", e.message);
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
