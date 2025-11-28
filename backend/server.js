/* ============================================================
   FINAL BACKEND — VERSION C (LTP FIXED)
   SmartAPI Login + Auto FUT Token + Live FUT LTP + Trend + Strikes
   Works with Render + Your Frontend
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

// FRONTEND PATH (same repo /frontend)
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ============================================================
   ENV CONFIG
============================================================ */
const SMART_API_KEY = process.env.SMART_API_KEY;
const SMART_API_SECRET = process.env.SMART_API_SECRET; // अभी use नहीं हो रहा, बाद में काम आ सकता है
const SMART_USER_ID = process.env.SMART_USER_ID;
const SMART_TOTP = process.env.SMART_TOTP;

const BASE_URL = "https://apiconnect.angelbroking.com";

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
   HELPERS — BASE32 → TOTP
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
   LOGIN FUNCTION — SmartAPI
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
          "Content-Type": "application/json",
          Accept: "application/json"
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
    SESSION.expires = Date.now() + 20 * 60 * 60 * 1000; // 20 घंटे

    return { ok: true };
  } catch (e) {
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
  return Math.round(v / step) * step;
}

/* ============================================================
   AUTO FUTURE RULES
============================================================ */
const FUT_RULES = {
  nifty: { search: "NIFTY", exch: "NFO", type: "FUTIDX", day: 4 }, // Thurs
  sensex: { search: "SENSEX", exch: "BFO", type: "FUTIDX", day: 4 },
  "natural gas": { search: "NATURALGAS", exch: "MCX", type: "FUTCOM", day: null }
};

const AUTO = {
  nifty: { symbol: null, token: null, expiry: null },
  sensex: { symbol: null, token: null, expiry: null },
  "natural gas": { symbol: null, token: null, expiry: null }
};

function fmtDate(d) {
  return (
    d.getFullYear() +
    "-" +
    (d.getMonth() + 1).toString().padStart(2, "0") +
    "-" +
    d.getDate().toString().padStart(2, "0")
  );
}

function getNextExp(market) {
  const rule = FUT_RULES[market];
  const today = new Date();
  const arr = [];

  if (market === "natural gas") {
    // simple approx: अगले 3 महीने की 25 तारीख
    for (let i = 0; i < 3; i++) {
      const d = new Date(today.getFullYear(), today.getMonth() + i, 25);
      arr.push(fmtDate(d));
    }
  } else {
    // अगले कुछ Thursday
    for (let i = 0; i < 4; i++) {
      const d = new Date(today);
      d.setDate(d.getDate() + i * 7);
      while (d.getDay() !== rule.day) {
        d.setDate(d.getDate() + 1);
      }
      arr.push(fmtDate(d));
    }
  }
  return arr;
}

/* ============================================================
   SEARCH SCRIP + AUTO TOKEN
============================================================ */
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
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify({ searchtext: keyword })
      }
    );

    const d = await r.json().catch(() => null);
    return d?.data || [];
  } catch {
    return [];
  }
}

async function autoFetch(market) {
  const rule = FUT_RULES[market];
  if (!rule) return null;
  if (!SESSION.jwt) return null;

  const expiries = getNextExp(market);
  const all = await smartSearch(rule.search);
  if (!all.length) return null;

  for (const exp of expiries) {
    const [y, m, d] = exp.split("-");
    const match = all.find((x) => {
      const sameExch = x.exch_seg === rule.exch;
      const sameType = x.instrumenttype === rule.type;
      const sameExp =
        typeof x.expirydate === "string" &&
        x.expirydate.includes(`${y}-${m}-${d}`);
      return sameExch && sameType && sameExp;
    });

    if (match) {
      AUTO[market] = {
        symbol: match.tradingsymbol,
        token: match.symboltoken,
        expiry: match.expirydate
      };
      return AUTO[market];
    }
  }

  return null;
}

/* ============================================================
   LIVE LTP FETCH  (FIXED exchangeTokens FORMAT)
============================================================ */
async function getFutureLTP(market) {
  const cfg = FUT_RULES[market];
  if (!cfg) return { ok: false, reason: "BAD_MARKET" };
  if (!SESSION.jwt) return { ok: false, reason: "NOT_LOGGED_IN" };

  let auto = AUTO[market];
  if (!auto.token) {
    auto = await autoFetch(market);
    if (!auto || !auto.token) {
      return { ok: false, reason: "TOKEN_NOT_FOUND" };
    }
  }

  try {
    const payload = {
      mode: "LTP",
      exchangeTokens: {
        [cfg.exch]: [String(auto.token)]
      }
    };

    const r = await fetch(
      `${BASE_URL}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${SESSION.jwt}`,
          "X-PrivateKey": SMART_API_KEY,
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify(payload)
      }
    );

    const data = await r.json().catch(() => null);
    if (!data || data.status === false) {
      return { ok: false, reason: "LTP_FAILED", raw: data };
    }

    let ltp = null;
    const ex = cfg.exch;
    const token = String(auto.token);

    // अलग-अलग possible shapes handle करने की कोशिश
    if (data.data) {
      const fetched = data.data.fetched || data.data[ex] || data.data;

      if (fetched) {
        if (
          fetched[ex] &&
          fetched[ex][token] &&
          fetched[ex][token].ltp != null
        ) {
          ltp = Number(fetched[ex][token].ltp);
        } else if (fetched[token] && fetched[token].ltp != null) {
          ltp = Number(fetched[token].ltp);
        }
      }
    }

    if (!ltp || !Number.isFinite(ltp)) {
      return { ok: false, reason: "LTP_PARSE_FAILED", raw: data };
    }

    return { ok: true, ltp };
  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

/* ============================================================
   MARKET CONFIG
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
   AUTO DETECT MARKET
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
