/* ============================
   ALPHA-SAFE BACKEND (PART 1)
   ============================*/

require("dotenv").config();
const express = require("express");
const fetch = require("node-fetch");
const moment = require("moment");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SMART_API_KEY = process.env.SMART_API_KEY;
const SMART_API_SECRET = process.env.SMART_API_SECRET;
const SMART_TOTP = process.env.SMART_TOTP;
const SMART_USER_ID = process.env.SMART_USER_ID;

let session = {
  access_token: null,
  refresh_token: null,
  expires_at: 0,
  logged_in: false,
};

/* ----------- SMART LOGIN FUNCTION ----------- */
async function smartLogin() {
  try {
    const url = "https://apiconnect.angelbroking.com/rest/auth/angel-login";
    const body = {
      clientcode: SMART_USER_ID,
      totp: SMART_TOTP,
      password: SMART_API_SECRET,
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify(body),
    });

    const j = await r.json().catch(() => null);
    if (j && j.data && j.data.jwtToken) {
      session.access_token = j.data.jwtToken;
      session.expires_at = Date.now() + 1000 * 60 * 60;
      session.logged_in = true;
      return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}

/* ----------- CHECK LOGIN STATUS ----------- */
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: session.logged_in,
    expires_at: session.expires_at,
  });
});

/* ----------- PING ROUTE ----------- */
app.get("/ping", (req, res) => {
  res.json({
    ok: true,
    alive: true,
    logged_in: session.logged_in,
    last_spot: null,
  });
});

/* ---------- SAFE FILTERS (FIXED VERSION) ---------- */

function detectVolumeSpikeSafe() {
  return false; // ALWAYS SAFE — AUTOMATIC FAKE SPIKE REMOVED
}

function rejectFakeBreakoutSafe(trendObj, futDiff) {
  if (trendObj.score < 5) return true;
  if (Math.abs(futDiff) > 80) return true;
  return false;
}

/* ---------- OPTION CHAIN FETCH (ASYNC FIXED) ---------- */

async function fetchOptionChainRaw(symbol) {
  try {
    const url =
      "https://apiconnect.angelbroking.com/rest/secure/option-chain/feeder";
    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify({ symbol }),
    });

    const j = await r.json().catch(() => null);
    if (j && j.data) return j.data;
    return null;
  } catch (e) {
    return null;
  }
}
/* ---------- ATM FINDER ---------- */

function findATMFromOptionChain(rawChain) {
  if (!rawChain || !Array.isArray(rawChain) || !rawChain.length) return null;

  const strikes = rawChain.map((it) => Number(it.strikePrice));
  const spot = Number(rawChain[0].underlyingValue || 0);
  if (!spot) return null;

  let best = strikes[0];
  let diff = Math.abs(best - spot);

  for (let s of strikes) {
    const d = Math.abs(s - spot);
    if (d < diff) {
      diff = d;
      best = s;
    }
  }

  return best;
}

/* ---------- TREND ENGINE ---------- */

function calculateTrend(ema20, ema50, rsi) {
  let score = 0;

  if (ema20 > ema50) score += 10;
  if (rsi > 60) score += 5;
  if (rsi > 70) score += 2;

  return {
    direction: ema20 > ema50 ? "UP" : "DOWN",
    score,
  };
}

/* ---------- STRIKE SELECTOR ---------- */

function chooseStrikes(atm, step = 50) {
  return {
    atm,
    ce: atm + step,
    pe: atm - step,
  };
}

/* ---------- ENTRY/SL/TARGET ENGINE ---------- */

function buildTradeLevels(strikes, futLtp, trend) {
  const entry = strikes.atm;
  const sl = entry - 40;
  const target = entry + 80;

  return {
    entry,
    sl,
    target,
    ce: strikes.ce,
    pe: strikes.pe,
    direction: trend.direction,
  };
}

/* ---------- FETCH FUTURES LTP (SAFE) ---------- */

async function fetchFutureLtpSafe(symbol) {
  try {
    const url =
      "https://apiconnect.angelbroking.com/rest/secure/market/quote/v3";

    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify({
        mode: "FULL",
        exchangeTokens: {
          NFO: [symbol],
        },
      }),
    });

    const j = await r.json().catch(() => null);
    if (j && j.data && j.data.fetched && j.data.fetched.length) {
      return Number(j.data.fetched[0].ltp || 0);
    }

    return null;
  } catch (e) {
    return null;
  }
}
/* ---------- EXPIRY DETECTOR ---------- */

function detectExpiry(symbol) {
  const today = moment().utcOffset("+05:30");
  const weekday = today.isoWeekday();

  let expiry = today.clone().isoWeekday(4); // Thursday

  if (weekday > 4) expiry.add(1, "week");

  return expiry.format("YYYY-MM-DD");
}

/* ---------- MAIN CALC ENGINE (SAFE VERSION) ---------- */

app.post("/api/calc", async (req, res) => {
  try {
    const { ema20, ema50, rsi, spot, market, use_live } = req.body || {};

    const symbol = (market || "").toUpperCase();

    /* 1) TREND ENGINE */
    const trend = calculateTrend(Number(ema20), Number(ema50), Number(rsi));

    /* 2) FETCH FUTURES LTP */
    let futLtp = null;
    if (use_live) {
      futLtp = await fetchFutureLtpSafe(symbol);
    }

    const futDiff = futLtp ? futLtp - Number(spot) : 0;

    /* 3) SAFE FILTER */
    const fake = rejectFakeBreakoutSafe(trend, futDiff);

    if (fake) {
      return res.json({
        success: false,
        error: "Fake breakout blocked (SAFE MODE)",
        trend,
        futDiff,
      });
    }

    /* 4) OPTION CHAIN */
    const chain = await fetchOptionChainRaw(symbol);

    if (!chain) {
      return res.json({
        success: false,
        error: "Option chain missing",
        trend,
      });
    }

    /* 5) ATM */
    const atm = findATMFromOptionChain(chain);

    if (!atm) {
      return res.json({
        success: false,
        error: "ATM not found",
        trend,
      });
    }

    /* 6) STRIKES */
    const strikes = chooseStrikes(atm);

    /* 7) LEVELS */
    const levels = buildTradeLevels(strikes, futLtp, trend);

    /* 8) OUTPUT */
    return res.json({
      success: true,
      trend,
      atm,
      strikes,
      levels,
      futLtp,
      expiry: detectExpiry(symbol),
    });
  } catch (e) {
    return res.json({
      success: false,
      error: String(e),
    });
  }
});
/* ---------- ALIAS ROUTE ---------- */
app.post("/api/suggest", (req, res) => {
  req.url = "/api/calc";
  app._router.handle(req, res);
});

/* ---------- SERVER START ---------- */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("ALPHA-SAFE running on PORT", PORT);
});

/* ============================
   END OF ALPHA-SAFE BACKEND
   ============================ */
