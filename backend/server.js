// =====================================
// Trading Helper Backend  (FINAL)
// SmartAPI Login + Live LTP + Calc Engine
// =====================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const fetch = require("node-fetch");
const crypto = require("crypto");

// =====================================
// APP INIT
// =====================================
const app = express();
app.use(bodyParser.json());

// =====================================
// SERVE FRONTEND FILES
// =====================================
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
// SMARTAPI CONFIG  (ENV से)
// =====================================
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// OPTIONAL: index LTP tokens (चाहें तो Render में env बना सकते हैं)
const SMART_NIFTY_TOKEN = process.env.SMART_NIFTY_TOKEN || "";
const SMART_SENSEX_TOKEN = process.env.SMART_SENSEX_TOKEN || "";
const SMART_NATGAS_TOKEN = process.env.SMART_NATGAS_TOKEN || "";

// =====================================
// SMARTAPI SESSION (TOKENS STORAGE)
// =====================================
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0
};

// =====================================
// BASE32 → BYTES  (TOTP के लिए)
// =====================================
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

// =====================================
// GENERATE TOTP
// =====================================
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

// =====================================
// SMARTAPI LOGIN
// =====================================
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }

  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY
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
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    // approx 20 घंटे valid
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
// /api/login  (frontend password से login)
// =====================================
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";

  if (!password) {
    return res.json({ success: false, error: "Password missing" });
  }

  const r = await smartApiLogin(String(password));

  if (!r.ok) {
    return res.json({
      success: false,
      error:
        r.reason === "ENV_MISSING"
          ? "SmartAPI ENV missing"
          : r.reason === "LOGIN_FAILED"
          ? "SmartAPI login failed"
          : "Login error: " + (r.error || "Unknown")
    });
  }

  res.json({
    success: true,
    message: "SmartAPI login successful",
    session: {
      hasToken: !!session.access_token,
      expires_at: session.expires_at
    }
  });
});

// =====================================
// /api/login/status
// =====================================
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null
  });
});

// =====================================
// (OPTIONAL) /api/settings – सिर्फ frontend को info देने के लिए
// =====================================
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY ? SMART_API_KEY : "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? SMART_TOTP_SECRET : ""
  });
});

// =====================================
// HELPERS
// =====================================
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

// =====================================
// MARKET CONFIG (3 markets + LTP tokens)
// =====================================
const MARKET_CONFIG = {
  nifty: {
    strikeStep: 50,
    angelSymbol: "NIFTY",
    exchange: "NSE",
    ltpToken: SMART_NIFTY_TOKEN || "" // चाहें तो env में भरें
  },
  sensex: {
    strikeStep: 100,
    angelSymbol: "SENSEX",
    exchange: "BSE",
    ltpToken: SMART_SENSEX_TOKEN || ""
  },
  "natural gas": {
    strikeStep: 5,
    angelSymbol: "NATURALGAS",
    exchange: "MCX",
    ltpToken: SMART_NATGAS_TOKEN || ""
  }
};

// =====================================
// AUTO DETECT MARKET
// =====================================
function autoDetectMarket(spot, raw) {
  const m = (raw || "").toString().trim().toLowerCase();
  if (MARKET_CONFIG[m]) return m;

  if (spot > 20 && spot < 2000) return "natural gas";
  if (spot >= 10000 && spot < 40000) return "nifty";
  return "sensex";
}

// =====================================
// NORMALIZE INPUT (request → clean object)
// =====================================
function normalizeInput(body) {
  const spot = num(body.spot);
  const marketKey = autoDetectMarket(spot, body.market);

  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot,
    market: marketKey,
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live
  };
}

// ====================================================================
// ⭐ LIVE LTP FUNCTION (backend से SmartAPI quote call)
// ====================================================================
async function getLiveLTP(symbol, exchange, symbolToken) {
  try {
    if (!session.access_token) {
      return { ok: false, error: "NOT_LOGGED_IN" };
    }

    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: `Bearer ${session.access_token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          mode: "LTP",
          exchange: exchange,
          tradingsymbol: symbol,
          symboltoken: symbolToken || ""
        })
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || data.status === false) {
      return { ok: false, error: "LTP_FETCH_FAILED", raw: data || null };
    }

    return { ok: true, ltp: data.data.ltp };
  } catch (err) {
    return { ok: false, error: "LTP_EXCEPTION", detail: err.message };
  }
}

// =====================================
// /api/ltp – generic LTP API (optional use)
// =====================================
app.post("/api/ltp", async (req, res) => {
  try {
    if (!session.access_token) {
      return res.json({ success: false, error: "NOT_LOGGED_IN" });
    }

    const symbol = req.body.symbol;
    const exchange = req.body.exchange || "NSE";
    const token = req.body.symboltoken || "";

    if (!symbol) {
      return res.json({ success: false, error: "Missing symbol" });
    }

    const r = await getLiveLTP(symbol, exchange, token);

    if (!r.ok) {
      return res.json({ success: false, error: "LTP error", detail: r });
    }

    res.json({ success: true, ltp: r.ltp });
  } catch (err) {
    res.json({
      success: false,
      error: "EXCEPTION in /api/ltp",
      detail: err.message
    });
  }
});

// =====================================
// TREND ENGINE
// =====================================
function computeTrend(input) {
  const ema20 = num(input.ema20);
  const ema50 = num(input.ema50);
  const rsi = num(input.rsi);
  const vwap = num(input.vwap);
  const spot = num(input.spot);

  const comp = {};
  let score = 50;

  // EMA
  const emaMid = (ema20 + ema50) / 2 || 1;
  const emaDiff = ema20 - ema50;
  const emaPct = (emaDiff / emaMid) * 100;
  comp.ema_gap = `EMA gap ${emaPct.toFixed(2)}%`;
  score += clamp(emaPct, -20, 20);

  // RSI
  comp.rsi = `RSI ${rsi}`;
  score += clamp(rsi - 50, -20, 20);

  // VWAP
  const vw = vwap ? ((spot - vwap) / vwap) * 100 : 0;
  comp.vwap = `VWAP ${vw.toFixed(2)}%`;
  score += clamp(vw, -10, 10);

  score = clamp(score, 0, 100);

  let main = "SIDEWAYS";
  let bias = "NONE";

  if (score >= 60) {
    main = "UPTREND";
    bias = "CE";
  } else if (score <= 40) {
    main = "DOWNTREND";
    bias = "PE";
  }

  return { main, score, bias, components: comp };
}

// =====================================
// STRIKE ENGINE
// =====================================
function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const step = cfg.strikeStep;
  const atm = roundToStep(input.spot, step);

  const ceStrike = atm + step;
  const peStrike = atm - step;

  function makeOption(strike, type, diff) {
    const steps = Math.max(1, Math.round(Math.abs(diff) / step));
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
    makeOption(ceStrike, "CE", ceStrike - input.spot),
    makeOption(peStrike, "PE", peStrike - input.spot),
    makeOption(atm, "STRADDLE", atm - input.spot)
  ];
}

// =====================================
// /api/calc – MAIN API (अब LTP भी try करेगा)
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);
    const cfg = MARKET_CONFIG[input.market];

    let liveUsed = false;
    let liveError = null;
    let liveLtpValue = null;

    // अगर use_live true है और login है, तो LTP try करो
    if (input.use_live && cfg && session.access_token) {
      const token = cfg.ltpToken || "";
      const r = await getLiveLTP(cfg.angelSymbol, cfg.exchange, token);

      if (r.ok && num(r.ltp) > 0) {
        input.spot = num(r.ltp);
        liveUsed = true;
        liveLtpValue = input.spot;
      } else {
        liveError = r.error || "LTP_FAILED";
      }
    }

    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token
        ? "SmartAPI Logged-In"
        : "Not logged-in (demo mode)",
      input,
      trend,
      strikes,
      meta: {
        live_data_used: liveUsed,
        live_ltp: liveLtpValue,
        live_error: liveError,
        note:
          "अगर live_data_used false है तो spot वही manual value है जो आपने input में डाली थी।"
      }
    });
  } catch (err) {
    console.error("Error in /api/calc:", err);
    res.json({ success: false, error: err.message || String(err) });
  }
});

// =====================================
// START SERVER
// =====================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER running on port " + PORT);
});
