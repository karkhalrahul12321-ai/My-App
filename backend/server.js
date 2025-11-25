// =====================================
// Trading Helper Backend (AUTO FUTURE TOKEN)
// SmartAPI Login + Auto Future Detect + Live LTP + Trend + Strikes
// Markets: Nifty, Sensex, Natural Gas
// =====================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(bodyParser.json());

// =====================================
// SERVE FRONTEND
// =====================================
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
// SMARTAPI CONFIG
// =====================================
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// सिर्फ fallback के लिए (अगर कभी auto-fetch fail हो जाए)
const SMART_NIFTY_TOKEN = process.env.SMART_NIFTY_TOKEN || "";
const SMART_SENSEX_TOKEN = process.env.SMART_SENSEX_TOKEN || "";
const SMART_NATGAS_TOKEN = process.env.SMART_NATGAS_TOKEN || "";

const SMART_NIFTY_SYMBOL =
  process.env.SMART_NIFTY_SYMBOL || "NIFTY30JAN25FUT";
const SMART_SENSEX_SYMBOL =
  process.env.SMART_SENSEX_SYMBOL || "SENSEX30JAN25FUT";
const SMART_NATGAS_SYMBOL =
  process.env.SMART_NATGAS_SYMBOL || "NATURALGAS27JAN25FUT";

// Angel का master CSV (यहीं से हम auto token निकालेंगे)
const ANGEL_MASTER_CSV_URL =
  "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.csv";

// =====================================
// SMARTAPI SESSION
// =====================================
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0
};

// =====================================
// BASE32 → BYTES (TOTP के लिए)
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
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }
    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // ~20h
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
// LOGIN APIs
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

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null
  });
});

app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || ""
  });
});

// =====================================
// SMALL HELPERS
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
// MARKET CONFIG (static info only)
// =====================================
const MARKET_CONFIG = {
  nifty: {
    name: "Nifty",
    strikeStep: 50,
    baseDistances: { far: 250, mid: 200, near: 150 },
    exchange: "NFO",
    underlying: "NIFTY"
  },
  sensex: {
    name: "Sensex",
    strikeStep: 100,
    baseDistances: { far: 500, mid: 400, near: 300 },
    exchange: "BFO",
    underlying: "SENSEX"
  },
  "natural gas": {
    name: "Natural Gas",
    strikeStep: 5,
    baseDistances: { far: 80, mid: 60, near: 50 },
    exchange: "MCX",
    underlying: "NATURALGAS"
  }
};

// =====================================
// AUTO DETECT MARKET (spot से)
// =====================================
function autoDetectMarket(spot, explicitRaw) {
  const m = (explicitRaw || "").toString().trim().toLowerCase();
  if (MARKET_CONFIG[m]) return m;
  const s = num(spot, 0);
  if (s > 20 && s < 2000) return "natural gas";
  if (s >= 10000 && s < 40000) return "nifty";
  if (s >= 40000) return "sensex";
  return "nifty";
}

function normalizeInput(body) {
  const spotVal = num(body.spot);
  const detectedMarket = autoDetectMarket(spotVal, body.market);
  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot: spotVal,
    market: detectedMarket,
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live
  };
}

// =====================================
// AUTO FUTURE TOKEN CACHE
// =====================================
const autoFutureCache = {
  lastFetch: 0,
  markets: {
    nifty: null,
    sensex: null,
    "natural gas": null
  }
};

// CSV expiry parse helper
function parseExpiryDate(str) {
  if (!str) return null;
  // Handle formats like "30-DEC-2025" or "30-DEC-25"
  const cleaned = String(str).trim().replace(/\s+/g, "-");
  const d = Date.parse(cleaned);
  return Number.isFinite(d) ? d : null;
}

// पूरे CSV से सिर्फ 3 futures निकालना
function extractFuturesFromCSV(csvText) {
  const lines = csvText.split(/\r?\n/);
  if (lines.length < 2) return {};

  const header = lines[0].split(",");
  const colIndex = (name) => header.indexOf(name);

  const idxSymbol = colIndex("symbol");
  const idxName = colIndex("name");
  const idxExpiry = colIndex("expiry");
  const idxInst = colIndex("instrumenttype");
  const idxSeg = colIndex("exch_seg");
  const idxToken = colIndex("symboltoken");
  const idxTsym = colIndex("tradingsymbol");

  const out = {
    nifty: [],
    sensex: [],
    "natural gas": []
  };

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const parts = line.split(",");

    const symbol = (parts[idxSymbol] || "").trim().toUpperCase();
    const name = (parts[idxName] || "").trim().toUpperCase();
    const inst = (parts[idxInst] || "").trim().toUpperCase();
    const seg = (parts[idxSeg] || "").trim().toUpperCase();
    const token = (parts[idxToken] || "").trim();
    const tsym = (parts[idxTsym] || "").trim();
    const expiryRaw = parts[idxExpiry];

    if (!token || !tsym || !expiryRaw) continue;

    const expiry = parseExpiryDate(expiryRaw);
    if (!expiry) continue;

    // सिर्फ FUTURE चाहिए
    if (!inst.startsWith("FUT")) continue;

    // Nifty FUTIDX (NFO)
    if (seg === "NFO" && symbol === "NIFTY") {
      out.nifty.push({ tradingsymbol: tsym, token, expiry, seg });
    }

    // Sensex FUTIDX (BFO)
    if (seg === "BFO" && symbol === "SENSEX") {
      out.sensex.push({ tradingsymbol: tsym, token, expiry, seg });
    }

    // Natural Gas FUTCOM (MCX)
    if (seg === "MCX" && symbol === "NATURALGAS") {
      out["natural gas"].push({ tradingsymbol: tsym, token, expiry, seg });
    }
  }

  return out;
}

// हर market के लिए nearest expiry ≥ today चुनना
function selectNearestContract(list) {
  if (!list || list.length === 0) return null;
  const today = new Date();
  const t0 = new Date(
    today.getFullYear(),
    today.getMonth(),
    today.getDate()
  ).getTime();

  // पहले future expiries जो आज या उससे आगे हैं
  const futureList = list.filter((x) => x.expiry >= t0);
  const base = futureList.length > 0 ? futureList : list;

  let best = base[0];
  for (const item of base) {
    if (item.expiry < best.expiry) best = item;
  }
  return best;
}

// CSV download + cache fill
async function refreshAutoFutures() {
  const now = Date.now();
  // हर 6 घंटे में एक बार से ज्यादा नहीं
  if (now - autoFutureCache.lastFetch < 6 * 60 * 60 * 1000) return;

  try {
    const resp = await fetch(ANGEL_MASTER_CSV_URL);
    const txt = await resp.text();
    const all = extractFuturesFromCSV(txt);

    for (const m of Object.keys(autoFutureCache.markets)) {
      const best = selectNearestContract(all[m]);
      if (best) {
        autoFutureCache.markets[m] = {
          tradingsymbol: best.tradingsymbol,
          token: best.token,
          exchange: best.seg,
          expiry: best.expiry
        };
      }
    }

    autoFutureCache.lastFetch = now;
  } catch (e) {
    // अगर CSV fail हो गया तो भी backend silently चलने दो
    console.error("Auto future CSV fetch failed:", e.message);
  }
}

// किसी भी market के लिए final future info (auto + fallback)
async function getFutureForMarket(marketKey) {
  const m = MARKET_CONFIG[marketKey];
  if (!m) return null;

  await refreshAutoFutures();
  const cached = autoFutureCache.markets[marketKey];

  if (cached && cached.token && cached.tradingsymbol) {
    return cached;
  }

  // Fallback: env में दिए गए manual symbol/token
  if (marketKey === "nifty" && SMART_NIFTY_TOKEN) {
    return {
      tradingsymbol: SMART_NIFTY_SYMBOL,
      token: SMART_NIFTY_TOKEN,
      exchange: m.exchange,
      expiry: null
    };
  }
  if (marketKey === "sensex" && SMART_SENSEX_TOKEN) {
    return {
      tradingsymbol: SMART_SENSEX_SYMBOL,
      token: SMART_SENSEX_TOKEN,
      exchange: m.exchange,
      expiry: null
    };
  }
  if (marketKey === "natural gas" && SMART_NATGAS_TOKEN) {
    return {
      tradingsymbol: SMART_NATGAS_SYMBOL,
      token: SMART_NATGAS_TOKEN,
      exchange: m.exchange,
      expiry: null
    };
  }

  // बिल्कुल ही कुछ न मिला
  return null;
}

// =====================================
// LIVE LTP (SmartAPI Quote)
// =====================================
async function getLiveLTP(tradingsymbol, exchange, symbolToken) {
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
          tradingsymbol: tradingsymbol || "",
          symboltoken: symbolToken || ""
        })
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || data.status === false) {
      return {
        ok: false,
        error: "LTP_FETCH_FAILED",
        raw: data || null
      };
    }

    return { ok: true, ltp: data.data.ltp };
  } catch (err) {
    return { ok: false, error: "LTP_EXCEPTION", detail: err.message };
  }
}

// Optional standalone LTP API
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
// TREND ENGINE (same as पहले वाला)
// =====================================
function computeTrend(input) {
  const ema20 = num(input.ema20);
  const ema50 = num(input.ema50);
  const rsi = num(input.rsi);
  const vwap = num(input.vwap);
  const spot = num(input.spot);

  const comp = {};
  let score = 50;
  let bias = "NONE";

  if (!ema20 || !ema50 || !spot || !vwap || !rsi) {
    comp.warning = "Inputs missing (approx trend)";
    return {
      main: "SIDEWAYS",
      strength: "NEUTRAL",
      score: 50,
      bias: "NONE",
      components: comp,
      comment: "Data incomplete, default sideways."
    };
  }

  const emaMid = (ema20 + ema50) / 2;
  const emaDiff = ema20 - ema50;
  const emaPct = (emaDiff / emaMid) * 100;
  let emaScore = clamp(emaPct * 1.5, -25, 25);

  comp.ema_gap =
    emaPct > 0.3
      ? `Bullish (${emaPct.toFixed(2)}%)`
      : emaPct < -0.3
      ? `Bearish (${emaPct.toFixed(2)}%)`
      : `Flat (${emaPct.toFixed(2)}%)`;

  let rsiScore = clamp((rsi - 50) * 1.2, -25, 25);

  if (rsi >= 70) comp.rsi = `RSI ${rsi} (overbought)`;
  else if (rsi >= 60) comp.rsi = `RSI ${rsi} (bullish)`;
  else if (rsi <= 30) comp.rsi = `RSI ${rsi} (oversold)`;
  else if (rsi <= 40) comp.rsi = `RSI ${rsi} (bearish)`;
  else comp.rsi = `RSI ${rsi} (neutral)`;

  const vwapDiff = spot - vwap;
  const vwapPct = (vwapDiff / vwap) * 100;
  let vwapScore = clamp(vwapPct * 1.5, -20, 20);

  comp.vwap =
    vwapPct > 0.1
      ? `Price above VWAP (${vwapPct.toFixed(2)}%)`
      : vwapPct < -0.1
      ? `Below VWAP (${vwapPct.toFixed(2)}%)`
      : `Near VWAP (${vwapPct.toFixed(2)}%)`;

  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) {
    structScore = 10;
    comp.price_structure = "Clean bullish";
  } else if (spot < ema20 && ema20 < ema50) {
    structScore = -10;
    comp.price_structure = "Clean bearish";
  } else {
    comp.price_structure = "Mixed structure";
  }

  const d = num(input.expiry_days, 7);
  let expiryAdj = 0;
  if (d <= 2) {
    expiryAdj = -5;
    comp.expiry = "Expiry near (volatile)";
  } else if (d >= 10) {
    expiryAdj = 3;
    comp.expiry = "Expiry far (stable)";
  } else {
    comp.expiry = "Expiry mid";
  }

  score =
    50 +
    emaScore * 0.4 +
    rsiScore * 0.3 +
    vwapScore * 0.2 +
    structScore * 0.2 +
    expiryAdj;

  score = clamp(score, 0, 100);

  let main = "SIDEWAYS";
  let strength = "RANGE";
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
  } else {
    main = "SIDEWAYS";
    strength = "RANGE";
    bias = "NONE";
  }

  const comment = `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`;

  return {
    main,
    strength,
    score,
    bias,
    components: comp,
    comment
  };
}

// =====================================
// STRIKE ENGINE
// =====================================
function scaleDistancesByExpiry(expiryDays, baseDistances, step) {
  const d = Math.max(0, num(expiryDays, 7));
  let factor = 0.2 + 0.05 * d;
  if (factor > 1) factor = 1;
  const out = {};
  ["near", "mid", "far"].forEach((k) => {
    const raw = baseDistances[k] || 0;
    let v = raw * factor;
    if (v < step / 2) v = step / 2;
    out[k] = v;
  });
  return out;
}

function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market] || MARKET_CONFIG["nifty"];
  const { spot, expiry_days } = input;

  const scaled = scaleDistancesByExpiry(
    expiry_days,
    cfg.baseDistances,
    cfg.strikeStep
  );

  const atm = roundToStep(spot, cfg.strikeStep);

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

  const ceStrike = roundToStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDist, cfg.strikeStep);
  const straddleStrike = atm;

  function makeOption(strike, type, diff) {
    const steps = Math.max(1, Math.round(Math.abs(diff) / cfg.strikeStep));
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
    makeOption(ceStrike, "CE", ceStrike - spot),
    makeOption(peStrike, "PE", peStrike - spot),
    makeOption(straddleStrike, "STRADDLE", straddleStrike - spot)
  ];
}

// =====================================
// MAIN /api/calc  (AUTO FUTURE + AUTO TOKEN)
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);
    const cfg = MARKET_CONFIG[input.market];

    let liveUsed = false;
    let liveError = null;
    let liveLtpValue = null;
    let futMeta = null;

    if (input.use_live && cfg && session.access_token) {
      const fut = await getFutureForMarket(input.market);
      futMeta = fut;

      if (fut && fut.token && fut.tradingsymbol) {
        const r = await getLiveLTP(
          fut.tradingsymbol,
          fut.exchange || cfg.exchange,
          fut.token
        );
        if (r.ok && num(r.ltp) > 0) {
          input.spot = num(r.ltp);
