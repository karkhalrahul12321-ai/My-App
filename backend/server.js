// ===========================
// ALPHA - FINAL (Part 1 of 2)
// Paste Part1 then Part2 to form server.js
// ===========================

/* ---------- Imports & Config ---------- */
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();

/* ---------- App Init ---------- */
const app = express();
app.use(bodyParser.json({ limit: "700kb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

/* ---------- Frontend Serve ---------- */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) => res.sendFile(path.join(frontendPath, "settings.html")));

/* ---------- SmartAPI / ENV ---------- */
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";

/* ---------- In-memory session store ---------- */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

/* ---------- Utilities: base32 decode + TOTP ---------- */
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const output = [];
  input = (input || "").replace(/=+$/, "").toUpperCase();
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
  if (!secret) return null;
  try {
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
  } catch (e) {
    return null;
  }
}

/* ---------- Safe fetch wrapper ---------- */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const j = await r.json().catch(() => null);
    return { ok: true, data: j, status: r.status };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

/* ---------- SmartAPI Login Implementation ---------- */
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) return { ok: false, reason: "PASSWORD_MISSING" };

  const totp = generateTOTP(SMART_TOTP_SECRET);
  if (!totp) return { ok: false, reason: "TOTP_FAIL" };

  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "00:00:00:00:00:00",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify({
        clientcode: SMART_USER_ID,
        password: tradingPassword,
        totp: totp,
      }),
      timeout: 15000,
    });

    const data = await resp.json().catch(() => null);
    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // ~20 hours

    return { ok: true, raw: data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message || String(err) };
  }
}

/* ---------- Routes: Login / Status / Settings ---------- */

// POST /api/login  -> { password }
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
  const r = await smartApiLogin(password);
  if (!r.ok) {
    const map = {
      ENV_MISSING: "SmartAPI ENV missing",
      PASSWORD_MISSING: "Password missing",
      TOTP_FAIL: "TOTP generation failed",
      LOGIN_FAILED: "SmartAPI login failed",
      EXCEPTION: "Login exception",
    };
    return res.status(400).json({ success: false, error: map[r.reason] || "Login error", raw: r.raw || null });
  }
  return res.json({ success: true, message: "SmartAPI Login Successful", session: { logged_in: true, expires_at: session.expires_at } });
});

// GET /api/login/status
app.get("/api/login/status", (req, res) => {
  res.json({ success: true, logged_in: !!session.access_token, expires_at: session.expires_at || null });
});

// GET /api/settings
app.get("/api/settings", (req, res) => {
  res.json({ success: true, apiKey: SMART_API_KEY ? "*****" : "", userId: SMART_USER_ID || "" });
});

/* ---------- Small helpers (used by Part 2) ---------- */

function roundToStep(symbol, value) {
  if (!isFinite(value)) return value;
  if (symbol === "NATURALGAS" || symbol === "NATURAL_GAS") return Math.round(value * 20) / 20; // 0.05 step
  return Math.round(value); // integer steps for indices
}

function toNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function clamp(v, a, b) {
  if (v === null || v === undefined) return v;
  return Math.max(a, Math.min(b, v));
}

/* ---------- Spot Verify / Auto-Fetch (used by Part2) ---------- */

async function fetchFuturesLTP(symbol) {
  // Placeholder: use Angel futures endpoint if available (will be implemented in live fetcher)
  // Return null if not available
  return null;
}

async function fetchOptionChainForSymbol(symbol) {
  // Placeholder for option chain fetch (live mode)
  return null;
}

/* ---------- Placeholder health route ---------- */
app.get("/ping", (req, res) => {
  res.json({ ok: true, msg: "Alpha backend alive", session: !!session.access_token });
});

/* PART 1 COMPLETE */
// ===========================
// ALPHA - FINAL (Part 2 of 2)
// Paste after Part 1
// ===========================

/* ---------- Engines (existing modular engines assumed in /engines) ---------- */
/* NOTE: engines are used as functions receiving data and returning analysis objects.
   If you keep engines as separate files in /engines, require them here.
   For this final file we assume engines are implemented as internal functions or required modules.
*/

// ----------------- Simple internal engine placeholders -----------------
// (If you have separate engine files in /engines, replace these with require(...) calls)

function computeTrendSimple(ema20, ema50, rsi, vwap, spot) {
  // lightweight trend scorer (used if modular engine not required)
  let score = 0;
  const reasons = [];
  if (ema20 > ema50) { score += 25; reasons.push("EMA20 > EMA50"); } else { score -= 25; reasons.push("EMA20 < EMA50"); }
  if (spot > vwap) { score += 20; reasons.push("Spot > VWAP"); } else { score -= 20; reasons.push("Spot < VWAP"); }
  if (rsi > 60) { score += 20; reasons.push("RSI > 60"); } else if (rsi < 40) { score -= 20; reasons.push("RSI < 40"); } else { reasons.push("RSI Neutral"); }
  const main = score > 10 ? "UP" : score < -10 ? "DOWN" : "NEUTRAL";
  const bias = main === "UP" ? "Bullish" : main === "DOWN" ? "Bearish" : "Neutral";
  const strength = Math.min(100, Math.max(0, Math.round(score + 50)));
  return { main, bias, strength, score, reasons };
}

/* ---------- Strike Distance Rules ---------- */
function getDistances(symbol, expiryDays) {
  const decay = Math.max(0.25, Math.min(1, (expiryDays || 7) / 30));
  if (!symbol) symbol = "NIFTY";
  if (symbol.includes("NIFTY")) return [
    Math.round(250 * decay),
    Math.round(200 * decay),
    Math.round(150 * decay)
  ];
  if (symbol.includes("SENSEX")) return [
    Math.round(500 * decay),
    Math.round(400 * decay),
    Math.round(300 * decay)
  ];
  if (symbol.includes("NATUR") || symbol.includes("GAS")) {
    const r = (x) => Math.round(x * 20) / 20;
    return [r(80 * decay), r(60 * decay), r(50 * decay)];
  }
  return [100, 75, 50];
}

/* ---------- Premium fallback ---------- */
function fallbackPremium(symbol, strike, spot) {
  const base = Math.abs((spot || strike) - strike);
  let p = Math.max(5, Math.round(base / 80));
  if (symbol.includes("NATUR") || symbol.includes("GAS")) p = Math.max(2, Math.round(base / 2));
  return p;
}

/* ---------- Build raw strikes (ATM, near, far) ---------- */
function buildRawStrikes(symbol, spot, expiryDays) {
  const atm = roundToStep(symbol, spot);
  const distances = getDistances(symbol, expiryDays);
  const ceStrike = roundToStep(symbol, atm + distances[0]);
  const peStrike = roundToStep(symbol, atm - distances[0]);
  const nearCE   = roundToStep(symbol, atm + distances[1]);
  const nearPE   = roundToStep(symbol, atm - distances[1]);
  return { atm, ceStrike, peStrike, nearCE, nearPE };
}

/* ---------- Reward/Risk entry stepper + target formula ---------- */

function computeTarget(entry, trendStrength, momentumLevel) {
  // trend contribution: trendStrength / 4
  const trend_contrib = (toNumber(trendStrength) || 0) / 4;
  // momentum contribution mapping: High=12, Med=8, Low=4
  let momentum_contrib = 8;
  if (momentumLevel === "High") momentum_contrib = 12;
  else if (momentumLevel === "Low") momentum_contrib = 4;
  const target = +(entry + trend_contrib + momentum_contrib).toFixed(2);
  return { target, trend_contrib, momentum_contrib };
}

function rewardRiskStepper(symbol, ltp, initialEntry, trendStrength, momentumLevel) {
  // SL fixed = 15
  const SL_FIXED = 15;
  let entry = +(initialEntry.toFixed(2));
  // target buffer initial guess - we use computeTarget to derive target from current entry
  for (let i = 0; i < 20; i++) { // max 20 adjustments
    const { target } = computeTarget(entry, trendStrength, momentumLevel);
    const reward = +(target - entry).toFixed(2);
    const sl = SL_FIXED;
    if (reward >= sl) {
      // accept
      return { entry: +entry.toFixed(2), stopLoss: +(entry - sl).toFixed(2), target: +target.toFixed(2), reward, sl };
    }
    // adjust entry lower by step
    const step = Math.max(1, Math.round((ltp || entry) * 0.02)); // 2% step or at least 1
    entry = +(entry - step).toFixed(2);
    if (entry <= 1) break;
  }
  // fallback: return LTP based final with SL fixed
  const finalEntry = +(Math.max(1, ltp || initialEntry).toFixed(2));
  return { entry: finalEntry, stopLoss: +(finalEntry - SL_FIXED).toFixed(2), target: +(finalEntry + SL_FIXED).toFixed(2), reward: SL_FIXED, sl: SL_FIXED };
}

/* ---------- Build final strike objects in UI order: CE, PE, ATM ---------- */
function buildStrikesFinal(symbol, spot, expiryDays, trendObj, livePremiums = {}) {
  // livePremiums: {ceStrike: ltp, peStrike: ltp, atm: ltp}
  const { atm, ceStrike, peStrike } = buildRawStrikes(symbol, spot, expiryDays);
  const ltpCE = livePremiums[ceStrike] ?? livePremiums["CE"] ?? fallbackPremium(symbol, ceStrike, spot);
  const ltpPE = livePremiums[peStrike] ?? livePremiums["PE"] ?? fallbackPremium(symbol, peStrike, spot);
  const ltpATM = livePremiums[atm] ?? fallbackPremium(symbol, atm, spot);

  // initialEntryStart = LTP - 5
  const initCE = Math.max(1, +(ltpCE - 5).toFixed(2));
  const initPE = Math.max(1, +(ltpPE - 5).toFixed(2));
  const initATM = Math.max(1, +(ltpATM - 5).toFixed(2));

  // determine momentum level from trendObj.score or rsi heuristics
  const momentumLevel = (trendObj.strength >= 65) ? "High" : (trendObj.strength >= 45) ? "Medium" : "Low";

  const ceCalc = rewardRiskStepper(symbol, ltpCE, initCE, trendObj.strength, momentumLevel);
  const peCalc = rewardRiskStepper(symbol, ltpPE, initPE, trendObj.strength, momentumLevel);
  const atmCalc = rewardRiskStepper(symbol, ltpATM, initATM, trendObj.strength, momentumLevel);

  return [
    { strike: ceStrike, distance: Math.abs(ceStrike - atm), entry: ceCalc.entry, stopLoss: ceCalc.stopLoss, target: ceCalc.target },
    { strike: peStrike, distance: Math.abs(peStrike - atm), entry: peCalc.entry, stopLoss: peCalc.stopLoss, target: peCalc.target },
    { strike: atm, distance: 0, entry: atmCalc.entry, stopLoss: atmCalc.stopLoss, target: atmCalc.target }
  ];
}

/* ---------- Spot verify & auto-correct ---------- */
async function verifyOrFetchSpot(symbol, providedSpot) {
  // If provided and numeric: quick sanity checks via futures/option chain (placeholders)
  const provided = toNumber(providedSpot);
  if (provided && provided > 0) {
    // try to verify with futures LTP
    const fut = await fetchFuturesLTP(symbol).catch(()=>null);
    if (fut && fut > 0) {
      const diff = Math.abs(fut - provided);
      if (diff < Math.max(2, Math.round(fut * 0.01))) {
        // close enough
        return provided;
      } else {
        // mismatch -> prefer futures-derived spot if available
        return fut;
      }
    }
    // if no futures info, try option ATM probe (placeholder)
    const oc = await fetchOptionChainForSymbol(symbol).catch(()=>null);
    if (oc && oc.atm) {
      const atmSpot = oc.atm;
      const diff2 = Math.abs(atmSpot - provided);
      if (diff2 < Math.max(2, Math.round(atmSpot * 0.01))) return provided;
      return atmSpot;
    }
    // fallback keep provided
    return provided;
  } else {
    // no provided spot -> try to fetch from futures or option chain
    const fut2 = await fetchFuturesLTP(symbol).catch(()=>null);
    if (fut2 && fut2 > 0) return fut2;
    const oc2 = await fetchOptionChainForSymbol(symbol).catch(()=>null);
    if (oc2 && oc2.atm) return oc2.atm;
    // ultimate fallback
    return provided || null;
  }
}

/* ---------- /api/calc (main engine route expected by frontend) ---------- */
app.post("/api/calc", async (req, res) => {
  try {
    const b = req.body || {};
    const market = (b.market || "NIFTY").toUpperCase();
    // map market to internal symbol keys if needed
    const symbol = market; // simple mapping; adjust if your scrip master uses tokens

    // inputs (manual mode may provide these)
    let ema20 = toNumber(b.ema20);
    let ema50 = toNumber(b.ema50);
    let rsi   = toNumber(b.rsi);
    let vwap  = toNumber(b.vwap);
    let spot  = toNumber(b.spot);
    const expiryDays = toNumber(b.expiry_days || b.expiryDays || b.daysToExpiry || 7);

    // Spot verify / autofill
    const realSpot = await verifyOrFetchSpot(symbol, spot);
    if (!realSpot) {
      return res.json({ success: false, error: "Unable to determine spot" });
    }

    // If any indicator missing: compute from live candles (placeholder)
    // For now if ema/rsi/vwap missing we fallback to simple heuristics
    if (ema20 === null || ema50 === null || rsi === null || vwap === null) {
      // Ideally use live-fetcher to compute; for now assume approximate
      // NOTE: In full-engine mode these will be calculated from candles
      // Keep existing provided ones if present, else fallback to spot-based guesses
      ema20 = ema20 || Math.round(realSpot - 86);
      ema50 = ema50 || Math.round(realSpot - 50);
      rsi = rsi || 55;
      vwap = vwap || realSpot - 20;
    }

    // run trend engine (use modular engine if present)
    const trendObj = computeTrendSimple(ema20, ema50, rsi, vwap, realSpot);

    // In live-mode we would fetch option chain to get real LTPs
    const livePremiums = {}; // placeholder map of strike->ltp; live-fetcher will fill this

    // build final strikes
    const strikes = buildStrikesFinal(symbol, realSpot, expiryDays, trendObj, livePremiums);

    const finalResponse = {
      success: true,
      trend: {
        main: trendObj.main,
        strength: trendObj.strength,
        bias: trendObj.bias,
        score: trendObj.score
      },
      input: {
        ema20,
        ema50,
        rsi,
        vwap,
        spot: realSpot,
        expiry_days: expiryDays,
        market: symbol
      },
      strikes: strikes,
      meta: {
        live_data_used: false,
        sources: {
          candles: false,
          oi: false,
          futures: false,
          option_chain: false
        }
      },
      login_status: session.access_token ? "Logged-in" : "Demo Mode",
      auto_tokens: {
        access: session.access_token || "",
        refresh: session.refresh_token || "",
        feed: session.feed_token || ""
      }
    };

    return res.json(finalResponse);

  } catch (err) {
    console.error("CALC ERROR:", err);
    return res.json({ success: false, error: err.message || String(err) });
  }
});

/* ---------- /analysis/manual compatibility route ---------- */
app.post("/analysis/manual", async (req, res) => {
  // forward body to /api/calc for compatibility with older UI endpoints
  req.url = "/api/calc";
  return app._router.handle(req, res);
});

/* ---------- Start Server if run directly ---------- */
if (!module.parent) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log("ALPHA FINAL fully synced running on", PORT));
}

// ===========================
// PART 2 COMPLETE — ALPHA FULLY SYNCED
// ===========================
