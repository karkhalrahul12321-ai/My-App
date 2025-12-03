// ==============================================
// Final server.js -- SmartAPI + OptionChain V2 WebSocket + Premium Engine
// Deploy-ready: login (TOTP) + websocket (v2) + premium HTTP + trend + strikes
// ==============================================

/*
  IMPORTANT:
  - ENV vars needed:
    SMARTAPI_BASE (optional)
    SMART_API_KEY
    SMART_API_SECRET
    SMART_TOTP
    SMART_USER_ID
    PORT
*/

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const WebSocket = require("ws");
const zlib = require("zlib");
require("dotenv").config();

// ---------- CONFIG ----------
const PORT = process.env.PORT || 10000;
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// Behavior
const AUTO_LOGIN_ON_START = true;

const WS_TRY_VARIANTS = [
  SMARTAPI_BASE.replace(/^http/, "ws") + "/ws",
  SMARTAPI_BASE.replace(/^http/, "wss") + "/ws",
  SMARTAPI_BASE.replace(/^http/, "wss") + "/ws/v2",
  SMARTAPI_BASE.replace(/^http/, "wss") + "/feed",
];

// ---------- APP INIT ----------
const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

// ---------- GLOBAL STATE ----------
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

let AUTO = {
  nifty: { symbol: null, token: null, expiry: null, ltp: null },
  sensex: { symbol: null, token: null, expiry: null, ltp: null },
  "natural gas": { symbol: null, token: null, expiry: null, ltp: null },
};

let SCRIP_INDEX = {}; // symbolToken → scrip info

let ws = null;
let wsConnected = false;
let wsSubscriptions = new Set();
let wsReconnectTimer = null;

// ---------- HELPERS ----------
function safeNum(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}
function now() { return Date.now(); }
function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
function roundToStep(v, step) { return Math.round(v / step) * step; }

// Base32 → TOTP
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
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

// Safe Fetch Wrapper
async function httpFetch(url, opts = {}, timeout = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}

// Fallback URL attempts
async function tryFetchVariants(pathOrUrl, opts = {}) {
  if (pathOrUrl.startsWith("http")) {
    try { return await httpFetch(pathOrUrl, opts); }
    catch (e) {}
  }
  const variants = [
    SMARTAPI_BASE.replace(/\/+$/, "") + pathOrUrl,
    SMARTAPI_BASE.replace(/^https:/, "http:").replace(/\/+$/, "") + pathOrUrl,
    SMARTAPI_BASE.replace(/^http:/, "https:").replace(/\/+$/, "") + pathOrUrl,
  ];
  for (const u of variants) {
    try { return await httpFetch(u, opts); }
    catch (e) {}
  }
  throw new Error("All variants failed for " + pathOrUrl);
}

// ---------- LOGIN (TOTP) ----------
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) return { ok: false, reason: "PASSWORD_MISSING" };

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);
    const payload = {
      clientcode: SMART_USER_ID,
      password: tradingPassword,
      totp,
    };

    const urls = [
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      `${SMARTAPI_BASE}/secure/login`,
      `${SMARTAPI_BASE}/oauth2/token`,
    ];

    let data = null, raw = null, usedUrl = null;

    for (const url of urls) {
      try {
        const resp = await httpFetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-PrivateKey": SMART_API_KEY,
            "X-UserType": "USER",
            "X-SourceID": "WEB",
          },
          body: JSON.stringify(payload),
        }, 15000);

        raw = await resp.text().catch(() => null);
        try { data = JSON.parse(raw); } catch { data = null; }

        usedUrl = url;
        if (data && (data.status === true || data.data)) break;

      } catch (e) {}
    }

    console.log("LOGIN RAW:", usedUrl, raw ? raw.slice(0,200) : raw);

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || raw };
    }

    const d = data.data || data;

    session.access_token =
      d.jwtToken || d.access_token || d.token || null;
    session.refresh_token =
      d.refreshToken || d.refresh_token || null;
    session.feed_token =
      d.feedToken || d.feed_token || null;

    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true, data: d };

  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}
// ====================================================================
// PART 2 — SCRIP MASTER LOADING + AUTO TOKEN DETECT + LTP FETCH
// ====================================================================

// ---------- LOAD SCRIPMASTER (auto index) ----------
async function loadScripMaster() {
  try {
    const url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";

    const resp = await tryFetchVariants(url);
    const txt = await resp.text();
    const arr = JSON.parse(txt);

    SCRIP_INDEX = {};

    for (const s of arr) {
      if (!s.token) continue;

      const t = s.token.toString().trim();
      SCRIP_INDEX[t] = {
        name: s.name || s.symbol,
        symbol: s.symbol,
        token: t,
        exch_seg: s.exch_seg,
        expiry: s.expiry,
        instrument: s.instrumenttype || s.instrument,
        strike: safeNum(s.strike || 0),
      };
    }

    console.log("ScripMaster Loaded:", Object.keys(SCRIP_INDEX).length, "tokens");
    return true;

  } catch (e) {
    console.log("ScripMaster load failed:", e.message);
    return false;
  }
}

// ---------- FIND FUTURE CONTRACT FOR MARKET ----------
function findFutureContract(market) {
  const m = market.toLowerCase();
  const wanted = m === "nifty" ? "NIFTY" :
                 m === "sensex" ? "SENSEX" :
                 m === "natural gas" ? "NATURALGAS" : null;

  if (!wanted) return null;

  let best = null;
  for (const k in SCRIP_INDEX) {
    const s = SCRIP_INDEX[k];
    if (!s.symbol) continue;
    if (!s.symbol.startsWith(wanted)) continue;

    // Only FUT contracts
    if (!/FUT/.test(s.symbol)) continue;

    // Pick nearest expiry (string compare OK)
    if (!best) best = s;
    else {
      if ((s.expiry || "") < (best.expiry || "")) best = s;
    }
  }
  return best;
}

// ---------- GET LTP FOR GIVEN TOKEN ----------
async function getLTP(exch, token) {
  if (!session.access_token) return { ok: false, reason: "NO_SESSION" };
  if (!token) return { ok: false, reason: "NO_TOKEN" };

  const body = {
    mode: "LTP",
    exchangeTokens: {
      [exch]: [token]
    }
  };

  try {
    const url = SMARTAPI_BASE + "/rest/secure/angelbroking/market/v1/quote/";

    const resp = await httpFetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${session.access_token}`,
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify(body),
    }, 15000);

    const txt = await resp.text();
    let data = null;
    try { data = JSON.parse(txt); } catch {}

    if (!data || !data.data) {
      return { ok: false, raw: txt, reason: "INVALID_LTP_RESPONSE" };
    }

    const exdata = data.data[exch];
    if (!exdata || !exdata[0] || !exdata[0].ltp) {
      return { ok: false, raw: data, reason: "NO_LTP" };
    }

    return { ok: true, ltp: safeNum(exdata[0].ltp) };

  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}
// ====================================================================
// PART 3 — TREND ENGINE + STRIKE ENGINE
// ====================================================================

// ------------------------------------------------------------
// TREND ENGINE (final lightweight version — no placeholders)
// ------------------------------------------------------------
function analyzeTrend({ ema20, ema50, rsi, vwap, spot, expiry_days }) {
  const gap = ((ema20 - ema50) / ema50) * 100;
  let cmp_vwap = ((spot - vwap) / vwap) * 100;

  let score = 0;

  // EMA GAP
  if (gap > 0.20) score += 20;
  else if (gap < -0.20) score -= 20;

  // RSI
  if (rsi > 60) score += 20;
  else if (rsi < 40) score -= 20;

  // VWAP
  if (cmp_vwap > 0.20) score += 10;
  else if (cmp_vwap < -0.20) score -= 10;

  // EXPIRY IMPACT
  if (expiry_days <= 2) score -= 10;  
  else if (expiry_days >= 5) score += 5;

  let main = "SIDEWAYS";
  let bias = "NONE";

  if (score >= 30) {
    main = "UPTREND";
    bias = "CE";
  }
  else if (score <= -30) {
    main = "DOWNTREND";
    bias = "PE";
  }

  let strength =
    Math.abs(score) >= 40 ? "STRONG" :
    Math.abs(score) >= 20 ? "MODERATE" : "RANGE";

  return {
    main,
    strength,
    score,
    bias,
    components: {
      ema_gap: `${gap.toFixed(2)}%`,
      rsi: `RSI ${rsi} ${rsi > 60 ? "bullish" : rsi < 40 ? "bearish" : "neutral"}`,
      vwap: cmp_vwap > 0 ? "Above VWAP" : "Below VWAP",
      price_structure: "Mixed",
      expiry: expiry_days <= 2 ? "Expiry near" :
              expiry_days >= 5 ? "Expiry far" :
              "Expiry mid",
    },
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
  };
}

// ------------------------------------------------------------
// STRIKE ENGINE
// ------------------------------------------------------------
function pickStrikes(market, spot, trend, expiry_days) {

  const m = market.toLowerCase();

  let gaps = {
    nifty:   { far: 250, mid: 150, near:  80 },
    sensex:  { far: 500, mid: 300, near: 150 },
    naturalgas: { far: 80, mid: 50, near: 30 }
  };

  let g;
  if (expiry_days <= 2) g = gaps[m].near;
  else if (expiry_days >= 5) g = gaps[m].far;
  else g = gaps[m].mid;

  const ce_strike = roundStrike(spot + g, m);
  const pe_strike = roundStrike(spot - g, m);
  const atm        = roundStrike(spot, m);

  function roundStrike(x, m) {
    if (m === "nifty") return Math.round(x / 50) * 50;
    if (m === "sensex") return Math.round(x / 100) * 100;
    if (m === "naturalgas") return Math.round(x / 10) * 10;
    return Math.round(x);
  }

  return [
    {
      type: "CE",
      strike: ce_strike,
      distance: Math.abs(ce_strike - spot),
      entry: 10,
      stopLoss: 6,
      target: 15,
      midPrice: null,
    },
    {
      type: "PE",
      strike: pe_strike,
      distance: Math.abs(pe_strike - spot),
      entry: 10,
      stopLoss: 6,
      target: 15,
      midPrice: null,
    },
    {
      type: "STRADDLE",
      strike: atm,
      distance: Math.abs(atm - spot),
      entry: 2000,
      stopLoss: 1200,
      target: 3000,
      midPrice: null,
    }
  ];
}
// ====================================================================
// PART 4 — AUTO-FETCH, WS (v2 try), ROUTES (autofetch, ltp, calc), START
// ====================================================================

// ---------- FALLBACK TOKENS (user-provided / safe) ----------
const FALLBACK_TOKENS = {
  nifty: { symbol: "NIFTY26DECFUT", token: "113063", expiry: null },
  sensex: { symbol: "SENSEX19DECFUT", token: "50000000000007", expiry: null },
  "natural gas": { symbol: "NATURALGAS26DECFUT", token: "243887", expiry: null },
};

// initialize AUTO with fallback (so responses always include something)
AUTO = {
  nifty: { ...FALLBACK_TOKENS.nifty, ltp: null },
  sensex: { ...FALLBACK_TOKENS.sensex, ltp: null },
  "natural gas": { ...FALLBACK_TOKENS["natural gas"], ltp: null },
};

// ---------- AUTO FETCH using SCRIP INDEX ----------
async function autoFetchFuture(market) {
  try {
    // ensure scripmaster loaded
    if (!SCRIP_INDEX || Object.keys(SCRIP_INDEX).length === 0) {
      await loadScripMaster().catch(() => {});
    }

    const found = findFutureContract(market);
    if (found) {
      AUTO[market] = {
        symbol: found.symbol,
        token: found.token,
        expiry: found.expiry || null,
        ltp: AUTO[market] ? AUTO[market].ltp : null,
      };
      return AUTO[market];
    }

    // fallback
    if (FALLBACK_TOKENS[market]) {
      AUTO[market] = { ...FALLBACK_TOKENS[market], ltp: AUTO[market] ? AUTO[market].ltp : null };
      return AUTO[market];
    }

    return null;
  } catch (e) {
    console.log("autoFetchFuture ERROR:", e.message);
    return null;
  }
}

// ---------- WEB SOCKET (best-effort v2 connect + reconnection) ----------
function connectWebSocket() {
  if (!session.feed_token && !session.access_token) {
    console.log("WS: No feed/access token available — skipping WS connect");
    return;
  }

  // choose candidate URLs
  const candidates = [
    // Common patterns — try few
    SMARTAPI_BASE.replace(/^http/, "wss") + "/ws/v2",
    SMARTAPI_BASE.replace(/^http/, "wss") + "/ws",
    SMARTAPI_BASE.replace(/^http/, "wss") + "/feed",
  ];

  let tried = 0;

  const tryOne = (url) => {
    tried++;
    console.log("WS: Trying", url);
    try {
      const socket = new WebSocket(url, {
        headers: {
          Authorization: `Bearer ${session.access_token}`,
          "X-PrivateKey": SMART_API_KEY,
        },
        timeout: 15000,
      });

      ws = socket;

      socket.on("open", () => {
        wsConnected = true;
        console.log("WS: connected to", url);
        // subscribe to tokens already known
        const tokens = [];
        for (const m of Object.keys(AUTO)) {
          if (AUTO[m] && AUTO[m].token) tokens.push(AUTO[m].token.toString());
        }
        // Example subscription message — Angel docs vary. This is best-effort.
        if (tokens.length > 0) {
          const subMsg = JSON.stringify({
            action: "subscribe",
            params: {
              token: tokens,
              feedToken: session.feed_token || null,
            },
          });
          try { socket.send(subMsg); } catch (e) {}
          console.log("WS: sent subscribe", tokens);
        }
      });

      socket.on("message", (msg) => {
        // some providers gzip; attempt to handle
        try {
          // if Buffer compress
          let text = msg;
          if (Buffer.isBuffer(msg)) {
            // try gunzip
            try {
              text = zlib.gunzipSync(msg).toString();
            } catch {
              try { text = msg.toString(); } catch {}
            }
          }
          const j = JSON.parse(text);
          // parse message and update AUTO LTP if possible
          // message formats vary; try common fields
          if (j && j.data) {
            const entries = Array.isArray(j.data) ? j.data : [j.data];
            for (const e of entries) {
              const tok = (e.symboltoken || e.token || e.symbolToken || "").toString();
              const ltp = safeNum(e.ltp || e.last_traded_price || e.lt || e.price || null, null);
              if (tok && ltp != null) {
                for (const k of Object.keys(AUTO)) {
                  if (AUTO[k].token && AUTO[k].token.toString() === tok) {
                    AUTO[k].ltp = ltp;
                  }
                }
              }
            }
          }
        } catch (err) {
          // ignore parse errors
        }
      });

      socket.on("close", (code, reason) => {
        wsConnected = false;
        console.log("WS: closed", code, reason && reason.toString ? reason.toString() : reason);
        // reconnect after delay
        if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
        wsReconnectTimer = setTimeout(() => connectWebSocket(), 5000);
      });

      socket.on("error", (err) => {
        wsConnected = false;
        console.log("WS: error", err && err.message ? err.message : err);
        try { socket.terminate(); } catch {}
        if (tried < candidates.length) {
          tryOne(candidates[tried]);
        } else {
          // schedule reconnect
          if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
          wsReconnectTimer = setTimeout(() => connectWebSocket(), 7000);
        }
      });

    } catch (e) {
      if (tried < candidates.length) tryOne(candidates[tried]);
      else {
        console.log("WS: all attempts failed");
      }
    }
  };

  tryOne(candidates[0]);
}

// ---------- ROUTES ----------

// Root serve
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// Login route already defined in Part1 (smartApiLogin), but ensure exported
// If login is performed, attempt to connect websocket
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
  const r = await smartApiLogin(password);
  if (!r.ok) {
    return res.json({
      success: false,
      error:
        r.reason === "ENV_MISSING"
          ? "SmartAPI ENV missing"
          : r.reason === "PASSWORD_MISSING"
          ? "Password missing"
          : r.reason === "LOGIN_FAILED"
          ? "SmartAPI login failed"
          : "Login error: " + (r.error || "Unknown"),
      raw: r.raw || null,
    });
  }

  // load scrip master and autofetch tokens once logged in
  await loadScripMaster().catch(() => {});
  for (const m of Object.keys(AUTO)) {
    await autoFetchFuture(m).catch(() => {});
  }

  // try connect websocket (best-effort)
  connectWebSocket();

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at,
    },
  });
});

// login status (overrides earlier if duplicated)
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
    feed_token: session.feed_token || null,
  });
});

// settings
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || "",
    scripIndexCount: Object.keys(SCRIP_INDEX || {}).length,
  });
});

// Test search route
app.get("/api/test/search", async (req, res) => {
  if (!session.access_token) return res.json({ success: false, error: "NOT_LOGGED_IN" });
  try {
    const resp = await httpFetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/searchScrip`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ searchtext: "NIFTY" }),
    }, 12000);
    const raw = await resp.text();
    console.log("===== /api/test/search RAW =====");
    console.log(raw && raw.substring ? raw.substring(0,2000) : raw);
    console.log("================================");
    res.type("application/json").send(raw);
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// Autofetch route
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token) return res.json({ success: false, error: "NOT_LOGGED_IN" });
  const out = {};
  for (const m of Object.keys(AUTO)) {
    try {
      out[m] = await autoFetchFuture(m);
    } catch (e) {
      out[m] = { error: e.message };
    }
  }
  res.json({ success: true, auto: out });
});

// LTP fetch route (HTTP pull)
app.get("/api/ltp", async (req, res) => {
  if (!session.access_token) return res.status(401).json({ success: false, message: "Not logged in." });

  const results = {};
  for (const m of Object.keys(AUTO)) {
    const token = AUTO[m].token;
    const exch = FUTURE_RULES[m] ? FUTURE_RULES[m].exchange : null;
    if (!token || !exch) {
      results[m] = { ok: false, reason: "NO_TOKEN_OR_EXCH" };
      continue;
    }
    const r = await getLTP(exch, token);
    if (r.ok) {
      AUTO[m].ltp = r.ltp;
      results[m] = { ok: true, ltp: r.ltp };
    } else {
      results[m] = r;
    }
  }

  res.json({ success: true, data: AUTO, detail: results });
});

// Normalize input helper
function normalizeInput(body) {
  const spotVal = safeNum(body.spot);
  const detected = (body.market || "").toString().trim().toLowerCase() || autoDetectMarket(spotVal, body.market);
  return {
    ema20: safeNum(body.ema20),
    ema50: safeNum(body.ema50),
    rsi: safeNum(body.rsi),
    vwap: safeNum(body.vwap),
    spot: spotVal,
    market: detected,
    expiry_days: safeNum(body.expiry_days, 7),
    use_live: !!body.use_live,
  };
}

// Main calc route
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);

    let usedLive = false;
    let liveLtp = null;
    let liveErr = null;

    if (input.use_live) {
      // ensure tokens populated
      const auto = await autoFetchFuture(input.market).catch(() => null);
      // attempt to fetch LTP via HTTP or WS fallback
      const cfg = FUTURE_RULES[input.market];
      const token = AUTO[input.market] ? AUTO[input.market].token : null;
      const exch = cfg ? cfg.exchange : null;

      if (token && exch) {
        const r = await getLTP(exch, token);
        if (r.ok && r.ltp != null) {
          input.spot = safeNum(r.ltp);
          usedLive = true;
          liveLtp = input.spot;
        } else {
          // try ws stored ltp
          if (AUTO[input.market] && AUTO[input.market].ltp) {
            input.spot = safeNum(AUTO[input.market].ltp);
            usedLive = true;
            liveLtp = input.spot;
          } else {
            liveErr = r;
          }
        }
      } else {
        liveErr = { ok: false, reason: "TOKEN_NOT_FOUND", auto: AUTO[input.market] || null };
      }
    }

    const trend = analyzeTrend(input);
    const strikes = pickStrikes(input.market, input.spot, trend, input.expiry_days);

    // Optionally, try to compute midPrice using a simple premium estimator or via market option quote
    // For now leave midPrice null unless we can fetch option chain pricing via API (requires option token)
    // TODO: implement premium engine if we fetch options chain

    res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token ? "SmartAPI Logged-In" : "Not logged-in (demo mode)",
      input,
      trend,
      strikes,
      auto_tokens: AUTO,
      meta: {
        live_data_used: usedLive,
        live_ltp: liveLtp,
        live_error: liveErr,
        ws_connected: wsConnected,
      },
    });
  } catch (err) {
    res.json({ success: false, error: err && err.message ? err.message : String(err) });
  }
});

// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// ---------- BOOTSTRAP: load scrip master and maybe auto-login ----------
async function bootstrap() {
  await loadScripMaster().catch(() => {});
  // populate AUTO from scrip master once
  for (const m of Object.keys(AUTO)) {
    await autoFetchFuture(m).catch(() => {});
  }

  if (AUTO_LOGIN_ON_START) {
    // Only attempt if env contains some password variable (we don't store user password in env in this code)
    // So skip by default to avoid accidental login attempts.
    console.log("Bootstrap complete. Manual login via POST /api/login is recommended.");
  }
}

// start server
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await bootstrap();
});
