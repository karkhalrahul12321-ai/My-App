// ================================
// server.js  — FINAL (PART 1/4)
// Trading Helper Backend — FULL VERSION
// Includes: SmartAPI login (TOTP), auto tokens, LTP HTTP, basic routes
// ================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const WebSocket = require("ws"); // used in WS manager (PART 2)
require("dotenv").config();

// -------------------- App init --------------------
const app = express();
app.use(bodyParser.json());

// Serve frontend (assumes frontend folder one level up)
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  // show user-friendly message on root if they hit /
  res.sendFile(path.join(frontendPath, "index.html"));
});

// -------------------- SmartAPI config (env) --------------------
const SMARTAPI_BASE =
  (process.env.SMARTAPI_BASE && process.env.SMARTAPI_BASE.replace(/\/$/, "")) ||
  "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMARTAPI_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || ""; // optional

// -------------------- Session storage --------------------
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  clientCode: SMART_USER_ID || null,
};

// -------------------- Helpers: base32 decode + TOTP --------------------
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const output = [];

  if (!input) return Buffer.from([]);
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
  // write big-endian
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

// -------------------- SmartAPI login --------------------
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
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: totp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);
    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // ~20 hours
    session.clientCode = SMART_USER_ID;

    // if feed_token present, ensure WS manager can use it
    try {
      wsManager && wsManager.updateAuth(session.feed_token, session.clientCode);
    } catch (e) {}

    return { ok: true };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// -------------------- Login routes --------------------
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

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at,
    },
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
  });
});

app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? "SET" : "",
    base: SMARTAPI_BASE,
  });
});

// -------------------- Small generic helpers --------------------
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

// -------------------- FUTURE rules, FALLBACK tokens, AUTO --------------------
const FUTURE_RULES = {
  nifty: { searchSymbol: "NIFTY", exchange: "NFO", instrumentType: "FUTIDX", expiryDay: 4 },
  sensex: { searchSymbol: "SENSEX", exchange: "BFO", instrumentType: "FUTIDX", expiryDay: 4 },
  "natural gas": { searchSymbol: "NATURALGAS", exchange: "MCX", instrumentType: "FUTCOM", expiryDay: null },
};

function fmtDate(d) {
  return `${d.getFullYear()}-${(d.getMonth() + 1).toString().padStart(2, "0")}-${d.getDate().toString().padStart(2, "0")}`;
}

function getNextExpiries(market) {
  const rule = FUTURE_RULES[market];
  const today = new Date();
  const expiries = [];
  if (!rule) return expiries;
  if (market === "natural gas") {
    for (let i = 0; i < 3; i++) {
      const dt = new Date(today.getFullYear(), today.getMonth() + i, 25);
      expiries.push(fmtDate(dt));
    }
  } else {
    for (let i = 0; i < 4; i++) {
      const dt = new Date();
      dt.setDate(today.getDate() + i * 7);
      while (dt.getDay() !== rule.expiryDay) dt.setDate(dt.getDate() + 1);
      expiries.push(fmtDate(dt));
    }
  }
  return expiries;
}

// FALLBACK tokens (fill with values you trust)
const FALLBACK_TOKENS = {
  nifty: { symbol: "NIFTY30DEC25FUT", token: "36688", expiry: "2025-12-30" },
  sensex: { symbol: "SENSEX50DEC25FUT", token: "1104398", expiry: "2025-12-24" },
  "natural gas": { symbol: "NATURALGAS26DEC25FUT", token: "463007", expiry: "2025-12-26" },
};

const AUTO = {
  nifty: { ...FALLBACK_TOKENS.nifty },
  sensex: { ...FALLBACK_TOKENS.sensex },
  "natural gas": { ...FALLBACK_TOKENS["natural gas"] },
};

// -------------------- smartSearch helper (uses logged-in session) --------------------
async function smartSearch(keyword) {
  if (!session.access_token) return [];
  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/searchScrip`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.access_token}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ searchtext: keyword }),
      }
    );
    const text = await resp.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch (e) {
      console.log("SEARCH JSON PARSE ERROR:", e.message);
      return [];
    }
    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    console.log("SMART SEARCH ERROR:", err.message);
    return [];
  }
}

// -------------------- autoFetchFuture (uses smartSearch, fallback if needed) --------------------
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const expiries = getNextExpiries(market);
  if (!expiries.length) {
    AUTO[market] = { ...FALLBACK_TOKENS[market] };
    return AUTO[market];
  }

  const all = await smartSearch(rule.searchSymbol);
  if (!all.length) {
    AUTO[market] = { ...FALLBACK_TOKENS[market] };
    return AUTO[market];
  }

  for (const exp of expiries) {
    const [y, m, d] = exp.split("-");
    const match = all.find((x) => {
      const sameExchange = (x.exch_seg || "").toUpperCase() === rule.exchange.toUpperCase();
      const sameType = (x.instrumenttype || "").toUpperCase() === rule.instrumentType.toUpperCase();
      const expStr = typeof x.expirydate === "string" ? x.expirydate : "";
      const sameExpiry = expStr.includes(`${y}-${m}-${d}`);
      return sameExchange && sameType && sameExpiry;
    });

    if (match) {
      AUTO[market] = { symbol: match.tradingsymbol, token: match.symboltoken, expiry: match.expirydate };
      console.log("autoFetchFuture: FOUND for", market, AUTO[market]);
      return AUTO[market];
    }
  }

  AUTO[market] = { ...FALLBACK_TOKENS[market] };
  return AUTO[market];
}

// manual trigger
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token) return res.json({ success: false, error: "NOT_LOGGED_IN" });
  const result = {};
  for (const m of Object.keys(FUTURE_RULES)) {
    const r = await autoFetchFuture(m);
    result[m] = r || AUTO[m];
  }
  res.json({ success: true, auto: result });
});

// debug raw search
app.get("/api/test/search", async (req, res) => {
  if (!session.access_token) return res.json({ success: false, error: "NOT_LOGGED_IN" });
  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/searchScrip`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "X-PrivateKey": SMART_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ searchtext: "NIFTY" }),
    });
    const raw = await resp.text();
    res.type("application/json").send(raw);
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// ============ END PART 1 ============
// (continue with PART 2)
// ================================
// server.js  — FINAL (PART 2/4)
// WebSocket manager + HTTP LTP fetch + LTP cache
// ================================

// -------------------- WS Manager (single shared client) --------------------
let wsManager = null;

class WSManager {
  constructor() {
    this.ws = null;
    this.feedToken = null;
    this.clientCode = null;
    this.apiKey = SMART_API_KEY;
    this.urlBase = (SMARTAPI_BASE && SMARTAPI_BASE.includes("api")) ? SMARTAPI_BASE.replace("/rest", "") : "wss://smartapisocket.angelone.in";
    this.reconnectDelay = 2000;
    this.connected = false;
    this.lastHeartbeat = 0;
    this.ltpCache = {}; // token -> last LTP
    this.subscribedTokens = new Set();
    this._reconnectTimer = null;
  }

  buildWsUrl() {
    // browser-style query params: clientCode & feedToken & apiKey
    const q = `?clientCode=${encodeURIComponent(this.clientCode || "")}&feedToken=${encodeURIComponent(this.feedToken || "")}&apiKey=${encodeURIComponent(this.apiKey || "")}`;
    return `${this.urlBase.replace(/^http/, "ws")}/smart-stream${q}`;
  }

  updateAuth(feedToken, clientCode) {
    const changed = this.feedToken !== feedToken || this.clientCode !== clientCode;
    this.feedToken = feedToken;
    this.clientCode = clientCode;
    if (changed) {
      this.connect(true);
    }
  }

  connect(force = false) {
    if (this.ws && !force) return;
    if (!this.feedToken || !this.clientCode || !this.apiKey) {
      console.log("WSManager: auth incomplete, not connecting");
      return;
    }

    try {
      if (this.ws) {
        try { this.ws.terminate(); } catch (e) {}
        this.ws = null;
      }

      const url = this.buildWsUrl();
      console.log("WSManager connecting to", url);
      this.ws = new WebSocket(url);

      this.ws.on("open", () => {
        console.log("WS open");
        this.connected = true;
        this.lastHeartbeat = Date.now();
        // (re)subscribe tokens if any
        if (this.subscribedTokens.size) this.subscribe([...this.subscribedTokens]);
      });

      this.ws.on("message", (msg) => {
        // SmartAPI messages may be JSON or binary; try parse
        try {
          const parsed = JSON.parse(msg.toString());
          this._handleMessage(parsed);
        } catch (e) {
          // not JSON — ignore or log
        }
      });

      this.ws.on("error", (err) => {
        console.log("WS error:", err && err.message);
      });

      this.ws.on("close", (code, reason) => {
        console.log("WS closed", code, reason && reason.toString());
        this.connected = false;
        // schedule reconnect
        if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
        this._reconnectTimer = setTimeout(() => this.connect(true), this.reconnectDelay);
      });
    } catch (e) {
      console.log("WSManager connect exception:", e.message);
    }
  }

  subscribe(tokens = []) {
    tokens.forEach((t) => this.subscribedTokens.add(String(t)));
    if (!this.connected || !this.ws) return;
    // SmartAPI subscription format for browser may be like: { "type":"subscribe","tokens":[...]}
    const payload = { type: "subscribe", tokens: Array.from(new Set(tokens.map(String))) };
    try { this.ws.send(JSON.stringify(payload)); } catch (e) {}
  }

  unsubscribe(tokens = []) {
    tokens.forEach((t) => this.subscribedTokens.delete(String(t)));
    if (!this.connected || !this.ws) return;
    const payload = { type: "unsubscribe", tokens: tokens.map(String) };
    try { this.ws.send(JSON.stringify(payload)); } catch (e) {}
  }

  _handleMessage(parsed) {
    // Expecting payload with token/ltp; adapt to provider format.
    // Typical: { "token":"36688", "ltp": 26000, ... } or nested payloads
    try {
      if (!parsed) return;
      // handle heartbeat or auth error messages
      if (parsed.type === "heartbeat") {
        this.lastHeartbeat = Date.now();
        return;
      }
      // payload may have 'data' or 'payload' arrays
      if (parsed.data && Array.isArray(parsed.data)) {
        parsed.data.forEach((it) => this._processTick(it));
      } else if (parsed.payload && Array.isArray(parsed.payload)) {
        parsed.payload.forEach((it) => this._processTick(it));
      } else {
        // fallback single object
        this._processTick(parsed);
      }
    } catch (e) {
      console.log("WS _handleMessage error:", e && e.message);
    }
  }

  _processTick(item) {
    // Standardize: try to find token and ltp
    const token = item.symboltoken || item.token || item.symbol || item.instrumentToken;
    const ltp = (item.ltp || item.last_traded_price || item.lastPrice || item.lp || null);
    if (token && ltp != null) {
      this.ltpCache[String(token)] = Number(ltp);
    }
  }

  getLTPForToken(token) {
    return this.ltpCache[String(token)] || null;
  }
}

// instantiate global manager
wsManager = new WSManager();

// Immediately attempt connect if feed token available
if (session.feed_token && session.clientCode) {
  wsManager.updateAuth(session.feed_token, session.clientCode);
  wsManager.connect();
}

// -------------------- LTP via HTTP (market/v1/quote) — used as fallback --------------------
async function fetchLTPViaHTTPForToken(exchange, tokenList = []) {
  if (!session.access_token) {
    return { ok: false, reason: "NOT_LOGGED_IN" };
  }
  const body = { mode: "FULL", exchangeTokens: {} };
  body.exchangeTokens[exchange] = tokenList.map((t) => String(t));
  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "X-PrivateKey": SMART_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) { return { ok: false, reason: "JSON_PARSE", raw: text }; }
    // parse ltp value
    const items = data && data.data && data.data.fetched ? data.data.fetched : (Array.isArray(data.data) ? data.data : null);
    if (!items || !items.length) return { ok: false, reason: "NO_DATA", raw: data };
    const out = {};
    items.forEach((it) => {
      const t = it.symboltoken || it.token || it.symbol;
      const l = it.ltp || it.last_traded_price || it.lastPrice || null;
      if (t && l != null) {
        out[String(t)] = Number(l);
      }
    });
    return { ok: true, ltp: out, raw: data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// -------------------- Helper to get future LTP (prefers WS cache, falls back to HTTP) --------------------
async function getAutoFutureLTP_cached(market) {
  const cfgExchange = { nifty: "NFO", sensex: "BFO", "natural gas": "MCX" }[market];
  let auto = AUTO[market];
  if (!auto || !auto.token) {
    auto = await autoFetchFuture(market);
    if (!auto || !auto.token) return { ok: false, reason: "TOKEN_NOT_FOUND" };
  }

  // try WS cache first
  if (wsManager) {
    const wsLtp = wsManager.getLTPForToken(auto.token);
    if (wsLtp != null) {
      return { ok: true, ltp: wsLtp, source: "ws" };
    }
  }

  // fall back to HTTP
  const r = await fetchLTPViaHTTPForToken(cfgExchange || "NFO", [auto.token]);
  if (r.ok && r.ltp && r.ltp[auto.token]) {
    return { ok: true, ltp: r.ltp[auto.token], source: "http", raw: r.raw };
  }

  return { ok: false, reason: "NO_LTP_FOUND", detail: r };
}

// -------------------- LTP debug route --------------------
app.get("/api/ltp/test", async (req, res) => {
  const market = (req.query.market || "nifty").toLowerCase();
  const r = await getAutoFutureLTP_cached(market);
  res.json({ success: r.ok, result: r, auto_tokens: AUTO, market });
});

// ============ END PART 2 ============
// (continue with PART 3)
// ================================
// server.js  — FINAL (PART 3/4)
// Trend engine, strike builder, option-chain & greeks endpoints (HTTP premium fallback)
// ================================

// -------------------- Market config --------------------
const MARKET_CONFIG = {
  nifty: { name: "Nifty", strikeStep: 50, baseDistances: { far: 250, mid: 200, near: 150 }, exchange: "NFO" },
  sensex: { name: "Sensex", strikeStep: 100, baseDistances: { far: 500, mid: 400, near: 300 }, exchange: "BFO" },
  "natural gas": { name: "Natural Gas", strikeStep: 5, baseDistances: { far: 80, mid: 60, near: 50 }, exchange: "MCX" },
};

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
    use_live: !!body.use_live,
  };
}

// -------------------- Trend engine --------------------
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
    return { main: "SIDEWAYS", strength: "NEUTRAL", score: 50, bias: "NONE", components: comp, comment: "Data incomplete, default sideways." };
  }

  const emaMid = (ema20 + ema50) / 2;
  const emaDiff = ema20 - ema50;
  const emaPct = (emaDiff / Math.max(1, emaMid)) * 100;
  const emaScore = clamp(emaPct * 1.5, -25, 25);

  comp.ema_gap = emaPct > 0.3 ? `Bullish (${emaPct.toFixed(2)}%)` : emaPct < -0.3 ? `Bearish (${emaPct.toFixed(2)}%)` : `Flat (${emaPct.toFixed(2)}%)`;

  let rsiScore = clamp((rsi - 50) * 1.2, -25, 25);
  if (rsi >= 70) comp.rsi = `RSI ${rsi} (overbought)`;
  else if (rsi >= 60) comp.rsi = `RSI ${rsi} (bullish)`;
  else if (rsi <= 30) comp.rsi = `RSI ${rsi} (oversold)`;
  else if (rsi <= 40) comp.rsi = `RSI ${rsi} (bearish)`;
  else comp.rsi = `RSI ${rsi} (neutral)`;

  const vwapDiff = spot - vwap;
  const vwapPct = (vwapDiff / Math.max(1, vwap)) * 100;
  const vwapScore = clamp(vwapPct * 1.5, -20, 20);
  comp.vwap = vwapPct > 0.1 ? `Price above VWAP (${vwapPct.toFixed(2)}%)` : vwapPct < -0.1 ? `Below VWAP (${vwapPct.toFixed(2)}%)` : `Near VWAP (${vwapPct.toFixed(2)}%)`;

  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) { structScore = 10; comp.price_structure = "Clean bullish"; }
  else if (spot < ema20 && ema20 < ema50) { structScore = -10; comp.price_structure = "Clean bearish"; }
  else comp.price_structure = "Mixed structure";

  const d = num(input.expiry_days, 7);
  let expiryAdj = 0;
  if (d <= 2) { expiryAdj = -5; comp.expiry = "Expiry near (volatile)"; }
  else if (d >= 10) { expiryAdj = 3; comp.expiry = "Expiry far (stable)"; }
  else comp.expiry = "Expiry mid";

  score = 50 + emaScore * 0.4 + rsiScore * 0.3 + vwapScore * 0.2 + structScore * 0.2 + expiryAdj;
  score = clamp(score, 0, 100);

  let main = "SIDEWAYS", strength = "RANGE";
  if (score >= 80) { main = "UPTREND"; strength = "STRONG"; bias = "CE"; }
  else if (score >= 60) { main = "UPTREND"; strength = "MODERATE"; bias = "CE"; }
  else if (score <= 20) { main = "DOWNTREND"; strength = "STRONG"; bias = "PE"; }
  else if (score <= 40) { main = "DOWNTREND"; strength = "MODERATE"; bias = "PE"; }

  const comment = `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`;
  return { main, strength, score, bias, components: comp, comment };
}

// -------------------- Strike engine --------------------
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
  const cfg = MARKET_CONFIG[input.market] || MARKET_CONFIG.nifty;
  const { spot, expiry_days } = input;
  const scaled = scaleDistancesByExpiry(expiry_days, cfg.baseDistances, cfg.strikeStep);
  const atm = roundToStep(spot, cfg.strikeStep);

  let ceDist, peDist;
  if (trend.main === "UPTREND") { ceDist = scaled.near; peDist = scaled.far; }
  else if (trend.main === "DOWNTREND") { ceDist = scaled.far; peDist = scaled.near; }
  else { ceDist = scaled.mid; peDist = scaled.mid; }

  const ceStrike = roundToStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDist, cfg.strikeStep);
  const straddleStrike = atm;

  function makeOption(strike, type, diff) {
    const steps = Math.max(1, Math.round(Math.abs(diff) / cfg.strikeStep));
    const base = Math.max(5, steps * 5);
    return { type, strike, distance: Math.abs(diff), entry: base, stopLoss: Math.round(base * 0.6), target: Math.round(base * 1.5) };
  }

  return [
    makeOption(ceStrike, "CE", ceStrike - spot),
    makeOption(peStrike, "PE", peStrike - spot),
    makeOption(straddleStrike, "STRADDLE", straddleStrike - spot),
  ];
}

// -------------------- Option Greeks endpoint (HTTP) --------------------
async function fetchOptionGreeks(symbolName, expiryDate) {
  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };
  try {
    const body = { name: symbolName, expirydate: expiryDate };
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/marketData/v1/optionGreek`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "X-PrivateKey": SMART_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) { return { ok: false, reason: "JSON_PARSE", raw: text }; }
    return { ok: true, data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

app.post("/api/greeks", async (req, res) => {
  // expects { name: "TCS", expirydate: "25JAN2024" } or similar
  const body = req.body || {};
  if (!body.name || !body.expirydate) return res.json({ success: false, error: "name and expirydate required" });
  const r = await fetchOptionGreeks(body.name, body.expirydate);
  if (!r.ok) return res.json({ success: false, error: r.reason || r.error || "Failed" , raw: r.raw || null });
  res.json({ success: true, data: r.data });
});

// -------------------- Full market quote / option-chain endpoint (premium engine) --------------------
async function fetchFullMarketQuote(exchangeTokensObj) {
  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };
  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "X-PrivateKey": SMART_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "FULL", exchangeTokens: exchangeTokensObj }),
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) { return { ok: false, reason: "JSON_PARSE", raw: text }; }
    return { ok: true, data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// Example endpoint to fetch option-chain for a given instrument tokens list
app.post("/api/quote/full", async (req, res) => {
  // expects body: { exchangeTokens: { "NFO": ["36688","..."], "MCX": ["..."] } }
  const body = req.body || {};
  if (!body.exchangeTokens) return res.json({ success: false, error: "exchangeTokens required" });
  const r = await fetchFullMarketQuote(body.exchangeTokens);
  if (!r.ok) return res.json({ success: false, error: r.reason || r.error, raw: r.raw || null });
  res.json({ success: true, data: r.data });
});

// -------------------- Main /api/calc endpoint (uses computeTrend + buildStrikes + optional live LTP) --------------------
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body || {});
    let usedLive = false, liveLtp = null, liveErr = null;

    if (input.use_live) {
      const r = await getAutoFutureLTP_cached(input.market);
      if (r.ok && r.ltp != null) {
        input.spot = num(r.ltp);
        usedLive = true;
        liveLtp = input.spot;
      } else {
        liveErr = r;
      }
    }

    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token ? "SmartAPI Logged-In" : "Not logged-in (demo mode)",
      input,
      trend,
      strikes,
      auto_tokens: AUTO,
      meta: { live_data_used: usedLive, live_ltp: liveLtp, live_error: liveErr },
    });
  } catch (err) {
    res.json({ success: false, error: err.message || String(err) });
  }
});

// ============ END PART 3 ============
// (continue PART 4)
// ================================
// server.js  — FINAL (PART 4/4)
// WS subscription endpoints, health, static fallback, server start
// ================================

// -------------------- Expose endpoints to control WS subscriptions --------------------
app.post("/api/ws/subscribe", (req, res) => {
  // body: { tokens: ["36688","..."] }
  const tokens = (req.body && Array.isArray(req.body.tokens) ? req.body.tokens.map(String) : []);
  if (!tokens.length) return res.json({ success: false, error: "tokens required" });
  if (!wsManager) wsManager = new WSManager();
  wsManager.subscribe(tokens);
  res.json({ success: true, subscribed: tokens });
});

app.post("/api/ws/unsubscribe", (req, res) => {
  const tokens = (req.body && Array.isArray(req.body.tokens) ? req.body.tokens.map(String) : []);
  if (!tokens.length) return res.json({ success: false, error: "tokens required" });
  if (!wsManager) return res.json({ success: false, error: "ws not running" });
  wsManager.unsubscribe(tokens);
  res.json({ success: true, unsubscribed: tokens });
});

app.get("/api/ws/status", (req, res) => {
  res.json({
    success: true,
    connected: !!(wsManager && wsManager.connected),
    feed_token: session.feed_token || null,
    clientCode: session.clientCode || null,
    subscribed: wsManager ? Array.from(wsManager.subscribedTokens) : [],
  });
});

// -------------------- Provide direct LTP by market (for frontend) --------------------
app.get("/api/ltp/market", async (req, res) => {
  const market = (req.query.market || "nifty").toLowerCase();
  // ensure auto tokens present
  let auto = AUTO[market];
  if (!auto || !auto.token) auto = await autoFetchFuture(market);
  if (!auto || !auto.token) return res.json({ success: false, error: "token not found" });

  // first check WS cache
  const wsVal = wsManager ? wsManager.getLTPForToken(auto.token) : null;
  if (wsVal != null) return res.json({ success: true, ltp: wsVal, source: "ws" });

  // fallback to HTTP
  const r = await fetchLTPViaHTTPForToken(MARKET_CONFIG[market].exchange, [auto.token]);
  if (r.ok && r.ltp && r.ltp[auto.token]) return res.json({ success: true, ltp: r.ltp[auto.token], source: "http" });

  res.json({ success: false, error: "LTP not available", detail: r });
});

// -------------------- Ping / health endpoint --------------------
app.get("/api/ping", (req, res) => {
  res.json({ success: true, server: "ok", time: Date.now(), logged_in: !!session.access_token });
});

// -------------------- SPA fallback for frontend routes --------------------
app.get("*", (req, res) => {
  // For root "/" the frontend is already handled above; this fallback ensures SPA routes work when deployed.
  res.sendFile(path.join(frontendPath, "index.html"));
});

// -------------------- Start server --------------------
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER running on port " + PORT);
  // ensure wsManager exists and tries to connect after start
  if (!wsManager) wsManager = new WSManager();
  if (session.feed_token && session.clientCode) {
    wsManager.updateAuth(session.feed_token, session.clientCode);
    wsManager.connect();
  }
});
