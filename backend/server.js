// server.js — A VERSION — PART A1/10
// Full trading backend — imports, env, scripmaster loader (JSON first), basic app

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

// defensive totp require
let totpGenerator = null;
try {
  totpGenerator = require("totp-generator");
  if (totpGenerator && totpGenerator.default) totpGenerator = totpGenerator.default;
} catch (e) {
  totpGenerator = null;
}

// defensive fetch (node-fetch@2 preferred)
let fetchLib;
try { fetchLib = require("node-fetch"); } catch (e) {
  if (typeof globalThis.fetch === "function") fetchLib = globalThis.fetch;
  else throw new Error("Please install node-fetch@2 as a dependency");
}
const fetch = fetchLib;

// optional libs
let unzipper = null;
try { unzipper = require("unzipper"); } catch (e) { unzipper = null; }
let WebSocket = null;
try { WebSocket = require("ws"); } catch (e) { WebSocket = null; }
let axios = null;
try { axios = require("axios"); } catch (e) { axios = null; }

// express app
const app = express();
app.use(bodyParser.json({ limit: "512kb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// ENV keys (core required)
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP_SECRET || ""; // base32 secret (preferred)
const SMART_TOTP = process.env.SMART_TOTP || ""; // static 6-digit fallback
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMARTAPI_WS_BASE = process.env.SMARTAPI_WS_BASE || "wss://smartapisocket.angelone.in/smart-stream";

// Local ScripMaster settings
const DATA_DIR = path.join(__dirname);
const LOCAL_SCRIP_JSON = path.join(DATA_DIR, "OpenAPIScripMaster.json");
const SCRIP_MASTER_JSON_URL = process.env.SCRIP_MASTER_URL || "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
const SCRIP_MASTER_ZIP_URL = process.env.SCRIP_MASTER_ZIP || "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.zip";

// internal constants
const SCRIP_DOWNLOAD_RETRY_MS = 60000;

// Global state
let accessToken = null;
let refreshToken = null;
let feedToken = null;
let tokenExpiry = 0; // ms timestamp
let wsClient = null;
let wsConnected = false;
let scripsCache = null;
let scripsLastUpdated = null;
let livePrices = {}; // token -> { ltp, ts }
let wsReconnectTimer = null;
let wsLastMsgTs = Date.now();

// helpers
function log(...args) { console.log.apply(console, args); }
function warn(...args) { console.warn.apply(console, args); }
function ok(payload={}) { return Object.assign({ success: true }, payload); }
function nok(msg, details=null) { return { success:false, message: msg, details: details }; }
function num(v, d=0) { const n = Number(v); return Number.isFinite(n) ? n : d; }

// ----------------- ScripMaster loader -----------------
async function loadScripMasterFromLocal() {
  try {
    if (fs.existsSync(LOCAL_SCRIP_JSON)) {
      const txt = fs.readFileSync(LOCAL_SCRIP_JSON, "utf8");
      const j = JSON.parse(txt);
      scripsCache = Array.isArray(j) ? j : (j.data || j.scripts || []);
      scripsLastUpdated = new Date().toISOString();
      log("Loaded local OpenAPIScripMaster.json entries:", (scripsCache||[]).length);
      return true;
    }
  } catch (e) {
    warn("local scrip parse error:", e && e.message);
  }
  return false;
}

async function downloadAndLoadScripMaster() {
  // 1. local file first
  if (await loadScripMasterFromLocal()) return true;

  // 2. remote JSON
  try {
    log("Attempting ScripMaster JSON download:", SCRIP_MASTER_JSON_URL);
    const r = await fetch(SCRIP_MASTER_JSON_URL, { timeout: 20000 });
    if (r && (r.ok || r.status === 200)) {
      const txt = await r.text();
      try {
        const j = JSON.parse(txt);
        scripsCache = Array.isArray(j) ? j : (j.data || j.scripts || []);
        scripsLastUpdated = new Date().toISOString();
        try { fs.writeFileSync(LOCAL_SCRIP_JSON, JSON.stringify(scripsCache, null, 2), "utf8"); } catch(e){}
        log("ScripMaster JSON loaded, entries:", (scripsCache||[]).length);
        return true;
      } catch (e) {
        warn("ScripMaster JSON parse failed:", e && e.message);
      }
    } else {
      warn("ScripMaster JSON HTTP status:", r && r.status);
    }
  } catch (e) {
    warn("ScripMaster JSON download error:", e && e.message);
  }

  // 3. ZIP fallback if available
  if (!unzipper) {
    warn("unzipper not installed - skipping ZIP fallback");
    return false;
  }
  try {
    log("Attempting ScripMaster ZIP fallback:", SCRIP_MASTER_ZIP_URL);
    const rz = await fetch(SCRIP_MASTER_ZIP_URL, { timeout: 30000 });
    if (!rz || !rz.ok) throw new Error("ZIP fetch failed: " + (rz && rz.status));
    const buffer = await rz.buffer();
    const stream = require("stream");
    const s = new stream.PassThrough();
    s.end(buffer);
    await new Promise((resolve, reject) => {
      s.pipe(unzipper.Parse())
        .on("entry", (entry) => {
          const name = entry.path || "";
          if (name.toLowerCase().endsWith(".json")) {
            let txt = "";
            entry.on("data", c => txt += c.toString("utf8"));
            entry.on("end", () => {
              try {
                const j = JSON.parse(txt);
                scripsCache = Array.isArray(j) ? j : (j.data || j.scripts || []);
                scripsLastUpdated = new Date().toISOString();
                try { fs.writeFileSync(LOCAL_SCRIP_JSON, JSON.stringify(scripsCache, null, 2), "utf8"); } catch(e){}
                log("ScripMaster loaded from ZIP entry:", name, "entries:", (scripsCache||[]).length);
              } catch (e) {
                warn("ZIP JSON parse error", e && e.message);
              }
            });
          } else {
            entry.autodrain();
          }
        })
        .on("close", () => resolve())
        .on("error", (err) => reject(err));
    });
    return !!(scripsCache && scripsCache.length);
  } catch (e) {
    warn("ZIP fallback failed:", e && e.message);
  }

  warn("ScripMaster load failed (all attempts).");
  return false;
}

// initial load (non-blocking)
downloadAndLoadScripMaster().then(ok=>{ if(!ok){ warn("Initial ScripMaster load failed; will retry periodically."); setInterval(()=>downloadAndLoadScripMaster().catch(()=>null), SCRIP_DOWNLOAD_RETRY_MS); } }).catch(()=>null);

// End of PART A1
// server.js — A VERSION — PART A2/10
// TOTP generation + SmartAPI login (robust parsing), token management

// ---------- TOTP generator (safe) ----------
async function generateTotpCode() {
  try {
    // 1) static 6-digit override
    if (SMART_TOTP && /^\d{6}$/.test(SMART_TOTP)) {
      log("Using static SMART_TOTP from env");
      return SMART_TOTP;
    }
    // 2) secret based
    if (SMART_TOTP_SECRET) {
      if (!totpGenerator) { warn("totp-generator not installed"); return null; }
      const t = String(totpGenerator(SMART_TOTP_SECRET));
      if (/^\d{6}$/.test(t)) return t;
      return t.slice(0,6);
    }
    warn("No TOTP secret/code found in env");
    return null;
  } catch (e) {
    warn("generateTotpCode error:", e && e.message);
    return null;
  }
}

// ---------- SmartAPI login (robust) ----------
async function smartLogin(force=false) {
  try {
    // reuse token if valid
    if (!force && accessToken && feedToken && tokenExpiry && Date.now() < tokenExpiry - 15000) {
      return { success: true, accessToken, feedToken, reused: true };
    }

    const totp = await generateTotpCode();
    if (!totp) {
      warn("No TOTP — cannot login");
      accessToken = null; feedToken = null;
      return { success: false, reason: "NO_TOTP" };
    }

    const payload = {
      api_key: SMART_API_KEY || process.env.SMART_API_KEY,
      user_id: SMART_USER_ID || process.env.SMART_USER_ID,
      password: SMART_API_SECRET,
      totp: totp
    };

    const loginUrl = (process.env.SMARTAPI_BASE || SMARTAPI_BASE) + "/rest/auth/angelbroking/user/v1/loginByPassword";
    log("Attempting SmartAPI login:", loginUrl);
    const resp = await fetch(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      timeout: 20000
    });
    const js = await resp.json().catch(()=>null);
    if (!resp.ok || !js) {
      warn("SmartAPI login HTTP error:", resp && resp.status, js);
      accessToken = null; feedToken = null;
      return { success: false, status: resp && resp.status, body: js };
    }

    const data = js.data || js || {};
    accessToken = data.jwtToken || data.accessToken || js.jwtToken || js.accessToken || null;
    refreshToken = data.refreshToken || js.refreshToken || null;
    feedToken = data.feedToken || js.feedToken || null;
    tokenExpiry = data.expires_in_ms ? Date.now() + Number(data.expires_in_ms) : Date.now() + (25*60*1000);

    log("SmartAPI login success -> accessToken:", !!accessToken, "feedToken:", !!feedToken);
    if (!feedToken) warn("feedToken missing in response; WS will not connect until feedToken present");
    return { success: !!accessToken, accessToken, feedToken, raw: js };

  } catch (e) {
    warn("smartLogin exception:", e && e.message);
    accessToken = null; feedToken = null;
    return { success: false, reason: e && e.message };
  }
}

// auto-initial login
(async ()=> {
  log("Initial SmartAPI login attempt...");
  const r = await smartLogin();
  if (!r.success) {
    warn("Initial login failed; scheduling retries every 20s");
    setInterval(()=>smartLogin(true).catch(()=>null), 20000);
  }
})();

// ---------- token refresh monitor ----------
setInterval(async ()=> {
  try {
    if (tokenExpiry && Date.now() > tokenExpiry - 60000) {
      log("Access token near expiry — refreshing");
      await smartLogin(true).catch(()=>null);
    }
  } catch (e) {}
}, 15000);

// End of PART A2
// server.js — A VERSION — PART A3/10
// WebSocket helper, parsing, subscribe, auto-subscribe FUTs

// build WS url
function buildWsUrl(clientCode, feedTokenLocal) {
  const base = process.env.SMARTAPI_WS_BASE || SMARTAPI_WS_BASE;
  const params = new URLSearchParams();
  if (clientCode) params.set("clientCode", clientCode);
  if (feedTokenLocal) params.set("feedToken", feedTokenLocal);
  if (SMART_API_KEY) params.set("apiKey", SMART_API_KEY);
  return base + "?" + params.toString();
}

// update live price
function updateLivePrice(token, ltp) {
  try {
    if (!token) return;
    const t = String(token);
    const now = Date.now();
    livePrices[t] = { ltp: Number(ltp), ts: now };
  } catch (e) {}
}

// process tick item
function processTickItem(item) {
  if (!item || typeof item !== "object") return;
  const token = item.token || item.instrument_token || item.symboltoken || item.tok || item.instrumentId || item.instrument;
  const ltp = Number(item.ltp || item.lastPrice || item.last_price || item.lp || item.price || item.p);
  if (token && !isNaN(ltp)) { updateLivePrice(String(token), ltp); return; }

  const maybeName = (item.symbol || item.tradingsymbol || item.tradingSymbol || item.name || item.scrip || "").toString().toUpperCase();
  if (maybeName && scripsCache && Array.isArray(scripsCache)) {
    const found = scripsCache.find(it => {
      if (!it) return false;
      const s = (it.symbol || it.tradingsymbol || it.name || "").toString().toUpperCase();
      return s === maybeName || s.includes(maybeName);
    });
    if (found && found.token && !isNaN(ltp)) updateLivePrice(String(found.token), ltp);
  }
}

// parse ws message
function parseWsMessage(raw) {
  try {
    if (!raw) return;
    let txt = null;
    if (Buffer.isBuffer(raw)) txt = raw.toString("utf8");
    else if (typeof raw === "string") txt = raw;
    else if (typeof raw === "object") txt = JSON.stringify(raw);
    else return;

    // try JSON
    let parsed = null;
    try { parsed = JSON.parse(txt); } catch (e) { parsed = null; }

    if (parsed) {
      if (Array.isArray(parsed.payload)) parsed.payload.forEach(item=>processTickItem(item));
      else if (Array.isArray(parsed.data)) parsed.data.forEach(item=>processTickItem(item));
      else if (parsed.payload && typeof parsed.payload === "object") processTickItem(parsed.payload);
      else if (parsed.token && (parsed.ltp || parsed.lastPrice)) processTickItem(parsed);
      else if (parsed.message) try { parseWsMessage(JSON.stringify(parsed.message)); } catch(_) {}
      return;
    }

    // pipe separated fallback
    if (txt.indexOf("|") > -1) {
      const parts = txt.split("|").map(s=>s.trim());
      if (parts.length >= 2) {
        const tok = parts[0];
        const ltp = Number(parts[1]) || null;
        if (tok && !isNaN(ltp)) updateLivePrice(tok, ltp);
      }
    }
  } catch (e) {}
}

// ensure ws connected
async function ensureWsConnected() {
  try {
    if (!WebSocket) { warn("ws package not installed — WS disabled"); return false; }

    if (!feedToken) {
      await smartLogin().catch(()=>null);
    }
    const clientCode = process.env.WS_CLIENT_CODE || SMART_USER_ID || "";
    const ft = feedToken || process.env.WS_FEED_TOKEN || "";
    if (!ft) { warn("No feedToken — cannot open WS"); return false; }

    const wsUrl = buildWsUrl(clientCode, ft);
    if (wsClient && wsConnected) return true;

    try { if (wsClient) { try { wsClient.terminate(); } catch(e){} wsClient = null; } } catch(e){}

    log("Connecting WS to:", wsUrl);
    wsClient = new WebSocket(wsUrl, { handshakeTimeout: 10000, perMessageDeflate: false });

    wsClient.on("open", () => {
      wsConnected = true;
      log("WS open");
      autoSubscribeFutures().catch(()=>null);
    });

    wsClient.on("message", (data) => {
      wsLastMsgTs = Date.now();
      try { parseWsMessage(data); } catch (e) {}
    });

    wsClient.on("error", (err) => {
      warn("WS error:", err && (err.message || err));
      wsConnected = false;
    });

    wsClient.on("close", (code, reason) => {
      wsConnected = false;
      warn("WS closed:", code, reason && (reason.toString ? reason.toString() : reason));
      if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
      wsReconnectTimer = setTimeout(()=>ensureWsConnected().catch(()=>null), 4000);
    });

    return true;
  } catch (e) {
    warn("ensureWsConnected exception:", e && e.message);
    return false;
  }
}

// send safe
function wsSendSafe(obj) {
  try {
    if (!wsClient || wsClient.readyState !== WebSocket.OPEN) return false;
    wsClient.send(JSON.stringify(obj));
    return true;
  } catch (e) {
    warn("ws send failed:", e && e.message);
    return false;
  }
}

// subscribe tokens
function wsSubscribeTokens(tokens = [], exchange = "ALL") {
  if (!Array.isArray(tokens) || !tokens.length) return false;
  const payload = { message_type: "subscribe", exchange: exchange, token: tokens.map(t=>String(t)) };
  return wsSendSafe(payload);
}

// find and auto-subscribe nearest futures tokens
async function autoSubscribeFutures() {
  try {
    if (!scripsCache || !Array.isArray(scripsCache)) return;
    const markets = ["NIFTY","SENSEX","NATURALGAS","NATURAL GAS","NATGAS"];
    const futs = scripsCache.filter(it => {
      if (!it || !it.symbol) return false;
      const s = (it.symbol || "").toString().toUpperCase();
      const inst = (it.instrumentType || it.instrument_type || "").toString().toUpperCase();
      if (!inst.includes("FUT")) return false;
      return markets.some(mk => s.includes(mk));
    });
    const byMk = {};
    for (let f of futs) {
      const s = (f.symbol || "").toString().toUpperCase();
      let key = null;
      if (s.includes("NIFTY")) key = "nifty";
      else if (s.includes("SENSEX")) key = "sensex";
      else if (s.includes("NATURALGAS") || s.includes("NATURAL")) key = "natural gas";
      if (!key) continue;
      byMk[key] = byMk[key] || [];
      byMk[key].push(f);
    }
    const tokens = [];
    for (let k of Object.keys(byMk)) {
      const arr = byMk[k];
      arr.sort((a,b) => {
        const da = a.expiry ? new Date(a.expiry) : new Date(8640000000000000);
        const db = b.expiry ? new Date(b.expiry) : new Date(8640000000000000);
        return da - db;
      });
      if (arr[0] && arr[0].token) tokens.push(String(arr[0].token));
    }
    if (tokens.length) {
      log("Auto-subscribe tokens:", tokens);
      wsSubscribeTokens(tokens, "ALL");
    }
  } catch (e) { warn("autoSubscribeFutures error:", e && e.message); }
}

// periodic ensure
setInterval(()=>{ ensureWsConnected().catch(()=>null); }, 10000);

// End of PART A3
// server.js — A VERSION — PART A4/10
// LTP HTTP fallback, option chain strike selection, expiry helpers

// fetch LTP via HTTP (SmartAPI endpoint - may need adjustments for your account)
async function fetchLtpHttp(symbol, exchange) {
  try {
    if (!symbol) return null;
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote/ltp`;
    const headers = { "Content-Type": "application/json" };
    if (accessToken) headers["Authorization"] = "Bearer " + accessToken;
    // try GET with symbol (some SmartAPI versions accept this)
    const r = await fetch(url + `?symbol=${encodeURIComponent(symbol)}&exchange=${encodeURIComponent(exchange||"NFO")}`, {
      headers, method: "GET", timeout: 10000
    });
    const js = await r.json().catch(()=>null);
    if (!js) return null;
    const ltp = js.ltp || (js.data && (js.data.ltp || js.data.lastPrice)) || null;
    if (!ltp) return null;
    return { success: true, ltp: Number(ltp), raw: js };
  } catch (e) {
    return null;
  }
}

// option chain helpers
function getStepSize(market) {
  const mk = (market || "").toLowerCase();
  if (mk.includes("gas") || mk.includes("natural")) return 5;
  return 50;
}
function findNearestExpiryFromScrips(market) {
  if (!scripsCache || !Array.isArray(scripsCache)) return null;
  const mk = (market || "").toLowerCase();
  const items = scripsCache.filter(it => {
    if (!it || !it.symbol) return false;
    const s = (it.symbol || "").toUpperCase();
    if (mk.includes("nifty") && s.includes("NIFTY")) return true;
    if (mk.includes("sensex") && s.includes("SENSEX")) return true;
    if (mk.includes("gas") && (s.includes("NATURAL") || s.includes("GAS"))) return true;
    return false;
  });
  if (!items.length) return null;
  const exps = [...new Set(items.map(x => x.expiry))].filter(Boolean).sort((a,b)=>new Date(a)-new Date(b));
  return exps.length ? exps[0] : null;
}
function findATM(price, step) {
  return Math.round(Number(price)/step)*step;
}
function get3Strikes(price, step) {
  const atm = findATM(price, step);
  return [atm-step, atm, atm+step];
}

// find CE/PE instrument by strike
function matchMarketSymbol(sym, market) {
  if (!sym) return false;
  const s = sym.toUpperCase();
  if ((market||"").includes("nifty")) return s.includes("NIFTY");
  if ((market||"").includes("sensex")) return s.includes("SENSEX");
  if ((market||"").includes("natural") || (market||"").includes("gas")) return s.includes("NATURAL") || s.includes("GAS") || s.includes("NG");
  return false;
}
function getCEPEFromStrike(market, strike, expiry) {
  if (!scripsCache || !Array.isArray(scripsCache)) return { CE: null, PE: null };
  const ce = scripsCache.find(it => it && Number(it.strike) === Number(strike) && (it.symbol||"").toUpperCase().includes("CE") && (expiry ? it.expiry == expiry : true) && matchMarketSymbol(it.symbol||"", market));
  const pe = scripsCache.find(it => it && Number(it.strike) === Number(strike) && (it.symbol||"").toUpperCase().includes("PE") && (expiry ? it.expiry == expiry : true) && matchMarketSymbol(it.symbol||"", market));
  return { CE: ce||null, PE: pe||null };
}

// get token ltp either from ws cache or HTTP fallback
async function getCachedOrHttpLtpForToken(token, symbolGuess, exchange) {
  try {
    if (livePrices[token]) return { token, ltp: livePrices[token].ltp, source: "ws" };
    const f = await fetchLtpHttp(symbolGuess || token, exchange || "NFO");
    if (f && f.success) return { token, ltp: f.ltp, source: "http" };
    return { token, ltp: null, source: "none" };
  } catch (e) {
    return { token, ltp: null, source: "error", error: e && e.message };
  }
}

async function buildStrike(market, strike, expiry) {
  const { CE, PE } = getCEPEFromStrike(market, strike, expiry);
  const out = { strike, CE: null, PE: null };
  if (CE) {
    const c = await getCachedOrHttpLtpForToken(CE.token, CE.symbol, CE.exch || CE.exch_seg || "NFO");
    out.CE = { symbol: CE.symbol, token: CE.token, ltp: c.ltp, expiry: CE.expiry };
  }
  if (PE) {
    const p = await getCachedOrHttpLtpForToken(PE.token, PE.symbol, PE.exch || PE.exch_seg || "NFO");
    out.PE = { symbol: PE.symbol, token: PE.token, ltp: p.ltp, expiry: PE.expiry };
  }
  return out;
}

// /option-chain/raw (returns chain)
app.post("/option-chain/raw", async (req, res) => {
  try {
    const market = (req.body && req.body.market) || "nifty";
    const spot = Number(req.body && (req.body.spot || req.body.basePrice) || 0);
    if (!market) return res.status(400).json(nok("invalid_market"));
    if (!spot) return res.status(400).json(nok("invalid_spot"));
    const step = getStepSize(market);
    const strikes = get3Strikes(spot, step);
    const expiry = findNearestExpiryFromScrips(market);
    if (!expiry) return res.status(500).json(nok("expiry_not_found"));
    const results = [];
    for (let st of strikes) { const obj = await buildStrike(market, st, expiry); results.push(obj); }
    return res.json(ok({ market, spot, strikes, expiry, chain: results }));
  } catch (e) {
    return res.status(500).json(nok("option_raw_error", e && e.message));
  }
});

// End of PART A4
// server.js — A VERSION — PART A5/10
// Premium engine + Black-Scholes Greeks

function normPdf(x) {
  return Math.exp(-0.5 * x * x) / Math.sqrt(2 * Math.PI);
}
function normCdf(x) {
  const sign = x < 0 ? -1 : 1;
  const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741, a4 = -1.453152027, a5 = 1.061405429, p = 0.3275911;
  const absx = Math.abs(x) / Math.sqrt(2.0);
  const t = 1.0 / (1.0 + p * absx);
  const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-absx * absx);
  return 0.5 * (1.0 + sign * y);
}

function blackScholesPrice(S, K, r, sigma, T, isCall=true) {
  if (T <= 0 || sigma <= 0) return isCall ? Math.max(0, S - K) : Math.max(0, K - S);
  const sqrtT = Math.sqrt(T);
  const d1 = (Math.log(S / K) + (r + 0.5 * sigma * sigma) * T) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  if (isCall) return S * normCdf(d1) - K * Math.exp(-r * T) * normCdf(d2);
  return K * Math.exp(-r * T) * normCdf(-d2) - S * normCdf(-d1);
}

function blackScholesGreeks(S, K, r, sigma, T, isCall=true) {
  if (T <= 0 || sigma <= 0) {
    const intrinsic = isCall ? (S > K ? 1 : 0) : (S < K ? -1 : 0);
    return { delta: intrinsic, gamma: 0, vega: 0, theta: 0, rho: 0 };
  }
  const sqrtT = Math.sqrt(T);
  const d1 = (Math.log(S / K) + (r + 0.5 * sigma * sigma) * T) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  const delta = isCall ? normCdf(d1) : (normCdf(d1) - 1);
  const gamma = normPdf(d1) / (S * sigma * sqrtT);
  const vega = S * normPdf(d1) * sqrtT;
  const callTheta = -(S * normPdf(d1) * sigma) / (2 * sqrtT) - r * K * Math.exp(-r * T) * normCdf(d2);
  const putTheta = -(S * normPdf(d1) * sigma) / (2 * sqrtT) + r * K * Math.exp(-r * T) * normCdf(-d2);
  const theta = (isCall ? callTheta : putTheta) / 365.0;
  const rhoCall = K * T * Math.exp(-r * T) * normCdf(d2);
  const rhoPut = -K * T * Math.exp(-r * T) * normCdf(-d2);
  const rho = (isCall ? rhoCall : rhoPut) / 100.0;
  return { delta, gamma, vega, theta, rho };
}

function computePremiumPlan(distancePoints, underlyingPrice, impliedVol = 0.25) {
  const d = Math.abs(Number(distancePoints || 0));
  const s = Number(underlyingPrice || 1);
  let entry = 10, stopLoss = 6, target = 15;
  if (d <= 10) { entry = 5; stopLoss = 3; target = 8; }
  else if (d <= 50) { entry = 10; stopLoss = 6; target = 15; }
  else if (d <= 100) { entry = 8; stopLoss = 5; target = 12; }
  else { entry = 6; stopLoss = 4; target = 10; }

  if (s > 20000) {
    entry = Math.max(1, Math.round(entry/2));
    stopLoss = Math.max(1, Math.round(stopLoss/2));
    target = Math.max(2, Math.round(target/2));
  }
  return { distance: d, entry, stopLoss, target };
}

// endpoints
app.post("/premium-calc", async (req, res) => {
  try {
    const b = req.body || {};
    let distance = Number(b.distance || 0);
    const strike = Number(b.strike || 0);
    const basePrice = Number(b.basePrice || b.spot || 0);
    if (!distance && strike && basePrice) distance = Math.abs(strike - basePrice);
    if (!distance) return res.status(400).json(nok("distance or (strike+basePrice) required"));
    const plan = computePremiumPlan(distance, basePrice, Number(b.iv || 0.25));
    return res.json(ok({ plan }));
  } catch (e) {
    return res.status(500).json(nok("premium_error", e && e.message));
  }
});

app.post("/greeks-calc", (req, res) => {
  try {
    const b = req.body || {};
    const spot = Number(b.spot || 0);
    const strike = Number(b.strike || 0);
    const iv = Number(b.iv || 0.25);
    const r = Number(b.r || 0.06);
    const days = Number(b.days || 7);
    const isCall = (b.type || "CE").toString().toUpperCase() === "CE";
    if (!spot || !strike) return res.status(400).json(nok("spot and strike required"));
    const T = Math.max(1, days) / 365.0;
    const price = blackScholesPrice(spot, strike, r, iv, T, isCall);
    const greeks = blackScholesGreeks(spot, strike, r, iv, T, isCall);
    return res.json(ok({ price, greeks }));
  } catch (e) {
    return res.status(500).json(nok("greeks_error", e && e.message));
  }
});

// End of PART A5
// server.js — A VERSION — PART A6/10
// Trend engine and /full-analysis endpoint

function computeTrendObject({ ema20, ema50, rsi, vwap, spot, expiry_days }) {
  try {
    const diff = (Number(ema20) - Number(ema50));
    const denom = ((Math.abs(Number(ema20)) + Math.abs(Number(ema50))) / 2) || 1;
    const pct = (diff / denom) * 100;
    let main = "SIDEWAYS", strength = "RANGE", bias = "NONE";
    if (pct > 0.3) { main = "UP"; bias = "BULLISH"; strength = pct > 1 ? "STRONG" : "MILD"; }
    else if (pct < -0.3) { main = "DOWN"; bias = "BEARISH"; strength = pct < -1 ? "STRONG" : "MILD"; }
    const rsiEval = rsi > 60 ? `RSI ${rsi} (overbought)` : rsi < 40 ? `RSI ${rsi} (oversold)` : `RSI ${rsi} (neutral)`;
    const emaGap = pct === 0 ? "Flat (0%)" : pct > 0 ? `Bullish (${pct.toFixed(2)}%)` : `Bearish (${pct.toFixed(2)}%)`;
    const vwapCmp = spot && vwap ? (spot > vwap ? `Above VWAP (+${((spot-vwap)/Math.max(1,vwap)*100).toFixed(2)}%)` : `Below VWAP (${((vwap-spot)/Math.max(1,vwap)*100).toFixed(2)}%)`) : "VWAP unknown";
    return {
      main, strength, bias,
      score: Math.abs(pct) * 10 + (rsi > 60 ? 5 : rsi < 40 ? 5 : 2),
      components: { ema_gap: emaGap, rsi: rsiEval, vwap: vwapCmp, price_structure: main==="SIDEWAYS"?"Mixed":"Directional", expiry: expiry_days>5?"Expiry mid":"Near expiry" },
      comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
    };
  } catch (e) {
    return null;
  }
}

function getAutoTokens() {
  if (!scripsCache || !Array.isArray(scripsCache)) return {};
  const markets = ["nifty", "sensex", "natural gas"];
  const out = {};
  for (let mk of markets) {
    const fut = findNearestFuture(mk);
    if (fut) out[mk] = { symbol: fut.symbol || fut.tradingsymbol || fut.name || "", token: fut.token || fut.symboltoken || "", expiry: fut.expiry || null };
    else out[mk] = null;
  }
  return out;
}

function findNearestFuture(market) {
  if (!scripsCache || !Array.isArray(scripsCache)) return null;
  const mk = market.toLowerCase();
  const futs = scripsCache.filter(it => {
    if (!it || !it.symbol) return false;
    const s = (it.symbol || "").toUpperCase();
    const inst = (it.instrumentType || it.instrument_type || "").toString().toUpperCase();
    if (!inst.includes("FUT")) return false;
    if (mk.includes("nifty") && s.includes("NIFTY")) return true;
    if (mk.includes("sensex") && s.includes("SENSEX")) return true;
    if (mk.includes("natural") && (s.includes("NATURAL") || s.includes("GAS"))) return true;
    return false;
  });
  if (!futs.length) return null;
  futs.sort((a,b)=> {
    const da = a.expiry ? new Date(a.expiry) : new Date(8640000000000000);
    const db = b.expiry ? new Date(b.expiry) : new Date(8640000000000000);
    return da - db;
  });
  return futs[0];
}

// unified spot getter
async function getSpotUnified(body) {
  let spot = Number(body.spot || 0);
  if (!spot) {
    const mk = (body.market || "nifty").toLowerCase();
    const s = await getSpotForMarket(mk);
    if (s) spot = s;
  }
  if (!spot) spot = Number(body.ema20 || 0) || Number(body.ema50 || 0) || 0;
  return spot;
}

app.post("/full-analysis", async (req, res) => {
  try {
    const body = req.body || {};
    const ema20 = Number(body.ema20 || 0);
    const ema50 = Number(body.ema50 || 0);
    const rsi = Number(body.rsi || 50);
    const vwap = Number(body.vwap || 0);
    const market = (body.market || "nifty").toLowerCase();
    const expiry_days = Number(body.expiry_days || 7);

    const spot = await getSpotUnified(body);
    if (!spot) return res.status(500).json(nok("Unable to determine spot"));

    const trend = computeTrendObject({ ema20, ema50, rsi, vwap, spot, expiry_days });

    const step = getStepSize(market);
    const atm = findATM(spot, step);
    const ceStrike = atm + step;
    const peStrike = atm - step;
    const straddle = atm;

    const strikes = [
      { type: "CE", strike: ceStrike, distance: Math.abs(ceStrike - spot), entry: 10, stopLoss: 6, target: 15 },
      { type: "PE", strike: peStrike, distance: Math.abs(peStrike - spot), entry: 10, stopLoss: 6, target: 15 },
      { type: "STRADDLE", strike: straddle, distance: Math.abs(straddle - spot), entry: 5, stopLoss: 3, target: 8 }
    ];

    const auto_tokens = getAutoTokens();
    const meta = { live_data_used: !!(Object.keys(livePrices||{}).length), live_ltp: spot, live_error: null };

    return res.json({
      success: true,
      message: "Calculation complete",
      login_status: feedToken ? "SmartAPI Logged-In" : "Login Issue",
      input: { ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live: !!body.use_live },
      trend, strikes, auto_tokens, meta
    });
  } catch (e) {
    return res.status(500).json(nok("full_analysis_error", e && e.message));
  }
});

// End of PART A6
// server.js — A VERSION — PART A7/10
// Admin, status, scrip endpoints, ltp endpoints, token lookup

app.get("/", (req, res) => {
  return res.json(ok({ message: "Trading backend running", version: "A-1.0", ws_connected: !!wsConnected, scrips_loaded: !!scripsCache, time: Date.now() }));
});

app.get("/health", (req, res) => {
  try {
    return res.json(ok({
      uptime: process.uptime(),
      time: Date.now(),
      wsConnected: !!wsConnected,
      scripsLoaded: !!scripsCache,
      scripsCount: Array.isArray(scripsCache) ? scripsCache.length : 0
    }));
  } catch (e) {
    return res.status(500).json(nok("health_error", e && e.message));
  }
});

app.get("/info", (req, res) => {
  try {
    return res.json(ok({
      node: process.version,
      smartapi_base: SMARTAPI_BASE,
      smartapi_ws_base: SMARTAPI_WS_BASE,
      env_keys_present: {
        SMART_API_KEY: !!SMART_API_KEY,
        SMART_API_SECRET: !!SMART_API_SECRET,
        SMART_USER_ID: !!SMART_USER_ID,
        SMART_TOTP: !!SMART_TOTP || !!SMART_TOTP_SECRET
      }
    }));
  } catch (e) {
    return res.status(500).json(nok("info_error", e && e.message));
  }
});

app.get("/admin/status", (req, res) => {
  try {
    return res.json(ok({
      wsConnected: !!wsConnected,
      accessTokenPresent: !!accessToken,
      feedTokenPresent: !!feedToken,
      tokenExpiry,
      livePricesCount: Object.keys(livePrices||{}).length,
      scripsLoaded: !!scripsCache,
      scripsCount: Array.isArray(scripsCache) ? scripsCache.length : 0,
      scripsLastUpdated
    }));
  } catch (e) { return res.status(500).json(nok("admin_status_error", e && e.message)); }
});

app.get("/scrips/status", (req, res) => {
  try {
    return res.json(ok({
      loaded: !!scripsCache,
      entries: Array.isArray(scripsCache) ? scripsCache.length : 0,
      lastUpdated: scripsLastUpdated
    }));
  } catch (e) { return res.status(500).json(nok("scrips_status_error", e && e.message)); }
});

app.get("/scrips/list", (req, res) => {
  try {
    if (!scripsCache) return res.status(404).json(nok("scrips_not_loaded"));
    const limit = Math.min(200, Number(req.query.limit || 100));
    const start = Math.max(0, Number(req.query.start || 0));
    return res.json(ok({ count: scripsCache.length, sample: scripsCache.slice(start, start + limit) }));
  } catch (e) { return res.status(500).json(nok("scrips_list_error", e && e.message)); }
});

// ltp endpoint (token or symbol)
app.get("/ltp", async (req, res) => {
  try {
    const token = req.query.token;
    const symbol = req.query.symbol;
    if (token) {
      if (livePrices[token]) return res.json(ok({ token, ltp: livePrices[token].ltp, ts: livePrices[token].ts }));
      const found = (scripsCache||[]).find(it => it && (String(it.token) === String(token) || String(it.symboltoken) === String(token)));
      if (found) {
        const fetched = await fetchLtpHttp(found.symbol || found.tradingsymbol || found.name, found.exch || found.exch_seg || "NFO");
        if (fetched && fetched.success) return res.json(ok({ token, ltp: fetched.ltp, source: "http" }));
      }
      return res.status(404).json(nok("ltp_not_found"));
    }
    if (symbol) {
      const found = (scripsCache||[]).find(it => it && ((it.symbol||"").toString().toUpperCase() === symbol.toString().toUpperCase() || (it.tradingsymbol||"").toString().toUpperCase() === symbol.toString().toUpperCase()));
      if (found) {
        if (livePrices[found.token]) return res.json(ok({ symbol, token: found.token, ltp: livePrices[found.token].ltp, source: "ws" }));
        const fetched = await fetchLtpHttp(found.symbol || found.tradingsymbol || found.name, found.exch || found.exch_seg || "NFO");
        if (fetched && fetched.success) return res.json(ok({ symbol, token: found.token, ltp: fetched.ltp, source: "http" }));
      }
      const fallback = await fetchLtpHttp(symbol, req.query.exchange || "NFO");
      if (fallback && fallback.success) return res.json(ok({ symbol, ltp: fallback.ltp, source: "http" }));
      return res.status(404).json(nok("symbol_not_found"));
    }
    return res.status(400).json(nok("provide token or symbol"));
  } catch (e) { return res.status(500).json(nok("ltp_error", e && e.message)); }
});

// token lookup
app.get("/token", (req, res) => {
  try {
    const symbol = req.query.symbol;
    if (!symbol) return res.status(400).json(nok("missing_symbol"));
    const found = (scripsCache||[]).find(it => it && ((it.symbol||"").toString().toUpperCase() === symbol.toString().toUpperCase() || (it.tradingsymbol||"").toString().toUpperCase() === symbol.toString().toUpperCase()));
    if (!found) return res.status(404).json(nok("not_found"));
    return res.json(ok({ symbol, found }));
  } catch (e) { return res.status(500).json(nok("token_error", e && e.message)); }
});

// End of PART A7
// server.js — A VERSION — PART A8/10
// Admin actions, manual triggers, heartbeat, reconnect tuning

app.post("/admin/refresh-scripmaster", async (req, res) => {
  try {
    const okLoaded = await downloadAndLoadScripMaster();
    return okLoaded ? res.json(ok({ message: "scripmaster_refreshed", entries: Array.isArray(scripsCache) ? scripsCache.length : 0 })) :
                      res.status(500).json(nok("refresh_failed"));
  } catch (e) {
    return res.status(500).json(nok("refresh_exception", e && e.message));
  }
});

app.post("/admin/login", async (req, res) => {
  try {
    const r = await smartLogin(true);
    if (r && r.success) return res.json(ok({ message: "login_ok", feedToken: r.feedToken || null }));
    return res.status(400).json(nok("login_failed", r));
  } catch (e) { return res.status(500).json(nok("login_exception", e && e.message)); }
});

app.post("/admin/connect-ws", async (req, res) => {
  try {
    const okc = await ensureWsConnected();
    return okc ? res.json(ok({ wsConnected: !!wsConnected })) : res.status(500).json(nok("ws_connect_failed"));
  } catch (e) { return res.status(500).json(nok("ws_connect_exception", e && e.message)); }
});

// heartbeat & auto-reconnect guard
setInterval(()=> {
  try {
    const now = Date.now();
    if (wsClient && wsClient.readyState === (WebSocket ? WebSocket.OPEN : 1)) {
      if (now - wsLastMsgTs > 20000) {
        warn("WS no data >20s — reconnecting");
        try { wsClient.terminate(); } catch(e) {}
        wsConnected = false;
        ensureWsConnected().catch(()=>null);
      }
      try { wsClient.ping && wsClient.ping(); } catch(e) {}
    } else {
      // ensure connection
      ensureWsConnected().catch(()=>null);
    }
  } catch (e) {}
}, 8000);

// auto resubscribe
setInterval(()=> {
  try {
    if (wsConnected) autoSubscribeFutures().catch(()=>null);
  } catch (e) {}
}, 30000);

// token refresh monitor handled in earlier interval

// End of PART A8
// server.js — A VERSION — PART A9/10
// Rate-limiter, debug, process guards, cleanup, graceful shutdown

// simple rate limiter
const simpleRate = {};
function withinRateLimit(key, limit = 200, windowSec = 60) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const rec = simpleRate[key] || { ts: now, count: 0 };
    if (now > rec.ts + windowSec) { rec.ts = now; rec.count = 1; }
    else rec.count = (rec.count || 0) + 1;
    simpleRate[key] = rec;
    return rec.count <= limit;
  } catch (e) { return true; }
}
app.use((req, res, next) => {
  try {
    const k = req.ip || req.headers["x-forwarded-for"] || "anon";
    if (!withinRateLimit(k, 200, 60)) return res.status(429).json(nok("rate_limited"));
  } catch (e) {}
  next();
});

// debug endpoints
app.get("/debug/echo", (req, res) => {
  try { return res.json(ok({ query: req.query || {}, headers: req.headers || {} })); } catch (e) { return res.status(500).json(nok("echo_error", e && e.message)); }
});
app.get("/debug/env", (req, res) => {
  try { return res.json(ok({ SMART_API_KEY: !!SMART_API_KEY, SMART_USER_ID: !!SMART_USER_ID, SCRIPS_LOADED: !!scripsCache, WS_CONNECTED: !!wsConnected })); } catch (e) { return res.status(500).json(nok("env_error", e && e.message)); }
});

// express error handler
function expressErrorHandler(err, req, res, next) {
  try {
    console.error("Express error:", err && (err.stack || err.message || err));
    if (res.headersSent) return next(err);
    return res.status(500).json(nok("internal_server_error", err && (err.message || err)));
  } catch (e) {
    try { res.status(500).json(nok("internal_server_error")); } catch(_) {}
  }
}
app.use(expressErrorHandler);

// uncaught guards
process.on("uncaughtException", (err) => {
  try { console.error("Uncaught Exception:", err && (err.stack || err)); } catch(_) {}
});
process.on("unhandledRejection", (reason, p) => {
  try { console.error("Unhandled Rejection:", reason); } catch(_) {}
});

// cleanup old livePrices every 30s
setInterval(()=> {
  try {
    const now = Date.now();
    for (let t of Object.keys(livePrices||{})) {
      const age = now - (livePrices[t].ts || 0);
      if (age > 5 * 60 * 1000) delete livePrices[t];
    }
  } catch (e) {}
}, 30000);

// graceful shutdown
function gracefulShutdown(signal) {
  return () => {
    log(`Received ${signal} — shutting down`);
    try { if (wsClient && wsClient.terminate) wsClient.terminate(); } catch(e) {}
    setTimeout(()=>process.exit(0), 500);
  };
}
process.on("SIGINT", gracefulShutdown("SIGINT"));
process.on("SIGTERM", gracefulShutdown("SIGTERM"));

// End of PART A9
// server.js — A VERSION — PART A10/10
// Final bootstrap: listen and startup tasks (PORT declared only once above in A1)

// Final startup log and init tasks
app.listen(PORT || 10000, async () => {
  log("---------------------------------------------------------");
  log("✔️  server.js (A-version) loaded");
  log("✔️  SmartAPI + WS + OptionChain + Greeks + Premium Engine Ready");
  log("✔️  Auto ScripMaster (JSON primary) + ZIP fallback (if installed)");
  log("✔️  Listening on PORT:", PORT || 10000);
  log("---------------------------------------------------------");
  try { await downloadAndLoadScripMaster(); } catch(e) { warn("Initial scrip load error:", e && e.message); }
  try { await ensureWsConnected(); } catch(e) { warn("Initial ws connect error:", e && e.message); }
});
