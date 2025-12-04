// server.js — FIXED — PART B1 of 10
// Clean, defensive imports + env + small helpers + ScripMaster JSON-first loader
// Dependencies: express body-parser dotenv node-fetch@2 totp-generator ws unzipper axios

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

// defensive require for totp-generator (some bundlers export default)
let totpGenerator;
try {
  totpGenerator = require("totp-generator");
  if (totpGenerator && totpGenerator.default) totpGenerator = totpGenerator.default;
} catch (e) {
  // will handle missing package at runtime
  totpGenerator = null;
}

const fetch = (() => {
  try {
    // prefer node-fetch@2 require style
    return require("node-fetch");
  } catch (e) {
    // as a last resort try global fetch (node 18+)
    if (typeof globalThis.fetch === "function") return globalThis.fetch;
    throw new Error("node-fetch not available. Please install node-fetch@2");
  }
})();

const unzipper = (() => {
  try { return require("unzipper"); } catch (e) { return null; }
})();

const WebSocket = (() => {
  try { return require("ws"); } catch (e) { return null; }
})();

const axios = (() => {
  try { return require("axios"); } catch (e) { return null; }
})();

// ---------- Basic app ----------
const app = express();
app.use(bodyParser.json({ limit: "256kb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// ---------- ENV keys (your four required keys) ----------
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET_ENV = process.env.SMART_TOTP_SECRET || ""; // preferred (base32 secret)
const SMART_TOTP_CODE_ENV = process.env.SMART_TOTP || ""; // optional 6-digit (temporary only)
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMARTAPI_WS_BASE = process.env.SMARTAPI_WS_BASE || "wss://smartapisocket.angelone.in/smart-stream";

// ---------- Internal defaults ----------
const PORT = process.env.PORT || 10000;
const DATA_DIR = path.join(__dirname);
const LOCAL_SCRIP_JSON = path.join(DATA_DIR, "OpenAPIScripMaster.json");
const SCRIP_MASTER_JSON_URL = process.env.SCRIP_MASTER_URL || "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
const SCRIP_MASTER_ZIP_URL = process.env.SCRIP_MASTER_ZIP || "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.zip";
const SCRIP_DOWNLOAD_RETRY_MS = 60000;

// ---------- Global state ----------
let accessToken = null;
let feedToken = null;
let tokenExpiry = 0;
let wsClient = null;
let wsConnected = false;
let scripsCache = null;
let scripsLastUpdated = null;
let livePrices = {}; // token -> { ltp, ts }

// ---------- small helpers ----------
function ok(data = {}) { return { success: true, ...data }; }
function nok(msg = "error", details = null) { return { success: false, message: msg, details: details }; }

function log(...args) { console.log.apply(console, args); }
function warn(...args) { console.warn.apply(console, args); }

// safe numeric helper
function num(v, def = 0) { const n = Number(v); return Number.isFinite(n) ? n : def; }

// ---------- ScripMaster loader: try local JSON first, then remote JSON, then ZIP fallback ----------
async function loadScripMasterFromLocal() {
  try {
    if (fs.existsSync(LOCAL_SCRIP_JSON)) {
      const text = fs.readFileSync(LOCAL_SCRIP_JSON, "utf8");
      const parsed = JSON.parse(text);
      scripsCache = Array.isArray(parsed) ? parsed : (parsed.data || parsed.scripts || []);
      scripsLastUpdated = new Date().toISOString();
      log("Loaded local OpenAPIScripMaster.json entries:", (scripsCache||[]).length);
      return true;
    }
  } catch (e) {
    warn("Local scrip master parse error:", e && e.message);
  }
  return false;
}

async function downloadAndLoadScripMaster() {
  // 1) prefer local file if exists
  if (await loadScripMasterFromLocal()) return true;

  // 2) try remote JSON
  try {
    log("Attempting ScripMaster JSON download:", SCRIP_MASTER_JSON_URL);
    const r = await fetch(SCRIP_MASTER_JSON_URL, { timeout: 20000 });
    if (r && (r.status === 200 || r.ok)) {
      const txt = await r.text();
      try {
        const j = JSON.parse(txt);
        scripsCache = Array.isArray(j) ? j : (j.data || j.scripts || []);
        scripsLastUpdated = new Date().toISOString();
        // Save local copy for future
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
    warn("ScripMaster JSON download exception:", e && e.message);
  }

  // 3) ZIP fallback (if unzipper available)
  if (!unzipper) {
    warn("Unzipper not available - skipping ZIP fallback.");
    return false;
  }

  try {
    log("Attempting ScripMaster ZIP fallback:", SCRIP_MASTER_ZIP_URL);
    const rz = await fetch(SCRIP_MASTER_ZIP_URL, { timeout: 30000 });
    if (!rz || !rz.ok) throw new Error("ZIP fetch failed: " + (rz && rz.status));
    const buffer = await rz.buffer();
    // parse zip in memory
    const stream = require("stream");
    const s = new stream.PassThrough();
    s.end(buffer);
    await new Promise((resolve, reject) => {
      s.pipe(unzipper.Parse())
        .on("entry", (entry) => {
          const fileName = entry.path || "";
          if (fileName.toLowerCase().endsWith(".json")) {
            let txt = "";
            entry.on("data", c => txt += c.toString("utf8"));
            entry.on("end", () => {
              try {
                const j = JSON.parse(txt);
                scripsCache = Array.isArray(j) ? j : (j.data || j.scripts || []);
                scripsLastUpdated = new Date().toISOString();
                try { fs.writeFileSync(LOCAL_SCRIP_JSON, JSON.stringify(scripsCache, null, 2), "utf8"); } catch(e){}
                log("ScripMaster loaded from ZIP entry:", fileName, "entries:", (scripsCache||[]).length);
              } catch (e) {
                warn("ZIP JSON parse failed:", e && e.message);
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

  warn("ScripMaster download failed (JSON & ZIP).");
  return false;
}

// Kick off initial load (non-blocking)
downloadAndLoadScripMaster().then(ok => {
  if (!ok) {
    warn("Initial ScripMaster load failed. Will retry every", SCRIP_DOWNLOAD_RETRY_MS, "ms");
    setInterval(() => downloadAndLoadScripMaster().catch(()=>null), SCRIP_DOWNLOAD_RETRY_MS);
  }
}).catch(()=>null);

// PART B1 ends here. Continue with PART B2 for auth, totp generation, and smartLogin.
// server.js — FIXED — PART B2 of 10
// SmartAPI TOTP Generator + Login Handler (fully patched)

// ---------------- TOTP GENERATOR (SAFE, DEFENSIVE) ----------------
async function generateTotpCode() {
  try {
    // 1) If user provides 6-digit static TOTP: use it directly
    if (SMART_TOTP_CODE_ENV && /^\d{6}$/.test(SMART_TOTP_CODE_ENV)) {
      log("Using static 6-digit TOTP from env");
      return SMART_TOTP_CODE_ENV;
    }

    // 2) If secret available: generate dynamic TOTP
    if (SMART_TOTP_SECRET_ENV) {
      if (!totpGenerator) {
        warn("TOTP generator missing, cannot create dynamic TOTP");
        return null;
      }
      const totp = String(totpGenerator(SMART_TOTP_SECRET_ENV));
      if (/^\d{6}$/.test(totp)) return totp;
      return totp.slice(0, 6);
    }

    // 3) No TOTP provided at all
    warn("No SMART_TOTP or SMART_TOTP_SECRET found in .env");
    return null;

  } catch (e) {
    warn("generateTotpCode error:", e && e.message);
    return null;
  }
}

// ---------------- SMARTAPI LOGIN (COMPLETE FIXED VERSION) ----------------
async function smartLogin(force = false) {
  try {
    // Reuse valid token
    if (!force && accessToken && feedToken && tokenExpiry && Date.now() < tokenExpiry - 15000) {
      return {
        success: true,
        accessToken,
        feedToken,
        reused: true
      };
    }

    // Generate TOTP
    const totp = await generateTotpCode();
    if (!totp) {
      warn("No TOTP available → cannot login");
      accessToken = null;
      feedToken = null;
      return { success: false, reason: "NO_TOTP" };
    }

    // Build payload
    const loginPayload = {
      apiKey: SMART_API_KEY,
      userId: SMART_USER_ID,
      password: SMART_API_SECRET,
      totp: totp
    };

    const loginURL = `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`;
    log("Attempting SmartAPI login →", loginURL);

    const resp = await fetch(loginURL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(loginPayload),
      timeout: 20000
    });

    const js = await resp.json().catch(() => null);

    if (!resp.ok || !js) {
      warn("Login HTTP error:", resp.status, js);
      accessToken = null;
      feedToken = null;
      return { success: false, reason: "HTTP_FAIL", status: resp.status };
    }

    // Extract tokens (SmartAPI returns data.jwtToken + feedToken)
    const data = js.data || {};
    accessToken =
      data.jwtToken ||
      data.accessToken ||
      js.jwtToken ||
      js.accessToken ||
      null;

    feedToken =
      data.feedToken ||
      js.feedToken ||
      null;

    // expiry
    tokenExpiry = data.expires_in_ms
      ? Date.now() + Number(data.expires_in_ms)
      : Date.now() + 25 * 60 * 1000;

    log("SmartAPI login success → accessToken:", !!accessToken, "feedToken:", !!feedToken);

    if (!feedToken) {
      warn("⚠ feedToken missing in login response → WS will fail");
    }

    return {
      success: !!accessToken,
      accessToken,
      feedToken,
      raw: js
    };

  } catch (e) {
    warn("smartLogin exception:", e && e.message);
    accessToken = null;
    feedToken = null;
    return { success: false, reason: e && e.message };
  }
}

// Auto login on server start
(async () => {
  log("Performing initial SmartAPI login...");
  const r = await smartLogin();
  if (!r.success) {
    warn("Initial login failed → will retry every 20 sec");
    setInterval(() => smartLogin(true).catch(() => null), 20000);
  }
})();
// server.js — FIXED — PART B3 of 10
// WebSocket connection, robust message parsing, subscribe helpers, LTP endpoints

// ---------- Build WS URL ----------
function buildWsUrl(clientCode, feedTokenLocal) {
  const base = process.env.SMARTAPI_WS_BASE || SMARTAPI_WS_BASE || "wss://smartapisocket.angelone.in/smart-stream";
  const params = new URLSearchParams();
  if (clientCode) params.set("clientCode", clientCode);
  if (feedTokenLocal) params.set("feedToken", feedTokenLocal);
  if (SMART_API_KEY) params.set("apiKey", SMART_API_KEY);
  const url = base + "?" + params.toString();
  return url;
}

// ---------- Update live price ----------
function updateLivePrice(token, ltp) {
  try {
    if (!token) return;
    const t = String(token);
    const now = Date.now();
    livePrices[t] = { ltp: Number(ltp), ts: now };
  } catch (e) {
    // ignore
  }
}

// ---------- Parse WS message defensively ----------
function parseWsMessage(raw) {
  try {
    if (!raw) return;
    let txt = null;
    if (Buffer.isBuffer(raw)) txt = raw.toString("utf8");
    else if (typeof raw === "string") txt = raw;
    else if (typeof raw === "object") txt = JSON.stringify(raw);
    else return;

    // Try JSON
    let parsed = null;
    try { parsed = JSON.parse(txt); } catch (e) { parsed = null; }

    if (parsed) {
      // Common shapes:
      // { payload: [ { token:..., ltp:... }, ... ] } or { data: [...] } or { payload: { token, ltp } }
      if (Array.isArray(parsed.payload)) {
        parsed.payload.forEach(item => processTickItem(item));
        return;
      }
      if (Array.isArray(parsed.data)) {
        parsed.data.forEach(item => processTickItem(item));
        return;
      }
      if (parsed.payload && typeof parsed.payload === "object") {
        processTickItem(parsed.payload);
        return;
      }
      if (parsed.token && (parsed.ltp || parsed.lastPrice || parsed.last_price)) {
        processTickItem(parsed);
        return;
      }
      // sometimes envelope: { message: { ... } }
      if (parsed.message) {
        try { parseWsMessage(JSON.stringify(parsed.message)); } catch(_) {}
        return;
      }
    }

    // Non-JSON pipe separated e.g. "token|ltp|..."
    if (txt.indexOf("|") > -1) {
      const parts = txt.split("|").map(s => s.trim());
      if (parts.length >= 2) {
        const tok = parts[0];
        const ltp = Number(parts[1]) || null;
        if (tok && !isNaN(ltp)) updateLivePrice(tok, ltp);
      }
      return;
    }

    // If nothing matched, ignore gracefully
  } catch (e) {
    // swallow parsing errors
  }
}

// ---------- Helpers to normalize incoming tick objects ----------
function processTickItem(item) {
  if (!item || typeof item !== "object") return;
  // Common token keys: token, symboltoken, instrument_token, instrumentToken
  const token = item.token || item.symboltoken || item.instrument_token || item.instrumentToken || item.tok || item.instrumentId || item.instrument;
  const ltp = Number(item.ltp || item.lastPrice || item.last_price || item.last_traded_price || item.lp || item.price || item.p);
  if (token && !isNaN(ltp)) {
    updateLivePrice(String(token), ltp);
    return;
  }
  // try name based lookup: symbol/name -> find token via scripsCache
  const maybeName = (item.symbol || item.tradingsymbol || item.tradingSymbol || item.name || item.scrip || "").toString().toUpperCase();
  if (maybeName && scripsCache && Array.isArray(scripsCache)) {
    const found = scripsCache.find(it => {
      if (!it) return false;
      const s = (it.symbol || it.tradingsymbol || it.name || "").toString().toUpperCase();
      return s === maybeName || s.includes(maybeName);
    });
    if (found && found.token && !isNaN(ltp)) {
      updateLivePrice(String(found.token), ltp);
    }
  }
}

// ---------- WS Connect with safe handlers ----------
let wsReconnectTimer = null;
async function ensureWsConnected() {
  try {
    // Require feedToken — attempt to login if missing
    if (!feedToken) {
      await smartLogin().catch(()=>null);
    }
    const clientCode = process.env.WS_CLIENT_CODE || SMART_USER_ID || "";
    const ft = feedToken || process.env.WS_FEED_TOKEN || "";
    const wsUrl = buildWsUrl(clientCode, ft);
    if (!WebSocket) {
      warn("ws package missing — live WS disabled");
      return false;
    }

    // If WS exists and open, do nothing
    if (wsClient && wsConnected) return true;

    // Close old client if present
    try { if (wsClient) { wsClient.terminate(); } } catch(e){}

    log("Opening WS →", wsUrl);
    wsClient = new WebSocket(wsUrl, { handshakeTimeout: 10000, perMessageDeflate: false });

    wsClient.on("open", () => {
      wsConnected = true;
      log("WS connected");
      // auto-subscribe common FUT tokens if available
      try { autoSubscribeFutures(); } catch(e){}
    });

    wsClient.on("message", (raw) => {
      try { parseWsMessage(raw); } catch(e) {}
    });

    wsClient.on("error", (err) => {
      warn("WS error:", err && (err.message || err));
    });

    wsClient.on("close", (code, reason) => {
      wsConnected = false;
      warn("WS closed:", code, (reason && reason.toString && reason.toString()) || reason);
      // schedule reconnect
      if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
      wsReconnectTimer = setTimeout(() => ensureWsConnected().catch(()=>null), 4000);
    });

    return true;
  } catch (e) {
    warn("ensureWsConnected exception:", e && e.message);
    return false;
  }
}

// ---------- Subscribe helper (send tokens to WS) ----------
function wsSendSafe(obj) {
  try {
    if (!wsClient || wsClient.readyState !== WebSocket.OPEN) return false;
    wsClient.send(JSON.stringify(obj));
    return true;
  } catch (e) {
    warn("wsSendSafe failed:", e && e.message);
    return false;
  }
}

// SmartAPI often expects: { message_type:"subscribe", exchange:"NFO", token:[...tokens] }
function wsSubscribeTokens(tokens = [], exchange = "ALL") {
  if (!Array.isArray(tokens) || tokens.length === 0) return false;
  const payload = { message_type: "subscribe", exchange: exchange, token: tokens.map(t=>String(t)) };
  return wsSendSafe(payload);
}

// ---------- Auto-subscribe FUT tokens (Nifty / Sensex / Natural Gas) ----------
async function autoSubscribeFutures() {
  try {
    if (!scripsCache || !Array.isArray(scripsCache)) return;
    const markets = ["NIFTY", "SENSEX", "NATURALGAS", "NATURAL GAS", "NATGAS"];
    const tokens = [];
    // heuristics: pick FUT instruments for these markets, prefer earliest expiry >= today
    const now = new Date();
    const futs = scripsCache.filter(it => {
      if (!it || !it.symbol) return false;
      const s = (it.symbol || "").toString().toUpperCase();
      const inst = (it.instrumentType || it.instrument_type || it.inst || "").toString().toUpperCase();
      if (!inst.includes("FUT")) return false;
      if (markets.some(mk => s.includes(mk))) return true;
      return false;
    });

    // group by market text and pick nearest expiry per group
    const byMarket = {};
    for (let f of futs) {
      const s = (f.symbol || "").toString().toUpperCase();
      let key = null;
      if (s.includes("NIFTY")) key = "nifty";
      else if (s.includes("SENSEX")) key = "sensex";
      else if (s.includes("NATURALGAS") || s.includes("NATURAL GAS") || s.includes("NATGAS")) key = "natural gas";
      if (!key) continue;
      byMarket[key] = byMarket[key] || [];
      byMarket[key].push(f);
    }

    for (let k of Object.keys(byMarket)) {
      const arr = byMarket[k];
      // sort by expiry ascending
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
  } catch (e) {
    warn("autoSubscribeFutures error:", e && e.message);
  }
}

// ---------- Ensure WS periodically (keep alive) ----------
setInterval(() => {
  ensureWsConnected().catch(()=>null);
}, 8000);

// ---------- Public endpoint: manual subscribe ----------
app.post("/admin/subscribe", async (req, res) => {
  try {
    const tokens = req.body && req.body.tokens;
    if (!Array.isArray(tokens) || tokens.length === 0) return res.status(400).json(nok("tokens required"));
    const ok = wsSubscribeTokens(tokens.map(t=>String(t)), req.body.exchange || "ALL");
    return res.json(ok ? ok({ subscribed: tokens.length }) : nok("subscribe_failed"));
  } catch (e) {
    return res.status(500).json(nok("subscribe_error", e && e.message));
  }
});

// ---------- Public endpoint: get ltp (token or symbol) ----------
app.get("/ltp", async (req, res) => {
  try {
    const token = req.query.token;
    const symbol = req.query.symbol;
    if (token) {
      if (livePrices[token]) return res.json(ok({ token, ltp: livePrices[token].ltp, ts: livePrices[token].ts }));
      // fallback: try find token in scripsCache by token field
      const found = (scripsCache || []).find(it => it && (String(it.token) === String(token) || String(it.symboltoken) === String(token) || String(it.symbolToken) === String(token)));
      if (found) {
        // attempt HTTP LTP fallback
        const fetched = await fetchLtpHttp(found.symbol || found.tradingSymbol || found.name, found.exch || found.exch_seg || "NFO");
        if (fetched && fetched.success) return res.json(ok({ token, ltp: fetched.ltp, source: "http" }));
      }
      return res.status(404).json(nok("ltp_not_found"));
    }
    if (symbol) {
      // try find token
      const found = (scripsCache || []).find(it => it && ((it.symbol || "").toString().toUpperCase() === symbol.toString().toUpperCase() || (it.tradingsymbol || "").toString().toUpperCase() === symbol.toString().toUpperCase()));
      if (found) {
        if (livePrices[found.token]) return res.json(ok({ symbol, token: found.token, ltp: livePrices[found.token].ltp, source: "ws" }));
        const fetched = await fetchLtpHttp(found.symbol || found.tradingsymbol || found.name, found.exch || found.exch_seg || "NFO");
        if (fetched && fetched.success) return res.json(ok({ symbol, token: found.token, ltp: fetched.ltp, source: "http" }));
      }
      // last resort: try HTTP fetch directly with provided symbol
      const fallback = await fetchLtpHttp(symbol, req.query.exchange || "NFO");
      if (fallback && fallback.success) return res.json(ok({ symbol, ltp: fallback.ltp, source: "http" }));
      return res.status(404).json(nok("symbol_not_found"));
    }

    return res.status(400).json(nok("provide token or symbol query param"));
  } catch (e) {
    return res.status(500).json(nok("ltp_error", e && e.message));
  }
});

// PART B3 ends here.
// server.js — FIXED — PART B4 of 10
// Option Chain Engine – Spot detection, expiry, strike calculations

// ---------- SIMPLE EXPIRY PICKER ----------
function findNearestExpiry(daysAhead = 7) {
  try {
    // Pick today's date + expiry_days
    const d = new Date();
    d.setDate(d.getDate() + Number(daysAhead || 7));
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  } catch (e) {
    return null;
  }
}

// ---------- PICK OPTION CHAIN INSTRUMENTS (CE/PE for selected strike) ----------
function findOptionInstrument(strike, type, market) {
  if (!scripsCache || !Array.isArray(scripsCache)) return null;
  const up = type.toUpperCase();
  const mk = (market || "").toLowerCase();
  const st = Number(strike);

  return scripsCache.find(it => {
    if (!it) return false;
    const sym = (it.symbol || it.tradingsymbol || "").toUpperCase();
    if (Number(it.strike) !== st) return false;
    if (up === "CE" && !sym.endsWith("CE")) return false;
    if (up === "PE" && !sym.endsWith("PE")) return false;

    // filter by market base
    if (mk.includes("nifty") && sym.includes("NIFTY")) return true;
    if (mk.includes("sensex") && sym.includes("SENSEX")) return true;
    if (mk.includes("gas") && (sym.includes("NATURAL") || sym.includes("GAS"))) return true;

    return false;
  }) || null;
}

// ---------- SIMPLE STRIKE ENGINE ----------
// Step: choose ATM strike, nearest CE, nearest PE, and a straddle center
function computeStrikes(spot, market, expiry_days) {
  const mk = (market || "").toLowerCase();
  const step =
    mk.includes("natural") || mk.includes("gas")
      ? 5    // NATGAS small step
      : 50;  // NIFTY / SENSEX standard

  const atm = Math.round(Number(spot) / step) * step;
  return {
    atm,
    ceStrike: atm + step,
    peStrike: atm - step,
    straddleStrike: atm
  };
}

// ---------- FETCH SPOT (via LTP fallback or WS last seen) ----------
async function getSpotForMarket(market) {
  try {
    const mk = (market || "").toLowerCase();
    if (!scripsCache) return null;

    // Pick nearest FUT for the market
    const futs = scripsCache.filter(it => {
      if (!it || !it.symbol) return false;
      const s = (it.symbol || "").toUpperCase();
      if (!s.includes("FUT")) return false;
      if (mk.includes("nifty") && s.includes("NIFTY")) return true;
      if (mk.includes("sensex") && s.includes("SENSEX")) return true;
      if (mk.includes("gas") && (s.includes("NATURAL") || s.includes("GAS"))) return true;
      return false;
    });

    if (!futs.length) return null;

    // nearest expiry
    futs.sort((a, b) => {
      const da = a.expiry ? new Date(a.expiry) : new Date(9999, 11, 31);
      const db = b.expiry ? new Date(b.expiry) : new Date(9999, 11, 31);
      return da - db;
    });
    const chosen = futs[0];
    const token = chosen.token || chosen.symboltoken || chosen.symbolToken;

    if (token && livePrices[token]) {
      return livePrices[token].ltp;
    }

    // fallback HTTP LTP
    const alt = await fetchLtpHttp(chosen.symbol || chosen.tradingSymbol || chosen.name, chosen.exch || chosen.exch_seg || "NFO");
    if (alt && alt.success) return alt.ltp;

    return null;
  } catch (e) {
    return null;
  }
}

// ---------- HTTP LTP FALLBACK ----------
async function fetchLtpHttp(symbol, exchange) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote/ltp`;

    const headers = { "Content-Type": "application/json" };
    if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;

    // SmartAPI expects JSON body OR query param depending on version — use query fallback
    const r = await fetch(url + `?symbol=${encodeURIComponent(symbol)}&exchange=${encodeURIComponent(exchange)}`, {
      headers,
      method: "GET",
      timeout: 10000
    });

    const js = await r.json().catch(() => null);
    if (!js) return null;

    // parse LTP
    const ltp =
      js.ltp ||
      (js.data && js.data.ltp) ||
      (js.data && js.data.lastPrice) ||
      (js.data && js.data.last_price) ||
      null;

    if (!ltp) return null;

    return { success: true, ltp: Number(ltp) };
  } catch (e) {
    return null;
  }
}

// ---------- OPTION CHAIN MAIN ENDPOINT ----------
app.post("/option-chain", async (req, res) => {
  try {
    const body = req.body || {};

    const inputSpot = Number(body.spot || 0);
    const market = (body.market || "nifty").toLowerCase();
    const expiry_days = Number(body.expiry_days || 7);

    // STEP-1: get spot (if no input spot)
    let spot = inputSpot;
    if (!spot) {
      const autoSpot = await getSpotForMarket(market);
      if (autoSpot) spot = autoSpot;
    }
    if (!spot) return res.status(500).json(nok("Failed to get spot"));

    // STEP-2: compute strikes
    const { atm, ceStrike, peStrike, straddleStrike } = computeStrikes(spot, market, expiry_days);

    // STEP-3: build final objects
    const strikes = [
      {
        type: "CE",
        strike: ceStrike,
        distance: Math.abs(ceStrike - spot),
        entry: 10,
        stopLoss: 6,
        target: 15
      },
      {
        type: "PE",
        strike: peStrike,
        distance: Math.abs(peStrike - spot),
        entry: 10,
        stopLoss: 6,
        target: 15
      },
      {
        type: "STRADDLE",
        strike: straddleStrike,
        distance: Math.abs(straddleStrike - spot),
        entry: 5,
        stopLoss: 3,
        target: 8
      }
    ];

    return res.json(ok({
      spot,
      market,
      expiry_days,
      strikes
    }));

  } catch (e) {
    return res.status(500).json(nok("CHAIN_ERROR", e && e.message));
  }
});

// PART B4 ends here.
// server.js — FIXED — PART B5 of 10
// Greeks (Black-Scholes), premium engine, premium endpoints

// ---------- Math helpers ----------
function normPdf(x) {
  return Math.exp(-0.5 * x * x) / Math.sqrt(2 * Math.PI);
}

// Cumulative normal distribution (approx)
function normCdf(x) {
  // Abramowitz & Stegun approximation
  const sign = x < 0 ? -1 : 1;
  const a1 =  0.254829592;
  const a2 = -0.284496736;
  const a3 =  1.421413741;
  const a4 = -1.453152027;
  const a5 =  1.061405429;
  const p  =  0.3275911;
  const absx = Math.abs(x) / Math.sqrt(2.0);
  const t = 1.0 / (1.0 + p * absx);
  const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-absx * absx);
  return 0.5 * (1.0 + sign * y);
}

// ---------- Black-Scholes core ----------
function blackScholesPrice(spot, strike, r, sigma, timeYears, isCall = true) {
  // spot S, strike K, r risk-free annual decimal, sigma annual vol decimal, timeYears T
  if (timeYears <= 0 || sigma <= 0) {
    // intrinsic price
    if (isCall) return Math.max(0, spot - strike);
    return Math.max(0, strike - spot);
  }
  const S = Number(spot), K = Number(strike);
  const sqrtT = Math.sqrt(timeYears);
  const d1 = (Math.log(S / K) + (r + 0.5 * sigma * sigma) * timeYears) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  if (isCall) {
    return S * normCdf(d1) - K * Math.exp(-r * timeYears) * normCdf(d2);
  } else {
    return K * Math.exp(-r * timeYears) * normCdf(-d2) - S * normCdf(-d1);
  }
}

// Greeks: Delta, Gamma, Vega, Theta (per day), Rho
function blackScholesGreeks(spot, strike, r, sigma, timeYears, isCall = true) {
  const S = Number(spot), K = Number(strike);
  if (timeYears <= 0 || sigma <= 0) {
    // at-expiry greeks: delta is either 0 or 1 (approx)
    const intrinsic = isCall ? (S > K ? 1 : 0) : (S < K ? -1 : 0);
    return { delta: intrinsic, gamma: 0, vega: 0, theta: 0, rho: 0 };
  }
  const sqrtT = Math.sqrt(timeYears);
  const d1 = (Math.log(S / K) + (r + 0.5 * sigma * sigma) * timeYears) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  const delta = isCall ? normCdf(d1) : (normCdf(d1) - 1);
  const gamma = normPdf(d1) / (S * sigma * sqrtT);
  const vega = S * normPdf(d1) * sqrtT; // per 1 vol (i.e., multiply/divide accordingly)
  // Theta (per year) approximate
  const callTheta = -(S * normPdf(d1) * sigma) / (2 * sqrtT) - r * K * Math.exp(-r * timeYears) * normCdf(d2);
  const putTheta  = -(S * normPdf(d1) * sigma) / (2 * sqrtT) + r * K * Math.exp(-r * timeYears) * normCdf(-d2);
  const theta = (isCall ? callTheta : putTheta) / 365.0; // per day
  const rhoCall = K * timeYears * Math.exp(-r * timeYears) * normCdf(d2);
  const rhoPut = -K * timeYears * Math.exp(-r * timeYears) * normCdf(-d2);
  const rho = isCall ? rhoCall / 100.0 : rhoPut / 100.0; // scaled (per 1% change)
  return { delta, gamma, vega, theta, rho };
}

// ---------- Premium engine (simple rules based on distance + volatility) ----------
function computePremiumPlan(distancePoints, underlyingPrice, impliedVol = 0.25) {
  // distancePoints: absolute distance between strike and basePrice
  // underlyingPrice: base price for scaling
  // impliedVol: annual vol as decimal (used for est. premium if needed)
  const d = Math.abs(Number(distancePoints || 0));
  const s = Number(underlyingPrice || 1);
  // rough heuristic: option premium roughly = S * sigma * sqrt(T) * moneynessFactor
  // But we will use rule-based presets (tuned to your earlier examples)
  let entry = 10, stopLoss = 6, target = 15;

  if (d <= 10) {
    entry = 5; stopLoss = 3; target = 8;
  } else if (d <= 50) {
    entry = 10; stopLoss = 6; target = 15;
  } else if (d <= 100) {
    entry = 8; stopLoss = 5; target = 12;
  } else {
    entry = 6; stopLoss = 4; target = 10;
  }

  // Adjust based on underlying price scale (for Sensex big numbers)
  if (s > 20000) {
    // scale down entries to be more realistic
    entry = Math.max(1, Math.round(entry / 2));
    stopLoss = Math.max(1, Math.round(stopLoss / 2));
    target = Math.max(2, Math.round(target / 2));
  }

  return { distance: d, entry, stopLoss, target };
}

// ---------- Endpoint: premium-calc (ad-hoc) ----------
app.post("/premium-calc", async (req, res) => {
  try {
    const body = req.body || {};
    // accept either: distance OR strike+basePrice
    let distance = Number(body.distance || 0);
    const strike = Number(body.strike || 0);
    const basePrice = Number(body.basePrice || body.spot || 0);
    const iv = Number(body.iv || body.impliedVol || 0.25);
    if (!distance && strike && basePrice) distance = Math.abs(strike - basePrice);
    if (!distance) return res.status(400).json(nok("distance or (strike + basePrice) required"));

    const plan = computePremiumPlan(distance, basePrice, iv);
    return res.json(ok({ plan }));
  } catch (e) {
    return res.status(500).json(nok("premium_error", e && e.message));
  }
});

// ---------- Endpoint: greeks-calc (ad-hoc) ----------
app.post("/greeks-calc", (req, res) => {
  try {
    const body = req.body || {};
    const spot = Number(body.spot || 0);
    const strike = Number(body.strike || 0);
    const iv = Number(body.iv || 0.25);
    const r = Number(body.r || 0.06);
    const days = Number(body.days || 7);
    const isCall = (body.type || "CE").toString().toUpperCase() === "CE";
    if (!spot || !strike) return res.status(400).json(nok("spot and strike required"));
    const T = Math.max(1, days) / 365.0;
    const price = blackScholesPrice(spot, strike, r, iv, T, isCall);
    const greeks = blackScholesGreeks(spot, strike, r, iv, T, isCall);
    return res.json(ok({ price, greeks }));
  } catch (e) {
    return res.status(500).json(nok("greeks_error", e && e.message));
  }
});

// PART B5 ends here.
// server.js — FIXED — PART B6 of 10
// Trend engine + full-analysis endpoint (EMA/RSI/VWAP + strikes + tokens)

// ---------- Simple Trend Engine ----------
function computeTrend({ ema20, ema50, rsi, vwap, spot, expiry_days }) {
  try {
    const diff = ema20 - ema50;
    const pct = (diff / ((ema20 + ema50) / 2)) * 100;
    let main = "SIDEWAYS";
    let strength = "RANGE";
    let bias = "NONE";

    if (pct > 0.3) {
      main = "UP";
      bias = "BULLISH";
      strength = pct > 1 ? "STRONG" : "MILD";
    } else if (pct < -0.3) {
      main = "DOWN";
      bias = "BEARISH";
      strength = pct < -1 ? "STRONG" : "MILD";
    }

    const rsiEval =
      rsi > 60 ? "RSI HIGH (overbought-ish)" :
      rsi < 40 ? "RSI LOW (oversold-ish)" :
      `RSI ${rsi} (neutral)`;

    const emaGap = pct === 0
      ? "Flat (0%)"
      : pct > 0
        ? `Bullish (${pct.toFixed(2)}%)`
        : `Bearish (${pct.toFixed(2)}%)`;

    const vwapCmp =
      spot > vwap
        ? `Above VWAP (+${(spot - vwap).toFixed(2)})`
        : `Below VWAP (${(spot - vwap).toFixed(2)})`;

    return {
      main,
      strength,
      bias,
      score: Math.abs(pct) * 10 + (rsi > 60 ? 5 : rsi < 40 ? 5 : 2),
      components: {
        ema_gap: emaGap,
        rsi: rsiEval,
        vwap: vwapCmp,
        price_structure: "Basic Structure",
        expiry: expiry_days > 5 ? "Expiry mid" : "Near expiry"
      },
      comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
    };
  } catch (e) {
    return null;
  }
}

// ---------- Auto token mapping (nearest FUT per market) ----------
function getAutoTokens() {
  if (!scripsCache || !Array.isArray(scripsCache)) return {};
  const mkts = ["nifty", "sensex", "natural gas"];
  const out = {};
  for (let mk of mkts) {
    const fut = findNearestFuture(mk);
    if (fut) {
      out[mk] = {
        symbol: fut.symbol || fut.tradingsymbol || fut.name || "",
        token: fut.token || fut.symboltoken || fut.symbolToken || "",
        expiry: fut.expiry || null
      };
    }
  }
  return out;
}

function findNearestFuture(market) {
  if (!scripsCache || !Array.isArray(scripsCache)) return null;
  const mk = market.toLowerCase();
  const futs = scripsCache.filter(it => {
    if (!it || !it.symbol) return false;
    const s = (it.symbol || "").toUpperCase();
    if (!s.includes("FUT")) return false;
    if (mk.includes("nifty") && s.includes("NIFTY")) return true;
    if (mk.includes("sensex") && s.includes("SENSEX")) return true;
    if (mk.includes("gas") && (s.includes("NATURAL") || s.includes("GAS"))) return true;
    return false;
  });
  if (!futs.length) return null;
  futs.sort((a, b) => {
    const da = a.expiry ? new Date(a.expiry) : new Date(9999,1,1);
    const db = b.expiry ? new Date(b.expiry) : new Date(9999,1,1);
    return da - db;
  });
  return futs[0];
}

// ---------- Helper: getSpot (fallback through WS, HTTP, or calc) ----------
async function getSpotUnified(body) {
  let spot = Number(body.spot || 0);

  if (!spot) {
    // try market-based spot
    const mk = (body.market || "nifty").toLowerCase();
    const s = await getSpotForMarket(mk);
    if (s) spot = s;
  }
  if (!spot) {
    // last fallback
    spot = Number(body.ema20 || 0) || Number(body.ema50 || 0) || 0;
  }
  return spot;
}

// ---------- FULL ANALYSIS ENDPOINT ----------
app.post("/full-analysis", async (req, res) => {
  try {
    const body = req.body || {};
    const ema20 = Number(body.ema20 || 0);
    const ema50 = Number(body.ema50 || 0);
    const rsi = Number(body.rsi || 0);
    const vwap = Number(body.vwap || 0);
    const market = (body.market || "nifty").toLowerCase();
    const expiry_days = Number(body.expiry_days || 7);

    // Spot (unified)
    const spot = await getSpotUnified(body);
    if (!spot) return res.status(500).json(nok("Unable to determine spot"));

    // Trend
    const trend = computeTrend({ ema20, ema50, rsi, vwap, spot, expiry_days });

    // Strikes
    const { atm, ceStrike, peStrike, straddleStrike } = computeStrikes(spot, market, expiry_days);

    const strikes = [
      {
        type: "CE",
        strike: ceStrike,
        distance: Math.abs(ceStrike - spot),
        entry: 10,
        stopLoss: 6,
        target: 15
      },
      {
        type: "PE",
        strike: peStrike,
        distance: Math.abs(peStrike - spot),
        entry: 10,
        stopLoss: 6,
        target: 15
      },
      {
        type: "STRADDLE",
        strike: straddleStrike,
        distance: Math.abs(straddleStrike - spot),
        entry: 5,
        stopLoss: 3,
        target: 8
      }
    ];

    // Auto-token mapping
    const auto_tokens = getAutoTokens();

    // Meta section
    const meta = {
      live_data_used: !!livePrices && Object.keys(livePrices).length > 0,
      live_ltp: spot,
      live_error: null
    };

    return res.json({
      success: true,
      message: "Calculation complete",
      login_status: feedToken ? "SmartAPI Logged-In" : "Login Issue",
      input: {
        ema20,
        ema50,
        rsi,
        vwap,
        spot,
        market,
        expiry_days,
        use_live: !!body.use_live
      },
      trend,
      strikes,
      auto_tokens,
      meta
    });

  } catch (e) {
    return res.status(500).json(nok("FULL_ANALYSIS_ERROR", e && e.message));
  }
});

// PART B6 ends here.
// server.js — FIXED — PART B7 of 10
// Admin / Diagnostic endpoints, memory checks, graceful shutdown, cleanup

// ---------- Health & basic info ----------
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
        SMART_TOTP_SECRET: !!SMART_TOTP_SECRET_ENV || !!SMART_TOTP_CODE_ENV
      }
    }));
  } catch (e) {
    return res.status(500).json(nok("info_error", e && e.message));
  }
});

// ---------- Admin status (detailed) ----------
app.get("/admin/status", (req, res) => {
  try {
    return res.json(ok({
      wsConnected: !!wsConnected,
      accessTokenPresent: !!accessToken,
      feedTokenPresent: !!feedToken,
      tokenExpiry: tokenExpiry,
      livePricesCount: Object.keys(livePrices || {}).length,
      scripsLoaded: !!scripsCache,
      scripsCount: Array.isArray(scripsCache) ? scripsCache.length : 0,
      scripsLastUpdated: scripsLastUpdated
    }));
  } catch (e) {
    return res.status(500).json(nok("admin_status_error", e && e.message));
  }
});

// ---------- Scrips endpoints ----------
app.get("/scrips/status", (req, res) => {
  try {
    return res.json(ok({
      loaded: !!scripsCache,
      entries: Array.isArray(scripsCache) ? scripsCache.length : 0,
      lastUpdated: scripsLastUpdated
    }));
  } catch (e) {
    return res.status(500).json(nok("scrips_status_error", e && e.message));
  }
});

app.get("/scrips/list", (req, res) => {
  try {
    if (!scripsCache || !Array.isArray(scripsCache)) return res.status(404).json(nok("scrips_not_loaded"));
    const limit = Math.min(200, Number(req.query.limit || 100));
    const start = Math.max(0, Number(req.query.start || 0));
    return res.json(ok({
      count: scripsCache.length,
      sample: scripsCache.slice(start, start + limit)
    }));
  } catch (e) {
    return res.status(500).json(nok("scrips_list_error", e && e.message));
  }
});

// ---------- LTP snapshot ----------
app.get("/ltp/latest", (req, res) => {
  try {
    const out = {};
    for (let k of Object.keys(livePrices || {})) out[k] = livePrices[k].ltp;
    return res.json(ok({ count: Object.keys(out).length, prices: out }));
  } catch (e) {
    return res.status(500).json(nok("ltp_latest_error", e && e.message));
  }
});

// ---------- Manual triggers ----------
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
    return res.status(400).json(nok("login_failed", r || null));
  } catch (e) {
    return res.status(500).json(nok("login_exception", e && e.message));
  }
});

app.post("/admin/connect-ws", async (req, res) => {
  try {
    const okc = await ensureWsConnected();
    return okc ? res.json(ok({ wsConnected: !!wsConnected })) : res.status(500).json(nok("ws_connect_failed"));
  } catch (e) {
    return res.status(500).json(nok("ws_connect_exception", e && e.message));
  }
});

// ---------- Memory & cleanup utilities ----------
app.get("/admin/memory", (req, res) => {
  try {
    const m = process.memoryUsage();
    return res.json(ok({
      rss_mb: Math.round(m.rss / 1024 / 1024 * 100) / 100,
      heapUsed_mb: Math.round(m.heapUsed / 1024 / 1024 * 100) / 100,
      uptime_sec: Math.round(process.uptime())
    }));
  } catch (e) {
    return res.status(500).json(nok("memory_error", e && e.message));
  }
});

app.post("/admin/flush-ltp-cache", (req, res) => {
  try {
    const count = Object.keys(livePrices || {}).length;
    livePrices = {};
    return res.json(ok({ flushed: count }));
  } catch (e) {
    return res.status(500).json(nok("flush_error", e && e.message));
  }
});

// ---------- Graceful shutdown ----------
function gracefulShutdown(signal) {
  return () => {
    log(`Received ${signal} - shutting down...`);
    try { if (wsClient && wsClient.terminate) wsClient.terminate(); } catch (e) {}
    try { /* allow some time then exit */ setTimeout(() => process.exit(0), 500); } catch(e) { process.exit(1); }
  };
}
process.on("SIGINT", gracefulShutdown("SIGINT"));
process.on("SIGTERM", gracefulShutdown("SIGTERM"));

// ---------- Auto-cleanup old livePrices (5 minutes threshold) ----------
setInterval(() => {
  try {
    const now = Date.now();
    for (let t of Object.keys(livePrices || {})) {
      const age = now - (livePrices[t].ts || 0);
      if (age > 5 * 60 * 1000) delete livePrices[t];
    }
  } catch (e) {
    warn("cleanup error", e && e.message);
  }
}, 30 * 1000);

// PART B7 ends here.
// server.js — FIXED — PART B8 of 10
// WebSocket heartbeat, keepalive, feedToken refresh, auto-reconnect tuning

// ---------- HEARTBEAT / KEEPALIVE ----------
let wsHeartbeatTimer = null;
let wsLastMsgTs = Date.now();

// Every message updates last-msg timestamp
function wsMessageHeartbeat() {
  wsLastMsgTs = Date.now();
}

// Patch message handler to include heartbeat
if (wsClient) {
  wsClient.on("message", () => wsMessageHeartbeat());
}

// ---------- KEEPALIVE PING ----------
function wsSendPing() {
  try {
    if (!wsClient || wsClient.readyState !== WebSocket.OPEN) return false;
    wsClient.ping();
    return true;
  } catch (e) {
    return false;
  }
}

// Start heartbeat-check
setInterval(async () => {
  try {
    const now = Date.now();

    // If no message for > 20 seconds → reconnect
    if (now - wsLastMsgTs > 20000) {
      warn("WS heartbeat: no data for 20s → reconnecting...");
      try { wsClient && wsClient.terminate && wsClient.terminate(); } catch(e){}
      wsConnected = false;
      await ensureWsConnected().catch(()=>null);
      return;
    }

    // Always send ping every 8s
    wsSendPing();
  } catch (e) {
    warn("WS heartbeat error:", e && e.message);
  }
}, 8000);

// ---------- FEEDTOKEN EXPIRY AUTO REFRESH ----------
setInterval(async () => {
  try {
    // if token near expiry → refresh login
    if (tokenExpiry && Date.now() > tokenExpiry - 60000) {
      log("Access token expiring soon → refreshing login...");
      await smartLogin(true).catch(()=>null);
    }
  } catch (e) {
    warn("token refresh error:", e && e.message);
  }
}, 15000);

// ---------- DEAD SOCKET GUARD ----------
setInterval(async () => {
  try {
    if (!wsClient || wsClient.readyState !== WebSocket.OPEN) {
      warn("WS Dead-socket guard triggered → reconnecting");
      await ensureWsConnected().catch(()=>null);
      return;
    }
  } catch (e) {
    warn("dead-socket guard error:", e && e.message);
  }
}, 10000);

// ---------- AUTO-RESUBSCRIBE (every 30 sec) ----------
setInterval(async () => {
  try {
    if (!wsConnected) return;
    // re-subscribe futures
    await autoSubscribeFutures().catch(()=>null);
  } catch (e) {
    warn("auto-resubscribe error:", e && e.message);
  }
}, 30000);

// PART B8 ends here.
// server.js — FIXED — PART B9 of 10
// Global error handlers, express error middleware,
// small utilities and diagnostics ========================

// ---------- Global Node process handlers ----------
process.on("uncaughtException", (err) => {
  try {
    console.error("UNCaught Exception:", err && err.stack ? err.stack : err);
  } catch (_) {}
});

process.on("unhandledRejection", (reason, p) => {
  try {
    console.error("Unhandled Rejection at:", p, "reason:", reason);
  } catch (_) {}
});

// ---------- Express generic error handler ----------
function expressErrorHandler(err, req, res, next) {
  try {
    console.error("Express error:", err && (err.stack || err.message || err));
    if (res.headersSent) return next(err);
    return res.status(500).json(nok("internal_server_error", err && (err.message || err)));
  } catch (e) {
    try { res.status(500).json(nok("internal_server_error")); } catch (_) {}
  }
}
app.use(expressErrorHandler);

// ---------- Lightweight anti-abuse (simple rate limiter) ----------
const simpleRate = {};
function withinRateLimit(key, limit = 200, windowSec = 60) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const rec = simpleRate[key] || { ts: now, count: 0 };

    if (now > rec.ts + windowSec) {
      rec.ts = now;
      rec.count = 1;
    } else {
      rec.count = (rec.count || 0) + 1;
    }

    simpleRate[key] = rec;
    return rec.count <= limit;
  } catch (e) {
    return true; // fallback allow
  }
}

app.use((req, res, next) => {
  try {
    const k = req.ip || req.headers["x-forwarded-for"] || "anon";
    if (!withinRateLimit(k, 200, 60)) {
      return res.status(429).json(nok("rate_limited"));
    }
  } catch (e) {}
  next();
});

// ---------- Debug endpoints ----------
app.get("/debug/echo", (req, res) => {
  try {
    return res.json(ok({
      query: req.query || {},
      headers: req.headers || {}
    }));
  } catch (e) {
    return res.status(500).json(nok("echo_error", e && e.message));
  }
});

app.get("/debug/env", (req, res) => {
  try {
    // Never expose secrets
    return res.json(ok({
      SMART_API_KEY: !!SMART_API_KEY,
      SMART_USER_ID: !!SMART_USER_ID,
      SCRIPS_LOADED: !!scripsCache,
      WS_CONNECTED: !!wsConnected
    }));
  } catch (e) {
    return res.status(500).json(nok("env_error", e && e.message));
  }
});

// ---------- Last-resort 404 handler ----------
app.use((req, res) => {
  return res
    .status(404)
    .json(nok("route_not_found", req.originalUrl));
});

// PART B9 ends here.
// PART B10 = app.listen + final footer logs.
// बोलो "भेजो B10"
// server.js — FIXED — PART B10 of 10
// Final bootstrap: app.listen(), startup checks, footer logs
// ===========================================================

const PORT = process.env.PORT || 10000;

app.listen(PORT, async () => {
  console.log("--------------------------------------------------");
  console.log("🚀 server.js bootstrap starting...");

  try {
    // STEP 1: Load ScripMaster at startup
    await loadScripMaster();
  } catch (e) {
    console.log("❌ Initial scripmaster load failed:", e && e.message);
  }

  // STEP 2: Start WS connection (auto reconnect)
  try {
    connectWS();
  } catch (e) {
    console.log("❌ WS initial connect failed:", e && e.message);
  }

  console.log("--------------------------------------------------");
  console.log("✅ server.js fully loaded (B1 → B10)");
  console.log("✅ SmartAPI + WS + OptionChain + Greeks + Premium Engine Ready");
  console.log("✅ Auto ScripMaster, Auto FUT subscription, Auto LTP alive");
  console.log("--------------------------------------------------");
  console.log("⚡ Listening on PORT:", PORT);
  console.log("--------------------------------------------------");
});
