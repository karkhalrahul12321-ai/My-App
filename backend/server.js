// server.js - CLEAN, OPTIMIZED, MERGED (Part-1 of 8)
// Dependencies required: express body-parser dotenv node-fetch@2 ws unzipper
// npm i express body-parser dotenv node-fetch@2 ws unzipper

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
require("dotenv").config();
const crypto = require("crypto");
const fetch = require("node-fetch");
const unzipper = require("unzipper");
const WebSocket = require("ws");

// ---------- Basic app ----------
const app = express();
app.use(bodyParser.json());
app.get("/_health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// ---------- ENV / Config (only 4 user-provided keys required) ----------
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// internal defaults (no need to set in env)
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com";
const SMARTAPI_WS_BASE = "wss://smartapisocket.angelone.in/smart-stream";
const SCRIP_MASTER_ZIP_URL = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.zip";
const DOWNLOAD_RETRY_MAX = 5;
const OPT_FEATURE_POLL_MS = 5000;
const PORT = process.env.PORT || 10000;
const DAILY_REFRESH_HOUR = 5;

// ---------- Globals ----------
let session = { access_token: null, refresh_token: null, feed_token: null, expires_at: 0 };
let SCRIPS = [];
let INSTR_INDEX_BY_SYMBOL = {};
let INSTR_INDEX_BY_MARKET = {};
let latestLtp = null;
let wsClient = null;
let wsConnected = false;
let wsReconnectTimer = null;
let pollIntervalHandle = null;

// Default AUTO tokens fallback (will be updated by autoFetchFuture)
const AUTO = {
  nifty: { symbol: "NIFTY30DEC25FUT", token: "36688", expiry: "2025-12-30" },
  sensex: { symbol: "SENSEX50DEC25FUT", token: "1104398", expiry: "2025-12-24" },
  "natural gas": { symbol: "NATURALGAS26DEC25FUT", token: "463007", expiry: "2025-12-26" }
};

// writeable locations for scrip master
const WRITE_PATHS = [
  path.join(__dirname, "scrip_master.json"),
  path.join("/mnt/data", "scrip_master.json"),
  path.join(__dirname, "..", "backend", "scrip_master.json")
];

// ---------- small helpers ----------
function num(v, d = 0) { const n = Number(v); return Number.isFinite(n) ? n : d; }
function fmtDate(d) { return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; }

// ---------- TOTP helpers ----------
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
  if (!secret) return null;
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

// ---------- SmartAPI login helper ----------
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) return { ok: false, reason: "ENV_MISSING" };
  if (!tradingPassword) return { ok: false, reason: "PASSWORD_MISSING" };
  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);
    const resp = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
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
      body: JSON.stringify({ clientcode: SMART_USER_ID, password: tradingPassword, totp })
    });
    const data = await resp.json().catch(() => null);
    if (!data || data.status === false) return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + (20 * 60 * 60 * 1000);
    return { ok: true, raw: d };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}
// Part-2 (of 8) - Scrip master load/save/parse + indexer + download
// ---------- Scrip master: save/load/parse ----------
function saveScripJson(jsonArr) {
  for (const p of WRITE_PATHS) {
    try {
      const dir = path.dirname(p);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(p, JSON.stringify(jsonArr, null, 2), "utf8");
      console.log("Scrip master saved to:", p);
      break;
    } catch (e) {
      console.log("saveScripJson failed:", p, e.message);
    }
  }
}
function loadScripMasterFromDisk() {
  for (const p of WRITE_PATHS) {
    try {
      if (fs.existsSync(p)) {
        const txt = fs.readFileSync(p, "utf8");
        const arr = JSON.parse(txt);
        if (Array.isArray(arr) && arr.length) {
          SCRIPS = arr;
          indexScrips();
          console.log("Loaded scrip master from disk:", p, "records:", SCRIPS.length);
          return { ok: true, path: p, count: SCRIPS.length };
        }
      }
    } catch (e) {
      console.log("loadScripMasterFromDisk error", p, e.message);
    }
  }
  console.log("No scrip master found on disk");
  return { ok: false };
}
function parseCsvToRecords(csvText) {
  const lines = csvText.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return [];
  const header = lines[0].split(",").map(h => h.trim().toLowerCase());
  const out = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(",");
    if (!cols.some(c => c && c.trim())) continue;
    const rec = {};
    header.forEach((h, idx) => rec[h] = (cols[idx] || "").trim());
    const inst = {
      tradingsymbol: rec.tradingsymbol || rec.trading_symbol || rec.name || rec.symbol || rec['tradingsymbol'] || '',
      symboltoken: rec.symboltoken || rec.token || rec.instrument_token || rec['symboltoken'] || '',
      exch_seg: rec.exch_seg || rec.exchange || rec.exch || '',
      expirydate: rec.expirydate || rec.expiry || rec['expiry'] || '',
      instrumenttype: rec.instrumenttype || rec.instrument_type || rec.type || '',
      lotsize: Number(rec.lotsize || rec.lot_size || rec['lot_size'] || rec.lotsize || 1),
      strike: Number(rec.strike || 0),
      option_type: (rec.option_type || rec.opt_type || rec.optiontype || '').toUpperCase()
    };
    out.push(inst);
  }
  return out;
}
function indexScrips() {
  INSTR_INDEX_BY_SYMBOL = {};
  INSTR_INDEX_BY_MARKET = {};
  for (const it of SCRIPS) {
    if (!it || !it.tradingsymbol) continue;
    INSTR_INDEX_BY_SYMBOL[it.tradingsymbol] = it;
    const sym = (it.tradingsymbol || "").toUpperCase();
    let mk = null;
    if (sym.includes("NIFTY")) mk = 'nifty';
    else if (sym.includes("SENSEX")) mk = 'sensex';
    else if (sym.includes("NATURALGAS") || sym.includes("NATURAL GAS") || sym.includes("NATGAS")) mk = 'natural gas';
    else {
      const ex = (it.exch_seg || "").toUpperCase();
      if (ex.includes('NFO')) mk = 'nifty';
      if (ex.includes('BFO')) mk = 'sensex';
      if (ex.includes('MCX')) mk = 'natural gas';
    }
    if (mk) {
      if (!INSTR_INDEX_BY_MARKET[mk]) INSTR_INDEX_BY_MARKET[mk] = [];
      INSTR_INDEX_BY_MARKET[mk].push(it);
    }
  }
  console.log("Indexed markets:", Object.keys(INSTR_INDEX_BY_MARKET).map(k => `${k}:${INSTR_INDEX_BY_MARKET[k].length}`).join(", "));
}

// ---------- Download & process ScripMaster ZIP ----------
async function downloadAndProcessScripMaster(url, maxRetries = DOWNLOAD_RETRY_MAX) {
  console.log("Attempting download of scrip master:", url);
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const buf = await resp.buffer();
      const directory = await unzipper.Open.buffer(buf);
      const accumulated = [];
      for (const entry of directory.files) {
        if (!entry.path.toLowerCase().endsWith(".csv")) continue;
        try {
          const contentBuf = await entry.buffer();
          const text = contentBuf.toString("utf8");
          const records = parseCsvToRecords(text);
          for (const r of records) accumulated.push(r);
          console.log(`Parsed ${records.length} records from ${entry.path}`);
        } catch (e) {
          console.log("entry parse error", e.message);
        }
      }
      if (!accumulated.length) throw new Error("No CSV records found in zip");
      SCRIPS = accumulated;
      indexScrips();
      saveScripJson(SCRIPS);
      console.log("Scrip master processed ok, total records:", SCRIPS.length);
      return { ok: true, count: SCRIPS.length };
    } catch (err) {
      console.log(`Download attempt ${attempt} failed:`, err.message);
      if (attempt < maxRetries) {
        const wait = Math.min(30000, 1000 * Math.pow(2, attempt));
        console.log(`Retrying in ${wait}ms...`);
        await new Promise(r => setTimeout(r, wait));
        continue;
      } else {
        console.log("All download attempts failed.");
        return { ok: false, error: err.message };
      }
    }
  }
}
// Part-3 (of 8) - Smart search + auto future detection + ws/http LTP logic
const FUTURE_RULES = {
  nifty: { searchSymbol: "NIFTY", exchange: "NFO", instrumentType: "FUTIDX", expiryDay: 4 },
  sensex: { searchSymbol: "SENSEX", exchange: "BFO", instrumentType: "FUTIDX", expiryDay: 4 },
  "natural gas": { searchSymbol: "NATURALGAS", exchange: "MCX", instrumentType: "FUTCOM", expiryDay: null }
};
async function smartSearch(keyword) {
  if (!session.access_token) return [];
  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/searchScrip`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "X-PrivateKey": SMART_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ searchtext: keyword })
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) { return []; }
    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    console.log("smartSearch err", err.message);
    return [];
  }
}
function getNextExpiries(market) {
  const rule = FUTURE_RULES[market];
  const today = new Date(); const expiries = [];
  if (!rule) return expiries;
  if (market === "natural gas") {
    for (let i = 0; i < 3; i++) { const dt = new Date(today.getFullYear(), today.getMonth() + i, 25); expiries.push(fmtDate(dt)); }
  } else {
    for (let i = 0; i < 4; i++) {
      const dt = new Date(); dt.setDate(today.getDate() + i * 7);
      while (dt.getDay() !== rule.expiryDay) dt.setDate(dt.getDate() + 1);
      expiries.push(fmtDate(dt));
    }
  }
  return expiries;
}
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market]; if (!rule) return null;
  const expiries = getNextExpiries(market);
  const all = await smartSearch(rule.searchSymbol);
  if (!all || !all.length) { return AUTO[market]; }
  for (const exp of expiries) {
    const [y, m, d] = exp.split("-");
    const match = all.find(x => {
      const sameExchange = (x.exch_seg || "").toUpperCase() === rule.exchange.toUpperCase();
      const sameType = (x.instrumenttype || "").toUpperCase() === rule.instrumentType.toUpperCase();
      const expStr = (x.expirydate || "").toString();
      const sameExpiry = expStr.includes(`${y}-${m}-${d}`);
      return sameExchange && sameType && sameExpiry;
    });
    if (match) { AUTO[market] = { symbol: match.tradingsymbol, token: match.symboltoken, expiry: match.expirydate }; return AUTO[market]; }
  }
  return AUTO[market];
}

// ---------- LTP WS/HTTP logic ----------
function buildSmartApiWsUrl() {
  const clientCode = SMART_USER_ID || "";
  const feedToken = session.feed_token || "";
  const apiKey = SMART_API_KEY || "";
  if (!clientCode || !feedToken || !apiKey) return SMARTAPI_WS_BASE;
  return `${SMARTAPI_WS_BASE}?clientCode=${encodeURIComponent(clientCode)}&feedToken=${encodeURIComponent(feedToken)}&apiKey=${encodeURIComponent(apiKey)}`;
}
async function getAutoFutureLTP(market) {
  const cfgMap = { nifty: { exchange: "NFO" }, sensex: { exchange: "BFO" }, "natural gas": { exchange: "MCX" } };
  const cfg = cfgMap[market];
  if (!cfg) return { ok: false, reason: "NO_MARKET_CFG" };
  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };
  const auto = AUTO[market];
  if (!auto || !auto.token) return { ok: false, reason: "TOKEN_NOT_FOUND", auto };
  try {
    const exchangeTokens = {}; exchangeTokens[cfg.exchange] = [String(auto.token)];
    const body = { mode: "LTP", exchangeTokens };
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "X-PrivateKey": SMART_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) { return { ok: false, reason: "JSON_PARSE_ERROR", raw: text }; }
    if (!data || data.status === false) return { ok: false, reason: "LTP_FAILED", detail: data };
    let ltpVal = null;
    if (data.data) {
      if (Array.isArray(data.data.fetched) && data.data.fetched[0]) ltpVal = data.data.fetched[0].ltp || data.data.fetched[0].last_traded_price || null;
      else if (Array.isArray(data.data) && data.data[0]) ltpVal = data.data[0].ltp || data.data[0].last_traded_price || null;
      else if (data.data.ltp) ltpVal = data.data.ltp;
    }
    if (!ltpVal) return { ok: false, reason: "NO_LTP", detail: data };
    return { ok: true, ltp: ltpVal, response: data };
  } catch (e) { return { ok: false, reason: "EXCEPTION", error: e.message }; }
}

function startHttpPollFallback(market = "nifty", pollIntervalMs = OPT_FEATURE_POLL_MS) {
  if (pollIntervalHandle) return;
  (async () => { const r = await getAutoFutureLTP(market); if (r.ok && r.ltp) latestLtp = num(r.ltp); })();
  pollIntervalHandle = setInterval(async () => { const r = await getAutoFutureLTP(market); if (r.ok && r.ltp) latestLtp = num(r.ltp); }, pollIntervalMs);
}

async function startWsLtpEnhanced(market = "nifty", pollIntervalMs = OPT_FEATURE_POLL_MS) {
  const wsUrl = buildSmartApiWsUrl();
  if (!wsUrl) { console.log("WS LTP: missing ws url -> using HTTP fallback"); startHttpPollFallback(market, pollIntervalMs); return; }
  try {
    if (wsClient) try { wsClient.terminate(); } catch (e) { }
    wsClient = new WebSocket(wsUrl);
    wsClient.on("open", () => {
      wsConnected = true;
      console.log("WS connected to", wsUrl);
      const tokens = [String(AUTO.nifty.token), String(AUTO.sensex.token), String(AUTO['natural gas'].token)].filter(Boolean);
      if (tokens.length) {
        const subscribePayload = JSON.stringify({ message_type: "subscribe", exchange: "ALL", token: tokens });
        try { wsClient.send(subscribePayload); console.log("WS subscribe sent", subscribePayload); } catch (e) { console.log("WS subscribe send error", e.message); }
      } else console.log("WS no tokens to subscribe");
    });
    wsClient.on("message", data => {
      try {
        const msg = (typeof data === "string") ? JSON.parse(data) : data;
        if (msg && msg.data) {
          if (Array.isArray(msg.data) && msg.data[0] && (msg.data[0].ltp || msg.data[0].last_traded_price)) latestLtp = num(msg.data[0].ltp || msg.data[0].last_traded_price);
          else if (msg.data.ltp) latestLtp = num(msg.data.ltp);
        } else if (msg && msg.payload && msg.payload.ltp) latestLtp = num(msg.payload.ltp);
        else if (msg && msg.ltp) latestLtp = num(msg.ltp);
      } catch (e) { /* ignore parse errors */ }
    });
    wsClient.on("close", () => {
      wsConnected = false;
      console.log("WS closed -> switching to HTTP fallback");
      startHttpPollFallback(market, pollIntervalMs);
      if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
      wsReconnectTimer = setTimeout(() => startWsLtpEnhanced(market, pollIntervalMs), 5000);
    });
    wsClient.on("error", err => {
      console.log("WS error", err && (err.message || err));
      try { wsClient.terminate(); } catch (e) { }
    });
  } catch (e) {
    console.log("startWsLtpEnhanced exception", e.message);
    startHttpPollFallback(market, pollIntervalMs);
  }
}
// Part-4 (of 8) - Startup actions + daily refresh scheduler + simple endpoints
loadScripMasterFromDisk();

(async () => {
  try {
    const dl = await downloadAndProcessScripMaster(SCRIP_MASTER_ZIP_URL, 3);
    if (!dl.ok) console.log("Startup scrip download failed (will continue with disk copy if any):", dl.error);
    for (const m of Object.keys(FUTURE_RULES)) {
      try { await autoFetchFuture(m); } catch (e) { console.log("autoFetchFuture error", m, e.message); }
    }
  } catch (e) {
    console.log("startup scrip download exception", e.message);
  }
  startWsLtpEnhanced("nifty", OPT_FEATURE_POLL_MS);
})();

function scheduleDailyRefresh(hourOfDay = DAILY_REFRESH_HOUR) {
  function msUntilNextRun() {
    const now = new Date();
    const next = new Date(now.getFullYear(), now.getMonth(), now.getDate(), hourOfDay, 0, 0, 0);
    if (next <= now) next.setDate(next.getDate() + 1);
    return next - now;
  }
  async function runOnce() {
    console.log("Daily refresh running scrip master download now");
    const r = await downloadAndProcessScripMaster(SCRIP_MASTER_ZIP_URL, 4);
    if (!r.ok) console.log("Daily refresh download failed:", r.error);
    else console.log("Daily refresh successful:", r.count, "records");
    setTimeout(runOnce, msUntilNextRun());
  }
  setTimeout(runOnce, msUntilNextRun());
}
scheduleDailyRefresh(DAILY_REFRESH_HOUR);

// ---------- Small test endpoints ----------
app.get("/api/ltp/latest", (req, res) => res.json({ success: true, ltp: latestLtp, ws_connected: wsConnected, feed_token: session.feed_token || null }));
app.get("/api/scrips/status", (req, res) => res.json({ success: true, scrip_count: SCRIPS.length, markets_indexed: Object.keys(INSTR_INDEX_BY_MARKET), auto_tokens: AUTO }));
app.get("/api/future-ltp", async (req, res) => {
  try {
    const markets = Object.keys(AUTO);
    const out = {};
    let usedLive = false;
    for (const m of markets) {
      let ltp = null;
      if (wsConnected && latestLtp) { ltp = latestLtp; usedLive = true; }
      if (!ltp) {
        const r = await getAutoFutureLTP(m);
        if (r && r.ok && r.ltp) { ltp = num(r.ltp); }
      }
      out[m] = { symbol: AUTO[m].symbol, token: AUTO[m].token, expiry: AUTO[m].expiry, ltp: ltp || null };
    }
    return res.json({ success: true, ws_connected: wsConnected, live_used: usedLive, data: out });
  } catch (e) {
    return res.json({ success: false, error: e.message });
  }
});
// Part-5 (of 8) - Option chain helpers + Greeks + strike LTP
// ---------- PART-2 functions integrated ----------
// Market resolver, ATM strike, 3-strike picker, fetchGreeks, getStrikeLTP, buildStrikeData
function resolveMarket(m) {
  if (!m) return null;
  m = m.toString().trim().toLowerCase();
  if (m.includes("nif")) return "nifty";
  if (m.includes("sen")) return "sensex";
  if (m.includes("gas") || m.includes("nat")) return "natural gas";
  return null;
}
function findATMStrike(price, step = 50) { const p = Number(price); return Math.round(p / step) * step; }
function get3Strikes(price, step = 50) { const atm = findATMStrike(price, step); return [atm, atm + step, atm - step].sort((a, b) => a - b); }
function pickCEPE(records) {
  let CE = null, PE = null;
  for (const r of records) {
    const opt = (r.option_type || "").toUpperCase();
    if (opt === "CE") CE = r;
    if (opt === "PE") PE = r;
  }
  return { CE, PE };
}
async function fetchGreeks(symbol, expiry) {
  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };
  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/marketData/v1/optionGreek`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${session.access_token}`, "X-PrivateKey": SMART_API_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ name: symbol, expirydate: expiry })
      }
    );
    const text = await resp.text();
    let json = null;
    try { json = JSON.parse(text); } catch (e) { return { ok:false, reason:"JSON_PARSE", raw:text }; }
    if (!json || json.status === false) return { ok:false, reason:"API_FAIL", raw:json };
    return { ok:true, data:json.data };
  } catch (err) { return { ok:false, error:err.message }; }
}
async function getStrikeLTP(exch, token) {
  if (!session.access_token) return null;
  try {
    const body = { mode: "LTP", exchangeTokens: { [exch]: [String(token)] } };
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`, {
      method: "POST",
      headers: { Authorization:`Bearer ${session.access_token}`, "X-PrivateKey":SMART_API_KEY, "Content-Type":"application/json" },
      body: JSON.stringify(body)
    });
    const text = await resp.text();
    let json = null;
    try { json = JSON.parse(text); } catch(e){ return null; }
    if (!json || json.status === false) return null;
    let ltp = null;
    if (json.data) {
      if (Array.isArray(json.data.fetched) && json.data.fetched[0]) ltp = json.data.fetched[0].ltp || json.data.fetched[0].last_traded_price;
      else if (json.data.ltp) ltp = json.data.ltp;
    }
    return Number(ltp) || null;
  } catch (e) { return null; }
}
async function buildStrikeData(recordCE, recordPE) {
  const out = { CE:null, PE:null };
  if (recordCE) {
    const exch = recordCE.exch_seg;
    const tok = recordCE.symboltoken;
    const ltp = await getStrikeLTP(exch, tok);
    out.CE = { tradingSymbol: recordCE.tradingsymbol, token: tok, ltp: ltp, strike: recordCE.strike, expiry: recordCE.expirydate };
  }
  if (recordPE) {
    const exch = recordPE.exch_seg;
    const tok = recordPE.symboltoken;
    const ltp = await getStrikeLTP(exch, tok);
    out.PE = { tradingSymbol: recordPE.tradingsymbol, token: tok, ltp: ltp, strike: recordPE.strike, expiry: recordPE.expirydate };
  }
  return out;
}

// ---------- /api/option-chain ----------
app.post("/api/option-chain", async (req, res) => {
  try {
    let { market, spot } = req.body;
    market = resolveMarket(market);
    if (!market) return res.json({ success:false, error:"INVALID_MARKET" });
    spot = Number(spot);
    if (!spot) return res.json({ success:false, error:"INVALID_SPOT" });
    const futureMeta = AUTO[market];
    const expiry = futureMeta.expiry || "";
    const strikes = get3Strikes(spot, market === "natural gas" ? 5 : 50);
    const chain = [];
    for (const st of strikes) {
      const list = (INSTR_INDEX_BY_MARKET[market] || []).filter(x => Number(x.strike) === Number(st) && (x.expirydate || "").startsWith(expiry));
      const { CE, PE } = pickCEPE(list);
      const oc = await buildStrikeData(CE, PE);
      chain.push(oc);
    }
    return res.json({ success: true, market, expiry, strikes: strikes, chain });
  } catch (err) { return res.json({ success:false, error:err.message }); }
});

// ---------- /api/greeks ----------
app.post("/api/greeks", async (req, res) => {
  let { market } = req.body;
  market = resolveMarket(market);
  if (!market) return res.json({ success:false, error:"INVALID_MARKET" });
  const symbol = (AUTO[market].symbol || "").split("FUT")[0];
  const expiry = AUTO[market].expiry || "";
  const g = await fetchGreeks(symbol, expiry);
  return res.json(g);
});
// Part-6 (of 8) - Trend engine + premium engine + full-analysis
function computeTrend(ema20, ema50, rsi, vwap, spot) {
  const diff = (ema20 - ema50);
  const gapPct = (Math.abs(diff) / Math.max(1, Math.abs(ema50))) * 100;
  let main = "SIDEWAYS", strength = "RANGE", bias = "NONE";
  if (gapPct > 0.6 && ema20 > ema50) { main = "UP"; bias = "BULL"; strength = gapPct > 1.5 ? "TREND" : "TRENDING"; }
  else if (gapPct > 0.6 && ema20 < ema50) { main = "DOWN"; bias = "BEAR"; strength = gapPct > 1.5 ? "TREND" : "TRENDING"; }
  else { main = "SIDEWAYS"; bias = "NONE"; strength = "RANGE"; }
  const score = Math.round((Math.min(100, Math.abs(rsi - 50) * 1.5) + Math.min(100, gapPct * 10)) / 2 * 100) / 100;
  const components = {
    ema_gap: `${gapPct.toFixed(2)}%`,
    rsi: `RSI ${rsi} (${rsi > 60 ? "high" : (rsi < 40 ? "low" : "neutral")})`,
    vwap: (spot > vwap) ? `Above VWAP (${((spot - vwap) / Math.max(1, vwap) * 100).toFixed(2)}%)` : `Below VWAP (${((vwap - spot) / Math.max(1, vwap) * 100).toFixed(2)}%)`,
    price_structure: main === "SIDEWAYS" ? "Mixed structure" : `${main} structure`,
    expiry: "Expiry mid"
  };
  const comment = `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`;
  return { main, strength, score, bias, components, comment };
}
function computePremiumPlan(distance) {
  let entry = 10, sl = 6, target = 15;
  if (distance <= 10) { entry = 5; sl = 3; target = 8; }
  else if (distance <= 50) { entry = 10; sl = 6; target = 15; }
  else if (distance > 80) { entry = 8; sl = 5; target = 12; }
  return { distance, entry, stopLoss: sl, target };
}

// ---------- Endpoint: Future LTP (market wise) ----------
app.get("/api/future-ltp", async (req, res) => {
  try {
    const markets = Object.keys(AUTO);
    const out = {};
    let usedLive = false;
    for (const m of markets) {
      let ltp = null;
      if (wsConnected && latestLtp) { ltp = latestLtp; usedLive = true; }
      if (!ltp) {
        const r = await getAutoFutureLTP(m);
        if (r && r.ok && r.ltp) { ltp = num(r.ltp); }
      }
      out[m] = { symbol: AUTO[m].symbol, token: AUTO[m].token, expiry: AUTO[m].expiry, ltp: ltp || null };
    }
    return res.json({ success: true, ws_connected: wsConnected, live_used: usedLive, data: out });
  } catch (e) {
    return res.json({ success: false, error: e.message });
  }
});

// ---------- Endpoint: Full Analysis (front-end compatible) ----------
app.post("/api/full-analysis", async (req, res) => {
  try {
    // Accept inputs
    let {
      ema20,
      ema50,
      rsi,
      vwap,
      spot,
      market,
      expiry_days,
      use_live
    } = req.body || {};

    // Basic validation/coercion
    ema20 = num(ema20, 0);
    ema50 = num(ema50, 0);
    rsi = Number(rsi) || 0;
    vwap = num(vwap, 0);
    spot = num(spot, 0);
    expiry_days = Number(expiry_days) || 0;
    market = resolveMarket(market) || "nifty";
    use_live = !!use_live;

    // 1) Trend analysis (local calculation)
    const trend = computeTrend(ema20, ema50, rsi, vwap, spot);

    // 2) Ensure AUTO token info up-to-date (try autoFetchFuture if expiry unknown)
    try {
      if (!AUTO[market] || !AUTO[market].token) {
        await autoFetchFuture(market);
      }
    } catch (e) { /* ignore */ }

    // 3) Live LTP selection
    let live_ltp = null;
    let live_data_used = false;
    if (use_live && wsConnected && latestLtp) {
      live_ltp = latestLtp;
      live_data_used = true;
    } else if (use_live) {
      // try HTTP fallback for market future
      const r = await getAutoFutureLTP(market);
      if (r && r.ok && r.ltp) { live_ltp = num(r.ltp); live_data_used = true; }
    }
    if (!live_ltp) live_ltp = spot || AUTO[market].last_known || null;

    // 4) Determine strikes (3 strikes around chosen price)
    const strikeStep = (market === "natural gas") ? 5 : 50; // Natural gas smaller step
    const basePrice = live_ltp || spot || (EMA := ema20) || 0;
    const strikesArr = get3Strikes(basePrice, strikeStep);

    // 5) For each strike, build option chain (CE/PE) using buildStrikeData (uses HTTP fallback)
    const chainPromises = strikesArr.map(async (st) => {
      // find records by matching strike and expiry (use AUTO[market].expiry)
      const expiry = AUTO[market].expiry || "";
      const list = (INSTR_INDEX_BY_MARKET[market] || []).filter(it => Number(it.strike) === Number(st) && (it.expirydate || "").startsWith((expiry || "").toString()));
      const { CE, PE } = pickCEPE(list);
      const built = await buildStrikeData(CE, PE); // returns CE and PE with ltp
      // compute premium plan for distance
      const distance = Math.abs(Number(basePrice) - Number(st));
      const plan = computePremiumPlan(distance);
      return {
        strike: st,
        distance,
        plan,
        data: built
      };
    });

    const chain = await Promise.all(chainPromises);
// Part-7 (of 8) - continue full-analysis response composition
    // 6) Build strikes summary response in your old format (CE, PE, STRADDLE)
    // We'll create top-level strike suggestions: CE (higher), PE (lower), STRADDLE (ATM)
    const sortedStrikes = [...strikesArr].sort((a, b) => a - b);
    const atm = sortedStrikes[1]; // middle element
    const ceStrike = sortedStrikes[2]; // higher
    const peStrike = sortedStrikes[0]; // lower

    // Helper: find in chain
    const findByStrike = (s) => chain.find(ch => Number(ch.strike) === Number(s)) || null;

    const ceData = findByStrike(ceStrike);
    const peData = findByStrike(peStrike);
    const straddleData = findByStrike(atm);

    // Compose UI-friendly strike objects
    const strikesOut = [
      ceData ? { type: "CE", strike: ceStrike, distance: ceData.distance, entry: ceData.plan.entry, stopLoss: ceData.plan.stopLoss, target: ceData.plan.target } : null,
      peData ? { type: "PE", strike: peStrike, distance: peData.distance, entry: peData.plan.entry, stopLoss: peData.plan.stopLoss, target: peData.plan.target } : null,
      straddleData ? { type: "STRADDLE", strike: atm, distance: straddleData.distance, entry: straddleData.plan.entry, stopLoss: straddleData.plan.stopLoss, target: straddleData.plan.target } : null
    ].filter(Boolean);

    // 7) Greeks: fetch for underlying name if available
    let greeksResp = { ok: false };
    try {
      const fut = AUTO[market] && AUTO[market].symbol ? AUTO[market].symbol.replace(/FUT.*$/i, "").trim() : null;
      const expiry = AUTO[market] && AUTO[market].expiry ? AUTO[market].expiry : null;
      if (fut && expiry) greeksResp = await fetchGreeks(fut, expiry);
    } catch (e) { greeksResp = { ok:false, error:e.message }; }

    // 8) Build response JSON
    const response = {
      success: true,
      message: "Calculation complete",
      login_status: session.access_token ? "SmartAPI Logged-In" : "Not Logged-In",
      input: {
        ema20, ema50, rsi, vwap, spot: basePrice, market, expiry_days, use_live
      },
      trend: {
        main: trend.main,
        strength: trend.strength,
        score: trend.score,
        bias: trend.bias,
        components: trend.components,
        comment: trend.comment
      },
      strikes: strikesOut,
      chain, // detailed per-strike CE/PE data
      greeks: greeksResp.ok ? greeksResp.data : null,
      auto_tokens: AUTO,
      meta: {
        live_data_used,
        live_ltp: live_ltp || null,
        ws_connected: !!wsConnected,
        live_error: null
      }
    };

    return res.json(response);

  } catch (err) {
    return res.json({ success:false, error: err.message });
  }
});
// Part-8 (of 8) - Final cleanup + start server
// A couple of convenience endpoints to login and set trading password (optional)
app.post("/api/login", async (req, res) => {
  const { tradingPassword } = req.body || {};
  if (!tradingPassword) return res.json({ success:false, error:"NO_PASSWORD" });
  const r = await smartApiLogin(tradingPassword);
  if (!r.ok) return res.json({ success:false, error:r });
  // start ws if available
  try { startWsLtpEnhanced("nifty", OPT_FEATURE_POLL_MS); } catch(e){}
  return res.json({ success:true, data: r.raw });
});

// small utility: expose scrip master download trigger (manual)
app.post("/api/refresh-scrips", async (req, res) => {
  try {
    const r = await downloadAndProcessScripMaster(SCRIP_MASTER_ZIP_URL, 3);
    return res.json({ success: r.ok, count: r.count || 0, error: r.error || null });
  } catch (e) { return res.json({ success:false, error: e.message }); }
});

// graceful shutdown
process.on("SIGINT", () => { console.log("SIGINT, shutting down"); try { if (wsClient) wsClient.terminate(); } catch (e){} process.exit(0); });
process.on("SIGTERM", () => { console.log("SIGTERM, shutting down"); try { if (wsClient) wsClient.terminate(); } catch (e){} process.exit(0); });

// ---------- Start server ----------
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
