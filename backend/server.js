/* PART 1/10 — BASE IMPORTS + CONFIG + SESSION + LOGIN */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

// Global Master Data
global.instrumentMaster = [];

// Helper to handle symbol naming
global.tsof = function (entry) {
  return String(
    entry?.tradingsymbol ||
    entry?.symbol ||
    entry?.name ||
    ""
  ).toUpperCase();
};

const tsof = global.tsof;

// ऑनलाइन मास्टर डेटा लोड करने का फंक्शन (Price mismatch रोकने के लिए जरूरी)
async function loadMasterOnline() {
  try {
    const url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
    const r = await fetch(url);
    const j = await r.json().catch(() => []);
    if (Array.isArray(j) && j.length > 0) {
      global.instrumentMaster = j;
      console.log("✅ MASTER LOADED ONLINE. COUNT:", j.length);
    } else {
      console.log("❌ MASTER LOAD FAILED: EMPTY RESPONSE");
    }
  } catch (e) {
    console.log("❌ MASTER LOAD ERROR:", e);
  }
}

loadMasterOnline();
// हर 1 घंटे में अपडेट करें
setInterval(loadMasterOnline, 60 * 60 * 1000);

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ENV Variables
const SMART_API_KEY = process.env.SMART_API_KEY;
const CLIENT_ID = process.env.CLIENT_ID;
const PASSWORD = process.env.PASSWORD;
const TOTP_SECRET = process.env.TOTP_SECRET;
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com";

let session = {
  access_token: null,
  feed_token: null,
  lastLogin: 0
};

let wsClient = null;
let optionLTP = {}; 
let wsStatus = { connected: false };

async function getTOTP() {
  try {
    const otplib = require("otplib");
    return otplib.authenticator.generate(TOTP_SECRET);
  } catch (e) {
    console.error("TOTP Error:", e);
    return "";
  }
}
/* PART 2/10 — LOGIN & WEBSOCKET SYNC */

async function loginAngel() {
  try {
    const otp = await getTOTP();
    const r = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "00:00:00:00:00:00",
        "X-UserType": "USER",
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({ clientcode: CLIENT_ID, password: PASSWORD, totp: otp })
    });
    const j = await r.json();
    if (j.status && j.data) {
      session.access_token = j.data.jwtToken;
      session.feed_token = j.data.feedToken;
      session.lastLogin = Date.now();
      console.log("✅ LOGIN SUCCESSFUL");
      initWebSocket();
      return true;
    }
    return false;
  } catch (e) {
    console.error("❌ LOGIN ERROR:", e);
    return false;
  }
}

function initWebSocket() {
  if (!session.feed_token) return;
  if (wsClient) { wsClient.terminate(); }

  wsClient = new WebSocket("wss://smartapisockets.angelone.in/smart-stream", {
    headers: {
      "Authorization": "Bearer " + session.access_token,
      "x-api-key": SMART_API_KEY,
      "x-client-code": CLIENT_ID,
      "x-feed-token": session.feed_token
    }
  });

  wsClient.on("open", () => {
    wsStatus.connected = true;
    console.log("📡 WS CONNECTED");
  });

  wsClient.on("message", (data) => {
    try {
      const buf = Buffer.from(data);
      // Angel SmartStream Binary Parsing (Simplified for LTP)
      if (buf.length >= 43) {
        const token = buf.slice(2, 32).toString('utf8').replace(/\0/g, '');
        const ltp = buf.readInt32LE(43) / 100;
        optionLTP[token] = { ltp, time: Date.now() };
      }
    } catch (e) {}
  });

  wsClient.on("close", () => {
    wsStatus.connected = false;
    setTimeout(initWebSocket, 5000);
  });
}
/* PART 3/10 — TOKEN RESOLVER (STRATEGIC FIX) */

async function resolveInstrumentToken(symbol, expiry = "", strike = 0, type = "FUT") {
  try {
    let master = global.instrumentMaster;
    if (!master || master.length === 0) return null;

    const wantedSymbol = String(symbol).toUpperCase();
    const wantedType = type.toUpperCase();
    const wantedStrike = Number(strike);

    let exchange = "NFO";
    if (wantedSymbol.includes("SENSEX")) exchange = "BFO";
    if (["NATURALGAS", "CRUDEOIL", "GOLD", "SILVER"].includes(wantedSymbol)) exchange = "MCX";

    let candidates = master.filter(it => {
      if (it.exch_seg !== exchange) return false;
      const name = (it.name || "").toUpperCase();
      if (name !== wantedSymbol && it.symbol !== wantedSymbol) return false;
      const iType = (it.instrumenttype || "").toUpperCase();
      if (wantedType === "FUT" && !iType.includes("FUT")) return false;
      if ((wantedType === "CE" || wantedType === "PE") && !iType.includes("OPT")) return false;
      return true;
    });

    if (wantedType === "CE" || wantedType === "PE") {
      candidates = candidates.filter(it => {
        // Angel master data scaling fix: 2450000 -> 24500
        let itStrike = Number(it.strike) / 100;
        if (itStrike === 0 || itStrike > 200000) itStrike = Number(it.strike); 
        const typeMatch = it.symbol.endsWith(wantedType);
        return Math.abs(itStrike - wantedStrike) < 1 && typeMatch;
      });
    }

    if (expiry) {
      candidates = candidates.filter(it => it.expiry === expiry);
    } else {
      candidates.sort((a, b) => moment(a.expiry, "DDMMMYYYY").diff(moment(b.expiry, "DDMMMYYYY")));
    }

    return candidates.length > 0 ? candidates[0] : null;
  } catch (err) {
    return null;
  }
}
/* PART 4/10 — LTP & OPTION PRICE SYNC */

async function fetchLTP(symbol, token = null, exchange = "NSE") {
  try {
    if (!token) {
      const found = global.instrumentMaster.find(i => i.symbol === (symbol + "-EQ") || (i.name === symbol && i.exch_seg === "NSE"));
      token = found ? found.token : null;
    }
    if (!token) return null;

    const r = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`, {
      method: "POST",
      headers: { 
        "Authorization": `Bearer ${session.access_token}`, 
        "Content-Type": "application/json", 
        "X-PrivateKey": SMART_API_KEY, 
        "X-UserType": "USER", 
        "X-SourceID": "WEB" 
      },
      body: JSON.stringify({ mode: "LTP", exchangeTokens: { [exchange]: [token] } })
    });
    const j = await r.json();
    return j?.data?.fetched?.[0]?.ltp || null;
  } catch (e) { return null; }
}

async function fetchOptionLTP(symbol, strike, type, expiry_days) {
  try {
    const expiryInfo = detectExpiryForSymbol(symbol, expiry_days);
    const inst = await resolveInstrumentToken(symbol, expiryInfo.currentWeek, strike, type);
    if (!inst) return null;

    // First try WebSocket
    if (optionLTP[inst.token] && (Date.now() - optionLTP[inst.token].time < 2000)) {
      return optionLTP[inst.token].ltp;
    }

    // Fallback to Direct API (to ensure NO Mismatch)
    const r = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${session.access_token}`, "Content-Type": "application/json", "X-PrivateKey": SMART_API_KEY, "X-UserType": "USER", "X-SourceID": "WEB" },
      body: JSON.stringify({ mode: "LTP", exchangeTokens: { [inst.exch_seg]: [inst.token] } })
    });
    const j = await r.json();
    const price = j?.data?.fetched?.[0]?.ltp || null;
    if (price) optionLTP[inst.token] = { ltp: price, time: Date.now() };
    return price;
  } catch (e) { return null; }
}
/* PART 5/10 — EXPIRY & UTILS */

function detectExpiryForSymbol(symbol, expiry_days = 0) {
  const today = moment().startOf('day');
  const format = "DDMMMYYYY";
  
  let exch = symbol === "SENSEX" ? "BFO" : "NFO";
  const expiries = [...new Set(global.instrumentMaster
    .filter(it => it.name === symbol && it.exch_seg === exch)
    .map(it => it.expiry))]
    .sort((a, b) => moment(a, format).diff(moment(b, format)));

  const validExpiries = expiries.filter(e => moment(e, format).isSameOrAfter(today));
  
  return {
    currentWeek: validExpiries[expiry_days] || validExpiries[0],
    nextWeek: validExpiries[expiry_days + 1] || validExpiries[1]
  };
}

function getStrikeStep(symbol) {
  if (symbol === "NIFTY") return 50;
  if (symbol === "BANKNIFTY") return 100;
  if (symbol === "FINNIFTY") return 50;
  if (symbol === "SENSEX") return 100;
  return 100;
}
/* PART 6/10 — INDICATORS */

function calculateRSI(closes, period = 14) {
  if (closes.length < period) return 50;
  let gains = 0, losses = 0;
  for (let i = 1; i <= period; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff >= 0) gains += diff; else losses -= diff;
  }
  let avgGain = gains / period;
  let avgLoss = losses / period;
  for (let i = period + 1; i < closes.length; i++) {
    const diff = closes[i] - closes[i - 1];
    avgGain = (avgGain * (period - 1) + (diff > 0 ? diff : 0)) / period;
    avgLoss = (avgLoss * (period - 1) + (diff < 0 ? -diff : 0)) / period;
  }
  if (avgLoss === 0) return 100;
  const rs = avgGain / avgLoss;
  return 100 - (100 / (1 + rs));
}

function calculateEMA(data, period) {
  const k = 2 / (period + 1);
  let ema = data[0];
  for (let i = 1; i < data.length; i++) {
    ema = (data[i] * k) + (ema * (1 - k));
  }
  return ema;
}
/* PART 7/10 — HISTORIC DATA */

async function getHistoric(symbol, interval = "FIVE_MINUTE", days = 2) {
  try {
    const found = global.instrumentMaster.find(i => i.symbol === (symbol + "-EQ") || (i.name === symbol && i.exch_seg === "NSE"));
    if (!found) return [];

    const toDate = moment().format("YYYY-MM-DD HH:mm");
    const fromDate = moment().subtract(days, 'days').format("YYYY-MM-DD HH:mm");

    const r = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/get candle`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${session.access_token}`, "Content-Type": "application/json", "X-PrivateKey": SMART_API_KEY, "X-UserType": "USER", "X-SourceID": "WEB" },
      body: JSON.stringify({
        exchange: "NSE",
        symboltoken: found.token,
        interval: interval,
        fromdate: fromDate,
        todate: toDate
      })
    });
    const j = await r.json();
    return j?.data || [];
  } catch (e) { return []; }
}
/* PART 8/10 — COMPUTE ENTRY */

async function computeEntry({ market, spot, expiry_days, ema20, ema50, vwap, rsi }) {
  const step = getStrikeStep(market);
  const atm = Math.round(spot / step) * step;
  
  const [ceLtp, peLtp, ceInst, peInst] = await Promise.all([
    fetchOptionLTP(market, atm, "CE", expiry_days),
    fetchOptionLTP(market, atm, "PE", expiry_days),
    resolveInstrumentToken(market, "", atm, "CE"),
    resolveInstrumentToken(market, "", atm, "PE")
  ]);

  return {
    market,
    spot: spot.toFixed(2),
    atm,
    ce: { symbol: ceInst?.tradingsymbol, ltp: ceLtp, token: ceInst?.token },
    pe: { symbol: peInst?.tradingsymbol, ltp: peLtp, token: peInst?.token },
    indicators: { ema20: ema20.toFixed(2), ema50: ema50.toFixed(2), vwap: vwap.toFixed(2), rsi: rsi.toFixed(2) },
    time: moment().format("HH:mm:ss")
  };
}
/* PART 9/10 — EXPRESS ROUTES */

app.post("/api/calc", async (req, res) => {
  try {
    const { market, expiry_days = 0 } = req.body;
    if (!session.access_token) await loginAngel();

    const INDEX_MAP = { "NIFTY": "Nifty 50", "BANKNIFTY": "Nifty Bank", "SENSEX": "SENSEX" };
    const spotName = INDEX_MAP[market] || market;
    
    const [spot, candles] = await Promise.all([
      fetchLTP(spotName),
      getHistoric(spotName)
    ]);

    if (!spot) throw new Error("Could not fetch spot price");

    const closes = candles.map(c => c[4]);
    const ema20 = calculateEMA(closes, 20);
    const ema50 = calculateEMA(closes, 50);
    const rsi = calculateRSI(closes, 14);
    
    // Simple VWAP from candles
    let tpv = 0, tv = 0;
    candles.slice(-20).forEach(c => {
      tpv += ((c[2]+c[3]+c[4])/3) * c[5];
      tv += c[5];
    });
    const vwap = tpv / tv;

    const result = await computeEntry({ market, spot, expiry_days, ema20, ema50, vwap, rsi });
    res.json({ success: true, data: result });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});
/* PART 10/10 — START SERVER */

app.get("/api/ping", (req, res) => res.json({ status: "running", ws: wsStatus.connected }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 SERVER RUNNING ON PORT ${PORT}`);
  loginAngel(); // Initial login
});
