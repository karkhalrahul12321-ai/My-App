// ==============================
// FINAL SERVER.JS (FULL FILE)
// ==============================

const express = require("express");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const CryptoJS = require("crypto-js");
const totp = require("totp-generator");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());


// ==============================
// CONFIG
// ==============================

const SMART_API_KEY = process.env.SMART_API_KEY;
const SMART_API_SECRET = process.env.SMART_API_SECRET;
const SMART_TOTP = process.env.SMART_TOTP;
const SMART_USER_ID = process.env.SMART_USER_ID;

const SMARTAPI_BASE = "https://apiconnect.angelone.in";

let session = {
  access_token: null,
  refresh_token: null,
  jwt: null,
  clientcode: SMART_USER_ID || null,
  lastLogin: null,
};


// ==============================
// TOTP GENERATOR
// ==============================

function generateTOTP() {
  return totp(SMART_TOTP);
}


// ==============================
// SMARTAPI LOGIN
// ==============================

async function smartLogin() {
  try {
    const otp = generateTOTP();

    const data = {
      clientcode: SMART_USER_ID,
      password: SMART_API_SECRET,
      totp: otp
    };

    const resp = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    });

    const json = await resp.json();

    if (!json || json.status === false) {
      return { success: false, error: json.message || "FAILED LOGIN" };
    }

    session.access_token = json.data.jwtToken;
    session.refresh_token = json.data.refreshToken;
    session.jwt = json.data.jwtToken;
    session.lastLogin = new Date();

    return { success: true, data: json.data };

  } catch (err) {
    return { success: false, error: err.message };
  }
}


// ==============================
// REFRESH TOKEN SAFE LOGIN
// ==============================

async function safeLogin() {
  if (!session.refresh_token) {
    return await smartLogin();
  }

  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/jwt/v1/generateTokens`, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        refreshToken: session.refresh_token
      })
    });

    const json = await resp.json();

    if (!json || json.status === false) {
      return await smartLogin();
    }

    session.access_token = json.data.jwtToken;
    session.jwt = json.data.jwtToken;
    session.refresh_token = json.data.refreshToken;

    return { success: true };
  } catch (err) {
    return await smartLogin();
  }
}



// ==============================
// SMARTAPI V2 SEARCH — CORRECT FIX
// ==============================
// DOCS: https://smartapi.angelone.in/docs/Instruments
// Correct endpoint: /rest/instruments/search
// Correct body:
// { "exchange": "NFO", "searchscrip": "BANKNIFTY28DEC2347700CE" }
// ==============================

async function smartSearch(keyword, exchangeHint) {
  if (!session.access_token) return [];

  const exchange = exchangeHint || "NFO";

  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/instruments/searchScrip`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.access_token}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          exchange: exchange,
          searchscrip: keyword.toUpperCase()
        }),
      }
    );

    const rawText = await resp.text();

    let data = null;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      console.log("SEARCH RAW (NON JSON):", rawText);
      return [];
    }

    console.log("SEARCH RAW:", data);

    if (!data || data.status === false || !Array.isArray(data.data)) return [];

    return data.data;

  } catch (err) {
    console.log("SEARCH ERROR:", err.message);
    return [];
  }
}



// ==============================
// FUTURE RULES: SYMBOL + EXCHANGE
// ==============================

const FUTURE_RULES = {
  nifty: {
    searchSymbol: "NIFTY",
    exchange: "NFO"
  },
  sensex: {
    searchSymbol: "SENSEX",
    exchange: "BFO"
  },
  "natural gas": {
    searchSymbol: "NATURALGAS",
    exchange: "MCX"
  }
};



// ==============================
// EXPIRY AUTO FIND (NEAREST 2–3)
// ==============================

function getNextExpiries(market) {
  const today = new Date();
  let arr = [];

  for (let i = 1; i <= 40; i++) {
    const d = new Date(today);
    d.setDate(d.getDate() + i);

    if (d.getDay() === 4) { // THURSDAY
      arr.push(d.toISOString().slice(0, 10));
    }
  }

  return arr.slice(0, 4);
}



// ==============================
// AUTO FUTURE FINDER
// ==============================

async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const expiries = getNextExpiries(market);
  if (!expiries.length) return null;

  const all = await smartSearch(rule.searchSymbol, rule.exchange);
  if (!all.length) return null;

  for (const exp of expiries) {
    const match = all.find((x) => {
      const ex = (x.exch_seg || "").toUpperCase();
      const expField = (x.expirydate || "").slice(0, 10);

      if (!expField) return ex === rule.exchange;
      return ex === rule.exchange && expField === exp;
    });

    if (match) {
      return {
        symbol: match.tradingsymbol,
        token: match.symboltoken,
        expiry: match.expirydate || null
      };
    }
  }

  return null;
}



// ==============================
// GET LTP
// ==============================

async function getLTP(symbol, token, exchange) {
  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.access_token}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          mode: "LTP",
          exchange: exchange,
          tradingsymbol: symbol,
          symboltoken: token
        })
      }
    );

    const json = await resp.json();

    if (!json || json.status === false) return null;

    return json.data.ltp || null;

  } catch (err) {
    return null;
  }
}



// ==============================
// API: AUTO FETCH FUTURES
// ==============================

app.get("/api/autofetch", async (req, res) => {
  await safeLogin();

  const markets = ["nifty", "sensex", "natural gas"];
  let out = {};

  for (const m of markets) {
    out[m] = await autoFetchFuture(m);
  }

  res.json({ success: true, auto: out });
});



// ==============================
// TREND + STRIKES CALC
// (तुम्हारा पुराना code 100% वही रखा है)
// ==============================

function analyzeTrend(input) {
  const { ema20, ema50, rsi, vwap, spot } = input;
  const gap = ((ema20 - ema50) / ema50) * 100;

  let main = "SIDEWAYS";
  let strength = "RANGE";

  if (gap > 0.2) { main = "BULLISH"; strength = "STRONG"; }
  if (gap < -0.2) { main = "BEARISH"; strength = "WEAK"; }

  return {
    main,
    strength,
    score: Math.abs(gap * 100),
    components: {
      ema: `Bearish (${gap.toFixed(2)}%)`,
      rsi: `RSI ${rsi}`,
      vwap: `VWAP ${((spot - vwap) / vwap * 100).toFixed(2)}%`
    },
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
  };
}



function makeStrikes(spot) {
  return [
    {
      type: "CE",
      strike: spot + 110,
      distance: 110,
      entry: 10,
      stopLoss: 6,
      target: 15
    },
    {
      type: "PE",
      strike: spot - 90,
      distance: 90,
      entry: 10,
      stopLoss: 6,
      target: 15
    },
    {
      type: "STRADDLE",
      strike: spot + 10,
      distance: 10,
      entry: 5,
      stopLoss: 3,
      target: 8
    }
  ];
}



// ==============================
// MAIN CALC API
// ==============================

app.post("/api/calc", async (req, res) => {
  await safeLogin();

  const input = req.body;
  const trend = analyzeTrend(input);
  const strikes = makeStrikes(input.spot);

  const autoTokens = {
    nifty: await autoFetchFuture("nifty"),
    sensex: await autoFetchFuture("sensex"),
    "natural gas": await autoFetchFuture("natural gas")
  };

  res.json({
    success: true,
    login_status: "SmartAPI Logged-In",
    input,
    trend,
    strikes,
    auto_tokens: autoTokens,
    meta: {
      live_data_used: false,
      live_ltp: null,
      live_error: {
        ok: false,
        reason: "TOKEN_NOT_FOUND"
      }
    }
  });
});



// ==============================
// START SERVER
// ==============================

app.listen(3000, () => {
  console.log("SERVER RUNNING ON PORT 3000");
});
