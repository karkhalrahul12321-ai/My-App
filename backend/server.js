/* PART 1/6 — BASE IMPORTS + CONFIG + SESSION + TOTP + LOGIN (FIXED SPOT ARCH BASE) */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

/* ONLINE MASTER AUTO-LOADER */
global.instrumentMaster = [];

async function loadMasterOnline() {
  try {
    const url =
      "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
    const r = await fetch(url);
    const j = await r.json().catch(() => []);
    if (Array.isArray(j) && j.length > 0) {
      global.instrumentMaster = j;
      console.log("MASTER LOADED ✔", j.length);
    }
  } catch (e) {
    console.log("MASTER LOAD ERROR", e);
  }
}
loadMasterOnline();
setInterval(loadMasterOnline, 60 * 60 * 1000);

const app = express();
app.use(cors());
app.use(bodyParser.json());

/* SERVE FRONTEND */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) =>
  res.sendFile(path.join(frontendPath, "index.html"))
);

/* SMARTAPI ENV */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* SESSION */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: null
};

/* LAST KNOWN PRICES (FIXED) */
let lastKnown = {
  spot: null,        // ONLY INDEX / COMMODITY SPOT
  future: null,      // FUTURE LTP
  updatedAt: 0,
  prevSpot: null
};

/* BASE32 + TOTP */
function base32Decode(input) {
  if (!input) return Buffer.from([]);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0,
    out = [];
  input = input.replace(/=+$/, "").toUpperCase();
  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateTOTP(secret) {
  try {
    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 30000);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(0, 0);
    buf.writeUInt32BE(time, 4);
    const hmac = crypto.createHmac("sha1", key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const code =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    return (code % 1000000).toString().padStart(6, "0");
  } catch {
    return null;
  }
}

/* SMARTAPI LOGIN */
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID)
    return { ok: false };

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
        totp
      })
    }
  );

  const data = await resp.json().catch(() => null);
  if (!data || data.status === false) return { ok: false };

  const d = data.data || {};
  session.access_token = d.jwtToken;
  session.refresh_token = d.refreshToken;
  session.feed_token = d.feedToken;
  session.expires_at = Date.now() + 20 * 60 * 60 * 1000;
  session.login_time = Date.now();

  return { ok: true };
}

/* LOGIN ROUTE */
app.post("/api/login", async (req, res) => {
  const r = await smartApiLogin(req.body?.password || "");
  res.json({
    success: !!r.ok,
    logged_in: !!r.ok,
    expires_at: session.expires_at
  });
});

module.exports = {
  app,
  session,
  lastKnown,
  generateTOTP
};
/* PART 2/6 — WEBSOCKET + MARKET MAP + SPOT TOKEN RESOLVER */

function getSpotExchange(market) {
  market = String(market || "").toUpperCase();
  if (market === "NIFTY") return "NSE";
  if (market === "SENSEX") return "BSE";
  if (market === "NATURALGAS") return "MCX";
  return "NSE";
}

/* RESOLVE SPOT TOKEN (INDEX / COMMODITY ONLY) */
async function resolveSpotToken(market) {
  try {
    const exchange = getSpotExchange(market);
    const master = global.instrumentMaster;
    if (!Array.isArray(master) || !master.length) return null;

    const m = market.toUpperCase();

    const matches = master.filter(it => {
      const ts = String(it.tradingsymbol || it.symbol || it.name || "").toUpperCase();
      const itype = String(it.instrumenttype || "").toUpperCase();

      if (exchange === "NSE" && m === "NIFTY")
        return itype.includes("INDEX") && ts.includes("NIFTY");

      if (exchange === "BSE" && m === "SENSEX")
        return itype.includes("INDEX") && ts.includes("SENSEX");

      if (exchange === "MCX" && m === "NATURALGAS")
        return ts.includes("NATURALGAS") || ts.includes("NAT GAS");

      return false;
    });

    if (!matches.length) return null;
    const pick = matches.find(x => x.token) || matches[0];

    return {
      exchange,
      token: String(pick.token),
      instrument: pick
    };
  } catch {
    return null;
  }
}

/* WEBSOCKET */
const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";
let wsClient = null;
let wsHeartbeat = null;

let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  subscriptions: []
};

const realtime = {
  ticks: {},
  candles1m: {}
};

async function startWebsocketIfReady() {
  if (wsClient || !session.feed_token || !session.access_token) return;

  wsClient = new WebSocket(WS_URL, {
    headers: {
      Authorization: session.access_token,
      "x-api-key": SMART_API_KEY,
      "x-client-code": SMART_USER_ID,
      "x-feed-token": session.feed_token
    }
  });

  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.lastError = null;

    wsClient.send(
      JSON.stringify({
        task: "auth",
        channel: "websocket",
        token: session.feed_token,
        user: SMART_USER_ID,
        apikey: SMART_API_KEY,
        source: "API"
      })
    );

    setTimeout(subscribeFuturesCore, 1000);

    wsHeartbeat = setInterval(() => {
      try {
        wsClient.send("ping");
      } catch {}
    }, 30000);
  });

  wsClient.on("message", raw => {
    wsStatus.lastMsgAt = Date.now();
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    const d = msg?.data;
    if (!d) return;

    const sym = d.tradingsymbol || d.symbol;
    const ltp = Number(d.ltp || d.lastPrice || 0);
    if (!sym || !ltp) return;

    /* FUTURE TICKS ONLY */
    lastKnown.future = ltp;

    realtime.ticks[sym] = {
      ltp,
      time: Date.now()
    };

    /* 1 MIN CANDLES */
    if (!realtime.candles1m[sym]) realtime.candles1m[sym] = [];
    const arr = realtime.candles1m[sym];
    const now = Math.floor(Date.now() / 60000) * 60000;
    const cur = arr[arr.length - 1];

    if (!cur || cur.time !== now) {
      arr.push({ time: now, open: ltp, high: ltp, low: ltp, close: ltp });
      if (arr.length > 180) arr.shift();
    } else {
      cur.high = Math.max(cur.high, ltp);
      cur.low = Math.min(cur.low, ltp);
      cur.close = ltp;
    }
  });

  wsClient.on("close", () => {
    wsStatus.connected = false;
    wsClient = null;
  });

  wsClient.on("error", err => {
    wsStatus.lastError = String(err);
    wsClient = null;
  });
}

/* FUTURES CORE SUBSCRIBE */
async function subscribeFuturesCore() {
  try {
    const symbols = ["NIFTY", "SENSEX", "NATURALGAS"];
    const tokens = [];

    for (let s of symbols) {
      const tok = await resolveInstrumentToken(s, detectExpiryForSymbol(s).currentWeek, 0, "FUT");
      if (tok?.token) tokens.push(tok.token);
    }

    if (!tokens.length) return;

    wsClient.send(
      JSON.stringify({
        task: "cn",
        channel: {
          instrument_tokens: tokens,
          feed_type: "ltp"
        }
      })
    );

    wsStatus.subscriptions = tokens;
  } catch {}
}

/* AUTO WS START AFTER LOGIN */
const _login = smartApiLogin;
smartApiLogin = async pw => {
  const r = await _login(pw);
  if (r.ok) setTimeout(startWebsocketIfReady, 1000);
  return r;
};

setTimeout(startWebsocketIfReady, 2000);
/* PART 3/6 — SPOT LTP (ANGEL MARKET DATA API) + CACHE */

/* FETCH SPOT LTP USING MARKET DATA API (DOC ALIGNED) */
async function fetchSpotLTP(market) {
  try {
    const info = await resolveSpotToken(market);
    if (!info || !info.token) return null;

    const payload = {
      mode: "LTP",
      exchangeTokens: {
        [info.exchange]: [info.token]
      }
    };

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote/`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: session.access_token,
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB"
        },
        body: JSON.stringify(payload)
      }
    );

    const j = await r.json().catch(() => null);
    const fetched = j?.data?.fetched;

    if (!Array.isArray(fetched) || !fetched.length) return null;

    const ltp = Number(fetched[0]?.ltp || 0);
    if (!ltp) return null;

    lastKnown.spot = ltp;
    lastKnown.updatedAt = Date.now();

    return ltp;
  } catch {
    return null;
  }
}

/* SAFE SPOT GETTER */
async function getSpot(market) {
  if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 3000) {
    return lastKnown.spot;
  }

  const live = await fetchSpotLTP(market);
  if (live) return live;

  return null;
}

/* WS STATUS API */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    subs: wsStatus.subscriptions
  });
});
/* PART 4/6 — API: SPOT + CALC (FIXED) */

/* API: GET SPOT */
app.get("/api/spot", async (req, res) => {
  try {
    const market = String(req.query.market || "NIFTY").toUpperCase();

    const spot = await getSpot(market);

    if (!spot) {
      return res.json({
        success: false,
        error: "SPOT_NOT_RESOLVED",
        market
      });
    }

    return res.json({
      success: true,
      market,
      spot,
      source: "MARKET_API"
    });
  } catch (e) {
    res.json({
      success: false,
      error: "SPOT_EXCEPTION",
      detail: String(e)
    });
  }
});

/* API: CALC (MASTER ENTRY ENGINE) */
app.post("/api/calc", async (req, res) => {
  try {
    const {
      market,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      spot: clientSpot
    } = req.body;

    let finalSpot = null;

    /* PRIORITY:
       1) Cached Spot
       2) Client Spot
       3) Live Spot API
    */
    if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 3000) {
      finalSpot = lastKnown.spot;
    } else if (clientSpot && isFinite(clientSpot)) {
      finalSpot = Number(clientSpot);
      lastKnown.spot = finalSpot;
      lastKnown.updatedAt = Date.now();
    } else {
      finalSpot = await fetchSpotLTP(market);
    }

    if (!finalSpot || !isFinite(finalSpot)) {
      return res.json({
        success: false,
        error: "SPOT_NOT_RESOLVED",
        guardian: {
          cached: !!lastKnown.spot,
          client: !!clientSpot,
          live: false
        }
      });
    }

    const entry = await computeEntry({
      market,
      spot: finalSpot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot: lastKnown.prevSpot
    });

    lastKnown.prevSpot = finalSpot;

    return res.json({
      success: true,
      entry
    });
  } catch (err) {
    res.json({
      success: false,
      error: "CALC_EXCEPTION",
      detail: String(err)
    });
  }
});
/* PART 5/6 — SAFETY + STATUS + FALLBACKS */

/* HEALTH CHECK */
app.get("/healthz", (req, res) => {
  res.json({
    ok: true,
    time: Date.now(),
    session: {
      logged_in: !!session.access_token,
      expires_at: session.expires_at
    },
    ws: {
      connected: wsStatus.connected,
      lastMsgAt: wsStatus.lastMsgAt
    },
    spot: {
      value: lastKnown.spot,
      updatedAt: lastKnown.updatedAt
    },
    future: lastKnown.future
  });
});

/* PING */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    ws_live: wsStatus.connected,
    spot: lastKnown.spot,
    future: lastKnown.future
  });
});

/* TOKEN RESOLVE API (UNCHANGED CORE LOGIC) */
app.get("/api/token/resolve", async (req, res) => {
  try {
    const market = String(req.query.market || "");
    const strike = Number(req.query.strike || 0);
    const type = String(req.query.type || "CE");

    const expiry = detectExpiryForSymbol(market).currentWeek;
    const tok = await resolveInstrumentToken(market, expiry, strike, type);

    if (!tok) {
      return res.json({
        success: false,
        error: "TOKEN_NOT_FOUND"
      });
    }

    return res.json({
      success: true,
      token: tok
    });
  } catch (e) {
    res.json({
      success: false,
      error: "TOKEN_RESOLVE_EXCEPTION",
      detail: String(e)
    });
  }
});

/* SAFE ROOT (KEEP SIMPLE) */
app.get("/", (req, res) => {
  res.send("Server OK — Spot & Futures LIVE 🚀");
});
/* PART 6/6 — SERVER START + EXPORTS (FINAL END) */

/* START SERVER */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});

/* EXPORTS (FOR TESTING / EXTENSION) */
module.exports = {
  app,
  session,
  lastKnown,
  getSpot,
  fetchSpotLTP,
  resolveSpotToken,
  generateTOTP
};
