// =======================
// TENGO BACKEND (FINAL FIXED)
// CommonJS Compatible (Render Safe)
// SmartAPI Login + Smart Stream V2 (URL Auth)
// =======================

const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const WebSocket = require("ws");

// -------------- ENV ----------------
require("dotenv").config();

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP_SECRET || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMARTAPI_BASE = "https://smartapi.angelone.in";

// ---------------- APP SETUP ----------------
const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 10000;

let session = {
  access_token: null,
  feed_token: null,
  expires_at: 0
};

// ---------------- TOTP ----------------
function generateTOTP(secret) {
  try {
    const crypto = require("crypto");

    const key = Buffer.from(secret, "hex");
    const epoch = Math.floor(Date.now() / 1000);
    const time = Buffer.alloc(8);
    time.writeUInt32BE(0, 0);
    time.writeUInt32BE(Math.floor(epoch / 30), 4);

    const hmac = crypto.createHmac("sha1", key).update(time).digest();
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

// ---------------- SAFE FETCH ----------------
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
// ======================================================
// PART 2 — SmartAPI Login + FeedToken Fetch + WS V2 Setup
// ======================================================

// ***** Smart Stream V2 URL (NEW – FIXED) *****
const WS_V2_URL = "wss://smartapisocket.angelone.in/smart-stream";

let wsClient = null;
let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

// ---------------- SmartAPI LOGIN (Password + TOTP) ----------------
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

    if (!data || !data.data || !data.data.jwtToken) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    session.access_token = data.data.jwtToken;
    session.feed_token = data.data.feedToken;
    session.expires_at = Date.now() + 12 * 60 * 60 * 1000; // 12 hrs

    console.log("LOGIN SUCCESS:", {
      access_token_set: true,
      feed_token_set: true
    });

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}
// ======================================================
// START Smart Stream WebSocket V2 (URL-AUTH MODE)
// ======================================================

async function startWebsocketV2IfReady() {
  console.log("DEBUG: Before WS Start =>", {
    access_token_set: !!session.access_token,
    feed_token_set: !!session.feed_token,
    expires_at: session.expires_at
  });

  // Already connected? Skip
  if (wsClient && wsStatus.connected) return;

  // auth token not ready yet
  if (!session.access_token || !session.feed_token) {
    console.log("WSv2 WAIT: tokens missing");
    return;
  }

  try {
    // cleanup old WS
    if (wsClient) {
      try { wsClient.close(); } catch (e) {}
      wsClient = null;
      wsStatus.connected = false;
    }

    // ********** FINAL URL (NO PAYLOAD AUTH) **********
    const finalWSUrl =
      `${WS_V2_URL}?clientCode=${SMART_USER_ID}` +
      `&apiKey=${SMART_API_KEY}` +
      `&feedToken=${session.feed_token}`;

    console.log("WSv2 CONNECT →", finalWSUrl);

    wsClient = new WebSocket(finalWSUrl, { perMessageDeflate: false });

    // --- on OPEN ---
    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;

      console.log("WSv2: connected (URL-auth)");
    });

    // --- on MESSAGE ---
    wsClient.on("message", (msg) => {
      wsStatus.lastMsgAt = Date.now();
      handleWSv2Message(msg);
    });

    // --- on ERROR ---
    wsClient.on("error", (err) => {
      console.log("WSv2 ERROR:", err.message || err);
      wsStatus.lastError = err.message || "ERR";
    });

    // --- on CLOSE ---
    wsClient.on("close", (code) => {
      console.log("WSv2 CLOSED:", code);
      wsStatus.connected = false;

      // auto reconnect
      setTimeout(() => {
        wsStatus.reconnectAttempts++;
        startWebsocketV2IfReady();
      }, 1500);
    });

  } catch (e) {
    console.log("WSv2 START ERR:", e.message || e);
  }
}
// ======================================================
// PART 4 — WebSocket V2 Message Handler + Subscribe System
// ======================================================

// Live tick store
const lastKnown = { spot: null, updatedAt: 0 };

// ----------- HANDLE WS MESSAGE (Smart Stream V2) ----------
function handleWSv2Message(raw) {
  try {
    const j = JSON.parse(raw.toString());

    // TRY to catch tick packets
    // Angel V2 sometimes uses:
    // { "type":"tick", "data": { "symbol":..., "ltp":... } }

    if (j.type === "tick" && j.data) {
      const token = j.data.symbol || j.data.token || null;
      const ltp = Number(j.data.ltp || j.data.lastPrice || j.data.price || 0);

      if (token && ltp > 0) {
        realtime.ticks[token] = { ltp, ts: Date.now() };

        // update last spot
        lastKnown.spot = ltp;
        lastKnown.updatedAt = Date.now();
      }

      return; // done
    }

    // HEARTBEAT
    if (j.type === "heartbeat") return;

    // DEBUG
    console.log("WSv2 MSG:", j);

  } catch (e) {
    console.log("WS MSG PARSE ERR:", e.message);
  }
}

// --------------- SUBSCRIBE -----------------
function wsSubscribe(tokens = []) {
  if (!wsClient || wsClient.readyState !== 1) {
    console.log("WS NOT CONNECTED → Cannot subscribe");
    return false;
  }

  const payload = {
    action: "subscribe",
    params: { mode: "ltp", tokenList: tokens }
  };

  try {
    wsClient.send(JSON.stringify(payload));
    wsStatus.subscriptions.push(...tokens);
    wsStatus.subscriptions = [...new Set(wsStatus.subscriptions)];
    return true;
  } catch (e) {
    console.log("SUBSCRIBE SEND ERR:", e.message);
    return false;
  }
}

// --------------- UNSUBSCRIBE -----------------
function wsUnsubscribe(tokens = []) {
  if (!wsClient || wsClient.readyState !== 1) {
    console.log("WS NOT CONNECTED → Cannot unsubscribe");
    return false;
  }

  const payload = {
    action: "unsubscribe",
    params: { mode: "ltp", tokenList: tokens }
  };

  try {
    wsClient.send(JSON.stringify(payload));
    wsStatus.subscriptions = wsStatus.subscriptions.filter(
      (t) => !tokens.includes(t)
    );
    return true;
  } catch (e) {
    console.log("UNSUBSCRIBE SEND ERR:", e.message);
    return false;
  }
}

// ---------- EXPRESS ROUTES for SUBSCRIBE ----------
app.post("/api/ws/subscribe", (req, res) => {
  const tokens = req.body?.tokens || [];
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return res.json({ success: false, error: "NO_TOKENS" });
  }

  const ok = wsSubscribe(tokens);
  res.json({
    success: ok,
    subscriptions: wsStatus.subscriptions
  });
});

// ---------- EXPRESS ROUTES for UNSUBSCRIBE ----------
app.post("/api/ws/unsubscribe", (req, res) => {
  const tokens = req.body?.tokens || [];
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return res.json({ success: false, error: "NO_TOKENS" });
  }

  const ok = wsUnsubscribe(tokens);
  res.json({
    success: ok,
    subscriptions: wsStatus.subscriptions
  });
});

// ---------- CHECK WS STATUS ----------
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subscriptions: wsStatus.subscriptions
  });
});
// ======================================================
// PART 5 — Strike engine, LTP fetchers, trend engine, computeEntry, /api/compute
// ======================================================

/**
 * Weekly expiry detector (nearest Thursday)
 */
function detectWeeklyExpiryYMD() {
  const now = new Date();
  const dow = now.getDay(); // 0=Sun ... 4=Thu
  const th = new Date(now);
  if (dow <= 4) th.setDate(now.getDate() + (4 - dow));
  else th.setDate(now.getDate() + (7 - (dow - 4)));
  const yyyy = th.getFullYear();
  const mm = String(th.getMonth() + 1).padStart(2, "0");
  const dd = String(th.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

/**
 * Resolve instrument token from global.instrumentMaster if available.
 * Returns instrument object or null. (Fallback: null)
 */
async function resolveInstrumentToken(symbol, expiryYMD, strike = null, type = "FUT") {
  try {
    if (!global.instrumentMaster || !Array.isArray(global.instrumentMaster)) return null;
    const expiryShort = expiryYMD.replace(/-/g, "").slice(2); // yymmdd
    const tsym = (symbol || "").toUpperCase();
    const candidates = global.instrumentMaster.filter((it) => {
      const ts = (it.tradingsymbol || "").toUpperCase();
      if (!ts.includes(tsym)) return false;
      if (!ts.includes(expiryShort)) return false;
      if (type === "FUT") return ts.includes("FUT");
      if (type === "CE" || type === "PE") {
        if (!ts.includes(type)) return false;
        const st = Number(it.strike || it.strikePrice || 0);
        return st === Number(strike);
      }
      return false;
    });
    return candidates.length ? candidates[0] : null;
  } catch (e) {
    return null;
  }
}

/**
 * Generic LTP fetch wrapper using SmartAPI getLtpData
 * Accepts exchange, tradingsymbol, symboltoken
 * Returns numeric ltp or null
 */
async function apiGetLtp(exchange, tradingsymbol, symboltoken) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const body = JSON.stringify({
      exchange: exchange || "NSE",
      tradingsymbol: tradingsymbol || "",
      symboltoken: symboltoken || ""
    });
    const headers = {
      "Content-Type": "application/json",
      "X-PrivateKey": SMART_API_KEY
    };
    if (session.access_token) headers.Authorization = session.access_token;

    const r = await fetch(url, { method: "POST", headers, body });
    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || j?.data?.ltpValue || 0);
    return isFinite(ltp) && ltp > 0 ? ltp : null;
  } catch (e) {
    return null;
  }
}

/**
 * fetchSpotLTP(symbol) - NSE spot like NIFTY
 */
async function fetchSpotLTP(symbol) {
  return await apiGetLtp("NSE", symbol, "");
}

/**
 * fetchFuturesLTP(symbol) - resolves instrument then fetches LTP
 */
async function fetchFuturesLTP(symbol) {
  const expiry = detectWeeklyExpiryYMD();
  const inst = await resolveInstrumentToken(symbol, expiry, null, "FUT");
  if (!inst) return null;
  return await apiGetLtp(inst.exchange || "NFO", inst.tradingsymbol, inst.token || inst.instrumentToken);
}

/**
 * fetchOptionLTP(symbol, strike, type)
 */
async function fetchOptionLTP(symbol, strike, type) {
  const expiry = detectWeeklyExpiryYMD();
  const inst = await resolveInstrumentToken(symbol, expiry, strike, type);
  if (!inst) return null;
  return await apiGetLtp(inst.exchange || "NFO", inst.tradingsymbol, inst.token || inst.instrumentToken);
}

/**
 * Strike helpers
 */
function roundToNearestStep(price, step = 50) {
  return Math.round(Number(price || 0) / step) * step;
}
function generateStrikesFromSpot(spot) {
  const atm = roundToNearestStep(spot, 50);
  return { atm, ce: atm + 50, pe: atm - 50 };
}

/**
 * Hybrid Trend Engine (keeps original style)
 * Returns structure similar to your app expectations.
 */
function hybridTrend({ ema20, ema50, rsi, vwap, spot }) {
  ema20 = Number(ema20 || 0);
  ema50 = Number(ema50 || 0);
  rsi = Number(rsi || 50);
  vwap = Number(vwap || 0);
  spot = Number(spot || 0);

  const components = {};
  components.ema_gap = ema20 && ema50 ? (((ema20 - ema50) / (ema50 || 1)) * 100).toFixed(2) + "%" : "0%";
  components.rsi = `RSI ${rsi}`;
  components.vwap = vwap ? (spot > vwap ? `Above VWAP` : `Below VWAP`) : "VWAP N/A";

  let score = 50;
  if (ema20 > ema50) score += 10; else score -= 10;
  if (spot > vwap) score += 8; else score -= 8;
  if (rsi > 60) score += 6; if (rsi < 40) score -= 6;

  const main = score > 55 ? "UPTREND" : score < 45 ? "DOWNTREND" : "NEUTRAL";
  const strength = Math.abs(score - 50) > 15 ? "STRONG" : "MODERATE";
  const bias = main === "UPTREND" ? "CE" : main === "DOWNTREND" ? "PE" : "NEUTRAL";

  return {
    main, strength, score, bias, components,
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
  };
}

/**
 * computeEntryFull - glue that your frontend expects
 * Accepts: { market, spot, ema20, ema50, rsi, vwap, use_live }
 * Returns object with strikes, trend, ce_ltp, pe_ltp, meta
 */
async function computeEntryFull({ market = "NIFTY", spot = null, ema20 = null, ema50 = null, rsi = null, vwap = null, use_live = false }) {
  try {
    market = (market || "NIFTY").toUpperCase();

    // priority: live -> provided -> API
    let finalSpot = null;
    if (use_live && lastKnown && lastKnown.spot) finalSpot = lastKnown.spot;
    if (!finalSpot && spot) finalSpot = Number(spot);
    if (!finalSpot) finalSpot = await fetchSpotLTP(market);

    if (!finalSpot) return { success: false, reason: "NO_SPOT" };

    const expiry = detectWeeklyExpiryYMD();
    const daysToExpiry = Math.max(1, Math.ceil((new Date(expiry) - new Date()) / (1000 * 3600 * 24)));

    const strikes = generateStrikesFromSpot(finalSpot);
    const trend = hybridTrend({ ema20, ema50, rsi, vwap, spot: finalSpot });

    // get option ltps (ATM +/- 50)
    const ceLTP = await fetchOptionLTP(market, strikes.ce, "CE").catch(() => null);
    const peLTP = await fetchOptionLTP(market, strikes.pe, "PE").catch(() => null);

    // futures diff (if available)
    const futLTP = await fetchFuturesLTP(market).catch(() => null);
    const futDiff = futLTP && finalSpot ? (futLTP - Number(finalSpot)) : null;

    // determine entry side
    const entrySide = trend.main === "UPTREND" ? "CE" : trend.main === "DOWNTREND" ? "PE" : "NONE";
    const entryLTP = entrySide === "CE" ? ceLTP : entrySide === "PE" ? peLTP : null;

    let levels = null;
    if (entryLTP) {
      const entryVal = Number(entryLTP);
      levels = {
        stopLoss: Number((entryVal * 0.85).toFixed(2)), // 15% SL
        target: Number((entryVal * 1.08).toFixed(2))   // dynamic small target
      };
    }

    return {
      success: true,
      market,
      spot: finalSpot,
      expiry,
      daysToExpiry,
      trend,
      strikes: [
        { type: "CE", strike: strikes.ce, distance: strikes.ce - strikes.atm, entry: entryLTP || null },
        { type: "PE", strike: strikes.pe, distance: strikes.atm - strikes.pe, entry: entryLTP || null },
        { type: "STRADDLE", strike: strikes.atm, distance: 0, entry: null }
      ],
      ce_ltp: ceLTP,
      pe_ltp: peLTP,
      futDiff,
      entrySide,
      entryLTP,
      levels,
      meta: {
        live_data_used: !!(use_live && lastKnown && lastKnown.spot),
        live_ltp: lastKnown && lastKnown.spot ? lastKnown.spot : null
      }
    };

  } catch (e) {
    return { success: false, reason: "EXCEPTION", error: e && e.message ? e.message : String(e) };
  }
}

/**
 * /api/compute route
 * Expects body: { market, spot, ema20, ema50, rsi, vwap, use_live }
 */
app.post("/api/compute", async (req, res) => {
  try {
    const b = req.body || {};
    const out = await computeEntryFull({
      market: b.market,
      spot: b.spot,
      ema20: b.ema20,
      ema50: b.ema50,
      rsi: b.rsi,
      vwap: b.vwap,
      use_live: !!b.use_live
    });

    // mirror the legacy response shape a bit so your app doesn't break
    if (out && out.success) {
      return res.json({
        success: true,
        message: "Calculation complete",
        login_status: session.access_token ? "SmartAPI Logged-In" : "Not Logged-In",
        input: {
          market: out.market,
          spot: out.spot,
          ema20: b.ema20 || null,
          ema50: b.ema50 || null,
          rsi: b.rsi || null,
          vwap: b.vwap || null,
          use_live: !!b.use_live
        },
        trend: out.trend,
        strikes: out.strikes,
        ce_ltp: out.ce_ltp,
        pe_ltp: out.pe_ltp,
        futDiff: out.futDiff,
        meta: out.meta
      });
    } else {
      return res.json({ success: false, error: out.reason || out.error || "Compute failed" });
    }
  } catch (err) {
    return res.json({ success: false, error: err && err.message ? err.message : String(err) });
  }
});
// ======================================================
// PART 6 — FINAL BLOCK (Server Listen + WS Auto-check)
// ======================================================

// ----------- AUTO START WS EVERY 5 SECONDS IF LOGGED-IN -----------
setInterval(() => {
  if (session.access_token && session.feed_token) {
    if (!wsStatus.connected) {
      console.log("WSv2 AUTO-CHECK → reconnecting…");
      startWebsocketV2IfReady();
    }
  }
}, 5000);

// ------------- HOME/HEALTH ROUTE (OPTIONAL) -------------
app.get("/", (req, res) => {
  res.send(`
    <h2>TENGO BACKEND RUNNING (FINAL FIXED)</h2>
    <p>Smart Stream V2: <b>${wsStatus.connected ? "Connected" : "Disconnected"}</b></p>
    <p>Last Tick: ${lastKnown.spot ? lastKnown.spot : "No data yet"}</p>
    <p>Login: ${session.access_token ? "Logged-In" : "Not Logged-In"}</p>
  `);
});

// ------------ 404 FALLBACK -------------
app.use((req, res) => {
  res.status(404).send("Not Found");
});

// ------------- START SERVER -------------
app.listen(PORT, () => {
  console.log("\n========================================");
  console.log("   TENGO BACKEND RUNNING (FINAL FIXED)");
  console.log("   Smart Stream V2 URL-AUTH ACTIVE");
  console.log("   Listening on PORT:", PORT);
  console.log("========================================\n");
});
