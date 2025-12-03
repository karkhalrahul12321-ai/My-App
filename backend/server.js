// ======================================================
// Part 1/4
// server.js (START)
// Trading Helper Backend (PART 1)
// - imports, config, express init
// - helpers (safe parsers, logging, nowTS)
// - SmartAPI login (TOTP) -> returns feed_token + fallback tokens
// - auto future token fetch (HTTP) + basic futures LTP fetch (HTTP safe)
// - placeholders for websocket-ready token storage (feed_token)
// ------------------------------------------------------

/* eslint-disable no-console */
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const WebSocket = require("ws"); // used later in part-2 (kept here for install)
const zlib = require("zlib");
require("dotenv").config();

// Basic app init
const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// Simple logger helper
function nowTS() {
  return new Date().toISOString();
}
function log(...args) {
  console.log(`[${nowTS()}]`, ...args);
}

// Safe number parser
function pnum(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

// Safe JSON parse
function safeParseJson(s, fallback = null) {
  try {
    return typeof s === "object" ? s : JSON.parse(String(s || ""));
  } catch (e) {
    return fallback;
  }
}

// Environment / config
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
// fallback tokens (optional) - should be set in env if you want safe fallback
const FALLBACK_AUTO_TOKENS_JSON = process.env.FALLBACK_AUTO_TOKENS || "{}";
let FALLBACK_AUTO_TOKENS = safeParseJson(FALLBACK_AUTO_TOKENS_JSON, {});

// Basic site paths (if serving SPA)
const frontendPath = path.join(__dirname, "frontend");

// In-memory runtime state
const runtime = {
  feed_token: null,         // SmartAPI feed token (for WS V2)
  feed_expires_at: null,
  auto_tokens: {},          // { nifty: { symbol, token, expiry }, ... }
  last_login: null,
  last_login_ok: false,
};

// Small helper to return API responses
function okResponse(data = {}) {
  return { success: true, ts: nowTS(), ...data };
}
function errResponse(msg, extra = {}) {
  return { success: false, ts: nowTS(), error: String(msg), ...extra };
}

// -----------------------------
// SmartAPI login (TOTP)
// This function tries to login using SMART API TOTP flow.
// It returns an object { ok: true, feed_token, tokens: {market: {symbol, token, expiry}} }
// On failure returns { ok: false, reason, detail }
// NOTE: SmartAPI endpoints vary by broker integration; this code uses
// the common shape many SmartAPI wrappers use. Adjust URLs if your broker differs.
// -----------------------------
async function smartLogin() {
  // Basic validation
  if (!SMART_API_KEY || !SMART_API_SECRET || !SMART_TOTP || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING", detail: "SMARTAPI ENV missing" };
  }

  // Example SmartAPI auth URL (may vary); keep flexible
  const loginUrl = process.env.SMARTAPI_LOGIN_URL || "https://api.smartapi.example/login"; // replace with real if needed

  try {
    // Build login body (many SmartAPI implementations accept TOTP or password)
    const body = {
      apiKey: SMART_API_KEY,
      userId: SMART_USER_ID,
      totp: SMART_TOTP,
    };

    // Use fetch (POST) - robust parsing
    const resp = await fetch(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // timeout not provided by node-fetch v2; will rely on infra
    });

    const txt = await resp.text();
    const data = safeParseJson(txt, null);

    if (!data) {
      // some SmartAPI return JSON even if resp.ok false; handle
      return { ok: false, reason: "INVALID_JSON", detail: txt };
    }

    // Typical pattern: data.data.feedToken, data.data.tokens etc
    const loginResp = data.data || data;

    // Try multiple fallbacks to find feed_token
    const feed_token =
      loginResp.feedToken ||
      loginResp.feed_token ||
      loginResp.data && (loginResp.data.feedToken || loginResp.data.feed_token) ||
      null;

    // Tokens list: sometimes in loginResp.tokens or loginResp.exchangeTokens
    let tokens = {};
    try {
      // Normalize tokens structure
      const tlist =
        loginResp.tokens ||
        loginResp.exchangeTokens ||
        loginResp.tokenList ||
        loginResp.token_map ||
        null;

      if (tlist && typeof tlist === "object") {
        // If it's an array
        if (Array.isArray(tlist)) {
          tlist.forEach((x) => {
            try {
              if (x && x.symbol) {
                const sym = x.symbol;
                const tok = x.token || x.tokenId || x.exchangeToken || x.tokenId;
                const exp = x.expiry || x.expiryDate || null;
                tokens[sym] = { symbol: sym, token: tok ? String(tok) : null, expiry: exp || null };
              }
            } catch (e) {}
          });
        } else {
          // object map
          Object.keys(tlist).forEach((k) => {
            const v = tlist[k];
            if (v) {
              const sym = v.symbol || k;
              const tok = v.token || v.tokenId || v.exchangeToken || null;
              const exp = v.expiry || null;
              tokens[sym] = { symbol: sym, token: tok ? String(tok) : null, expiry: exp };
            }
          });
        }
      }
    } catch (e) {
      // ignore token parse errors
    }

    // If feed_token is missing but data contains a 'session' or 'data' with tokens, attempt fallback
    if (!feed_token && (loginResp.sessionToken || loginResp.session || loginResp.data)) {
      // some implementations use session tokens as feed tokens – attempt guess
      const maybe = loginResp.sessionToken || loginResp.session || null;
      if (maybe) {
        // not ideal but store as feed_token candidate
        runtime.feed_token = maybe;
      }
    }

    // Build result
    const result = {
      ok: true,
      feed_token: feed_token || runtime.feed_token || null,
      tokens,
      raw: data,
    };

    // Update runtime
    runtime.last_login = nowTS();
    runtime.last_login_ok = true;
    if (result.feed_token) {
      runtime.feed_token = result.feed_token;
      // If token expiry available, try parse expiry (not mandatory)
      runtime.feed_expires_at = Date.now() + 30 * 60 * 1000; // assume 30 min default
    }

    // massage auto_tokens into standardized set (nifty, sensex, natural gas)
    // If tokens map contains futures names, try to extract default markers
    // We'll use a safe search routine for futures below (fetchAutoFutureTokens)
    return result;
  } catch (err) {
    runtime.last_login_ok = false;
    return { ok: false, reason: "LOGIN_FAILED", detail: String(err) };
  }
}

// -----------------------------
// Fetch auto future tokens (HTTP) - robust parsing
// tries to find common futures symbols & tokens (nifty, sensex, natural gas)
// Many brokers provide a /market/tokens or /instruments endpoint returning array/object.
// We will attempt a small search heuristics over returned data.
// -----------------------------
async function fetchAutoFutureTokens() {
  // If fallback env provided, use that first
  if (FALLBACK_AUTO_TOKENS && Object.keys(FALLBACK_AUTO_TOKENS).length > 0) {
    runtime.auto_tokens = FALLBACK_AUTO_TOKENS;
    return { ok: true, source: "fallback", tokens: runtime.auto_tokens };
  }

  // Example instruments URL (replace via env if needed)
  const instUrl = process.env.SMARTAPI_INSTR_URL || "https://api.smartapi.example/instruments";

  try {
    const resp = await fetch(instUrl, { method: "GET" });
    const txt = await resp.text();
    const data = safeParseJson(txt, null);
    if (!data) {
      return { ok: false, reason: "INVALID_INSTR_JSON", detail: txt };
    }

    // data could be array, or {data: [...]} etc
    let arr = [];
    if (Array.isArray(data)) arr = data;
    else if (Array.isArray(data.data)) arr = data.data;
    else {
      // try to find nested arrays
      const potential = Object.values(data).find((v) => Array.isArray(v));
      if (potential) arr = potential;
    }

    // helper to search for futures
    function findFuture(keyword) {
      keyword = String(keyword).toLowerCase();
      for (const item of arr) {
        try {
          const js = JSON.stringify(item).toLowerCase();
          if (js.includes(keyword) && (js.includes("fut") || js.includes("future") || js.includes("fut"))) {
            // extract symbol token fields
            const sym = item.symbol || item.name || (item.tradingsymbol || item.tradingSymbol) || null;
            const tok = item.token || item.tokenId || item.exchangeToken || null;
            const expiry = item.expiry || item.expiryDate || item.expiry_date || item.date || null;
            if (sym) return { symbol: sym, token: tok ? String(tok) : null, expiry: expiry || null };
          }
        } catch (e) {}
      }
      return null;
    }

    const targets = {
      nifty: ["nifty", "nifty 50", "nifty50", "nifty30"],
      sensex: ["sensex", "sen", "s&p bse", "bse"],
      "natural gas": ["naturalgas", "natural gas", "natgas", "gas"],
    };

    const out = {};
    for (const k of Object.keys(targets)) {
      for (const trykey of targets[k]) {
        const f = findFuture(trykey);
        if (f) {
          out[k] = f;
          break;
        }
      }
    }

    // If found none, try mapping by symbol pattern: includes 'FUT'
    if (Object.keys(out).length === 0 && arr.length > 0) {
      for (const item of arr.slice(0, 500)) {
        try {
          const js = JSON.stringify(item).toLowerCase();
          if (js.includes("fut")) {
            // store as generic under guessed key
            const sym = item.symbol || item.tradingsymbol || item.name || null;
            const tok = item.token || item.exchangeToken || item.tokenId || null;
            if (sym && tok) {
              // heuristics: if symbol contains 'nifty' -> nifty, 'sensex' -> sensex etc
              if (sym.toLowerCase().includes("nifty")) out.nifty = { symbol: sym, token: String(tok) };
              else if (sym.toLowerCase().includes("sensex") || sym.toLowerCase().includes("sen")) out.sensex = { symbol: sym, token: String(tok) };
              else if (sym.toLowerCase().includes("natural")) out["natural gas"] = { symbol: sym, token: String(tok) };
            }
          }
        } catch (e) {}
      }
    }

    // If still empty, return partial with note
    runtime.auto_tokens = out;
    return { ok: true, source: "instruments", tokens: out };
  } catch (err) {
    // return failure but not fatal
    return { ok: false, reason: "INSTR_FETCH_FAILED", detail: String(err) };
  }
}

// -----------------------------
// Basic HTTP LTP fetch for futures
// Uses auto_tokens to lookup token and then fetch LTP via SmartAPI HTTP route
// Response: { ok: true, ltp: Number, raw: ... } or { ok: false, reason, detail }
// -----------------------------
async function fetchFutureLTP(marketKey = "nifty") {
  try {
    const info = runtime.auto_tokens && runtime.auto_tokens[marketKey];
    if (!info || !info.token) {
      return { ok: false, reason: "NO_TOKEN", detail: "No auto token for market" };
    }

    // Example LTP URL format - replace with real SmartAPI HTTP LTP endpoint if different
    // Many SmartAPI providers: GET /market/ltp?token=XXXX or POST with tokens array
    const ltpUrlTemplate = process.env.SMARTAPI_LTP_URL || "https://api.smartapi.example/market/ltp?token={token}";
    const url = ltpUrlTemplate.replace("{token}", encodeURIComponent(info.token));

    const resp = await fetch(url, { method: "GET" });
    const txt = await resp.text();
    const data = safeParseJson(txt, null);
    if (!data) return { ok: false, reason: "INVALID_LTP_JSON", detail: txt };

    // common shapes: { data: { ltp: 1234 } } or { ltp: 1234 } or array of objects
    let ltp = null;
    if (typeof data === "object") {
      if (data.ltp) ltp = pnum(data.ltp, null);
      else if (data.data && (data.data.ltp || data.data.lastPrice)) ltp = pnum(data.data.ltp || data.data.lastPrice, null);
      else if (Array.isArray(data.data) && data.data[0] && (data.data[0].ltp || data.data[0].lastPrice)) ltp = pnum(data.data[0].ltp || data.data[0].lastPrice, null);
      else {
        // try to find numeric in nested
        const js = JSON.stringify(data);
        const m = js.match(/\b\d+(\.\d+)?\b/);
        if (m) ltp = pnum(m[0], null);
      }
    }

    if (ltp === null) {
      return { ok: false, reason: "LTP_NOT_FOUND", raw: data };
    }
    return { ok: true, ltp, raw: data };
  } catch (err) {
    return { ok: false, reason: "LTP_FETCH_ERROR", detail: String(err) };
  }
}

// -----------------------------
// Fallback helper: attempt to fill runtime.auto_tokens from provided token array
// Accepts an array or object from user-provided tokens to set runtime.auto_tokens safely.
// -----------------------------
function setFallbackAutoTokens(obj) {
  try {
    if (!obj || typeof obj !== "object") return false;
    const out = {};
    // allow both keyed by name or array list
    if (Array.isArray(obj)) {
      obj.forEach((x) => {
        if (x && x.symbol) {
          const key = (x.name || x.symbol || "").toString().toLowerCase();
          out[key] = { symbol: x.symbol, token: x.token ? String(x.token) : null, expiry: x.expiry || null };
        }
      });
    } else {
      Object.keys(obj).forEach((k) => {
        const v = obj[k];
        if (v && v.symbol) out[k] = { symbol: v.symbol, token: v.token ? String(v.token) : null, expiry: v.expiry || null };
      });
    }
    runtime.auto_tokens = out;
    return true;
  } catch (e) {
    return false;
  }
}

// -----------------------------
// Quick /api/test and small helpers for debugging
// -----------------------------
app.get("/api/ping", (req, res) => {
  res.json(okResponse({ app: "Trading Helper Backend", uptimeSec: Math.floor(process.uptime()) }));
});

// Expose simple status
app.get("/api/status", (req, res) => {
  res.json(
    okResponse({
      runtime: {
        feed_token: runtime.feed_token ? "<present>" : null,
        last_login: runtime.last_login,
        last_login_ok: runtime.last_login_ok,
        auto_tokens: runtime.auto_tokens,
      },
    })
  );
});

// POST /api/login -> trigger SmartAPI login and fetch auto tokens
app.post("/api/login", async (req, res) => {
  try {
    const loginResp = await smartLogin();
    // try fetch auto tokens after login
    const tokensResp = await fetchAutoFutureTokens();

    // If smartLogin failed but fallback tokens available, accept fallback
    if (!loginResp.ok && tokensResp.ok && Object.keys(tokensResp.tokens || {}).length > 0) {
      runtime.auto_tokens = tokensResp.tokens;
      return res.json(okResponse({ message: "Login failed but fallback tokens applied", login: loginResp, auto_tokens: runtime.auto_tokens }));
    }

    // Normal success response
    if (loginResp.ok) {
      // if fetchAutoFutureTokens returned tokens, merge
      if (tokensResp && tokensResp.ok && tokensResp.tokens) {
        runtime.auto_tokens = Object.assign({}, runtime.auto_tokens, tokensResp.tokens || {});
      }
      return res.json(okResponse({ message: "SmartAPI Logged-In", login: loginResp, auto_tokens: runtime.auto_tokens }));
    }

    // otherwise return error info
    return res.json(errResponse("Login failed", { login: loginResp }));
  } catch (err) {
    return res.json(errResponse("Login exception", { detail: String(err) }));
  }
});

// POST /api/autofetch -> explicit trigger to refresh auto future tokens (non-blocking)
app.post("/api/autofetch", async (req, res) => {
  try {
    const r = await fetchAutoFutureTokens();
    if (r.ok) {
      runtime.auto_tokens = r.tokens || runtime.auto_tokens;
      return res.json(okResponse({ message: "Auto tokens fetched", tokens: runtime.auto_tokens }));
    } else {
      return res.json(errResponse("Auto fetch failed", r));
    }
  } catch (err) {
    return res.json(errResponse("Auto fetch exception", { detail: String(err) }));
  }
});

// POST /api/ltp -> get futures LTP for market (nifty/sensex/natural gas)
// { market: "nifty" }
app.post("/api/ltp", async (req, res) => {
  try {
    const market = (req.body && req.body.market) || "nifty";
    const r = await fetchFutureLTP(market);
    if (r.ok) {
      return res.json(okResponse({ market, live_ltp: r.ltp, raw: r.raw }));
    } else {
      // return failure with details
      return res.json(errResponse("LTP fetch failed", r));
    }
  } catch (err) {
    return res.json(errResponse("LTP exception", { detail: String(err) }));
  }
});

// -----------------------------
// Provide a safe route to accept user-supplied fallback tokens JSON
// (DEVELOPER USE) - PUT /api/fallback_tokens { tokens: {...} }
// -----------------------------
app.put("/api/fallback_tokens", (req, res) => {
  try {
    const tokens = req.body && req.body.tokens;
    if (!tokens) return res.json(errResponse("No tokens provided"));
    const ok = setFallbackAutoTokens(tokens);
    if (!ok) return res.json(errResponse("Invalid tokens format"));
    return res.json(okResponse({ message: "Fallback tokens set", tokens: runtime.auto_tokens }));
  } catch (err) {
    return res.json(errResponse("Exception", { detail: String(err) }));
  }
});

// -----------------------------
// SPA fallback (will serve frontend index if exists) - keep this near end of file
// (Part-4 will re-add/sendFile; for now placeholder to avoid crashes if frontend not present)
// -----------------------------
app.get("/", (req, res) => {
  res.json(okResponse({ msg: "Trading Helper Backend - root. Add frontend or use /api endpoints." }));
});

// -----------------------------------------------------
// End of Part-1 (imports, config, SmartAPI login, auto tokens, LTP http)
// -----------------------------------------------------
// NEXT: Part-2 will contain:
//  - Option-chain parsing helpers
//  - WebSocket V2-ready placeholders & safe stubs
//  - Basic premium-engine helper skeletons
//  - Start of premium block definitions
//
// Paste Part-2 immediately AFTER this block in the same server.js file.
// -----------------------------------------------------
// ================================
// Part-2 / Option-chain parsing + WS V2 helper + IV/Greeks
// ================================

// -- CONFIG helpers (reuse env + auto_tokens from Part-1)
const DEFAULT_RISK_FREE = 0.07; // conservative annual interest (7%) - used in BS calc
const IV_TOL = 1e-4;
const IV_MAX_ITER = 60;

// -----------------------------
// Utilities
// -----------------------------
function nowTS() { return Date.now(); }

function safeNum(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function midFromBidAsk(bid, ask) {
  const b = safeNum(bid, null);
  const a = safeNum(ask, null);
  if (b === null && a === null) return null;
  if (b === null) return a;
  if (a === null) return b;
  return (b + a) / 2;
}

// convert days -> year fraction for options (actual/365)
function daysToYears(d) {
  if (!d || d <= 0) return 1/365;
  return Math.max(d / 365, 1/36500);
}

// Black-Scholes (European) — returns option price given vol (sigma)
function ndist(x) {
  // Cumulative normal distribution (approx)
  // Abramowitz & Stegun approximation
  const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741;
  const a4 = -1.453152027, a5 = 1.061405429;
  const p = 0.3275911;
  const sign = x < 0 ? -1 : 1;
  const absx = Math.abs(x) / Math.sqrt(2);
  const t = 1 / (1 + p * absx);
  const y = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-absx * absx);
  return 0.5 * (1 + sign * y);
}

function blackScholesPrice(type, S, K, T, r, sigma, q = 0) {
  // S: spot, K: strike, T: time(years), r: rate, sigma: vol, q: dividend yield (set 0)
  if (T <= 0) {
    // immediate payoff
    if (type === "CE") return Math.max(S - K, 0);
    return Math.max(K - S, 0);
  }
  if (sigma <= 0) {
    // forward price approximation
    const f = S * Math.exp(-q * T);
    if (type === "CE") return Math.max(f - K * Math.exp(-r * T), 0);
    return Math.max(K * Math.exp(-r * T) - f, 0);
  }
  const sqrtT = Math.sqrt(T);
  const d1 = (Math.log(S / K) + (r - q + 0.5 * sigma * sigma) * T) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  const Nd1 = ndist(d1);
  const Nd2 = ndist(d2);
  if (type === "CE") {
    return S * Math.exp(-q * T) * Nd1 - K * Math.exp(-r * T) * Nd2;
  } else {
    // Put
    return K * Math.exp(-r * T) * ndist(-d2) - S * Math.exp(-q * T) * ndist(-d1);
  }
}

// Implied vol via bisection (stable)
function impliedVolBisection(type, marketPrice, S, K, T, r, q = 0) {
  if (marketPrice === null || marketPrice <= 0) return null;
  // quick bounds
  let low = 1e-6, high = 5.0;
  // if price is greater than BS at high, return high
  let priceHigh = blackScholesPrice(type, S, K, T, r, high, q);
  if (marketPrice > priceHigh) return high;
  // bisection loop
  for (let i = 0; i < IV_MAX_ITER; i++) {
    const mid = 0.5 * (low + high);
    const price = blackScholesPrice(type, S, K, T, r, mid, q);
    const diff = price - marketPrice;
    if (Math.abs(diff) < IV_TOL) return mid;
    // choose side
    const priceLow = blackScholesPrice(type, S, K, T, r, low, q);
    // monotonic in sigma -> sign check
    if ((priceLow - marketPrice) * (diff) <= 0) {
      high = mid;
    } else {
      low = mid;
    }
  }
  return 0.5 * (low + high);
}

// Simple Greeks (Delta only — for reference)
function approxDelta(type, S, K, T, r, sigma, q = 0) {
  const eps = 1e-4 * Math.max(1, S);
  const p1 = blackScholesPrice(type, S + eps, K, T, r, sigma, q);
  const p0 = blackScholesPrice(type, S - eps, K, T, r, sigma, q);
  return (p1 - p0) / (2 * eps);
}

// -----------------------------
// Option-chain fetch + parse
// -----------------------------
//
// Expected SmartAPI response formats vary; this function is robust:
// - Accepts full JSON arrays or {data: [...]}, or nested shapes
// - Tries to find FUT (future symbol) to decide mapping
//
// Requires: auto_tokens[market] object from Part-1 (symbol + token)
// Fallback: caller can pass a symbol lookup string in info.lookup
//

async function fetchOptionChainHTTP(market, info = {}) {
  // info may include: symbol, feed_token, timeout, fetchTokenUrl override
  // We rely on SmartAPI token endpoints from Part-1 code (e.g. login returned tokens)
  // Build endpoint — try several common SmartAPI endpoints
  const fut = (auto_tokens && auto_tokens[market] && auto_tokens[market].symbol) || info.symbol;
  const basePaths = [
    // common SmartAPI endpoints patterns (HTTP)
    `/api/option-chain/${encodeURIComponent(fut || market)}`,
    `/option-chain/${encodeURIComponent(fut || market)}`,
    `/v3/option-chain/${encodeURIComponent(fut || market)}`,
    `/api/v1/option-chain/${encodeURIComponent(fut || market)}`
  ];
  const tries = basePaths.length;
  let lastErr = null;
  for (let i = 0; i < tries; i++) {
    const path = basePaths[i];
    try {
      const url = (process.env.SMART_API_BASE || "").replace(/\/$/, "") + path;
      const reqHeaders = {
        "Accept": "application/json",
        "Content-Type": "application/json",
      };
      // include session auth if available (SMART_* envs) - Part-1 handled login
      if (typeof SMART_USER_ID !== "undefined" && SMART_USER_ID) {
        reqHeaders["X-User-Id"] = SMART_USER_ID;
      }
      const resp = await fetch(url, { method: "GET", headers: reqHeaders, timeout: 10000 });
      if (!resp || resp.status >= 400) {
        lastErr = new Error("Option chain fetch failed: " + (resp && resp.status));
        continue;
      }
      const data = await resp.json().catch(() => null);
      if (!data) { lastErr = new Error("Empty JSON"); continue; }
      return { ok: true, raw: data, source: url };
    } catch (e) {
      lastErr = e;
      continue;
    }
  }
  return { ok: false, error: lastErr ? String(lastErr) : "no-response" };
}

// Robust parser to normalize option chain to array of rows
function normalizeOptionChain(raw) {
  if (!raw) return [];
  // try common shapes
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw.data)) return raw.data;
  if (Array.isArray(raw.records)) return raw.records;
  // search for any nested array
  const queue = [raw];
  while (queue.length) {
    const node = queue.shift();
    if (!node || typeof node !== "object") continue;
    for (const k of Object.keys(node)) {
      if (Array.isArray(node[k])) return node[k];
      if (node[k] && typeof node[k] === "object") queue.push(node[k]);
    }
  }
  return [];
}

// parse a single row into normalized cell
function parseRow(row) {
  // possible keys: strikePrice / strike / price, CE/PE nested objects etc.
  // attempt to detect CE object
  const out = {
    strike: null,
    expiry: null,
    CE: null,
    PE: null,
    raw: row
  };
  try {
    // strike
    if (row.strikePrice !== undefined) out.strike = safeNum(row.strikePrice, null);
    else if (row.strike !== undefined) out.strike = safeNum(row.strike, null);
    else if (row.strike_price !== undefined) out.strike = safeNum(row.strike_price, null);
    else if (row.instrument && row.instrument.strike) out.strike = safeNum(row.instrument.strike, null);
    // expiry
    if (row.expiryDate) out.expiry = row.expiryDate;
    else if (row.expiry) out.expiry = row.expiry;
    // CE / PE potential nested shapes
    if (row.CE || row.ce) out.CE = row.CE || row.ce;
    if (row.PE || row.pe) out.PE = row.PE || row.pe;
    // sometimes the row itself is CE or PE object
    if (row.optionType && (row.optionType === "CE" || row.optionType === "PE")) {
      const t = row.optionType;
      if (t === "CE") out.CE = row;
      else out.PE = row;
    }
    // normalize CE/PE fields if present
    ["CE", "PE"].forEach((t) => {
      if (!out[t]) return;
      const o = out[t];
      // common fields: lastPrice / ltp / LTP, bidQty, bidprice, askPrice, oi
      const norm = {
        ltp: null, bid: null, ask: null, oi: null, volume: null,
        bidQty: null, askQty: null, strike: out.strike
      };
      norm.ltp = (o.lastPrice || o.ltp || o.LTP || o.last_price) ? safeNum(o.lastPrice || o.ltp || o.LTP || o.last_price, null) : null;
      norm.bid = (o.bidPrice || o.bid || o.buyPrice) ? safeNum(o.bidPrice || o.bid || o.buyPrice, null) : null;
      norm.ask = (o.askPrice || o.ask || o.sellPrice) ? safeNum(o.askPrice || o.ask || o.sellPrice, null) : null;
      norm.oi = (o.openInterest || o.oi) ? safeNum(o.openInterest || o.oi, null) : null;
      norm.volume = (o.volume || o.totalTradedVolume) ? safeNum(o.volume || o.totalTradedVolume, null) : null;
      norm.bidQty = (o.bidQty || o.bidQty) ? safeNum(o.bidQty || o.bidQty, null) : null;
      norm.askQty = (o.askQty || o.askQty) ? safeNum(o.askQty || o.askQty, null) : null;
      // attach computed mid
      norm.mid = midFromBidAsk(norm.bid, norm.ask);
      out[t] = norm;
    });
  } catch (e) {
    // safe fallback
  }
  return out;
}

// Build normalized chain map: strike -> {strike, expiry, CE, PE}
function buildChainMap(rows) {
  const normalized = rows.map(parseRow);
  const map = new Map();
  normalized.forEach((r) => {
    const strike = r.strike;
    if (strike === null || typeof strike === "undefined") return;
    const key = String(strike);
    const val = map.get(key) || { strike: strike, expiry: r.expiry || null, CE: null, PE: null, raw: [] };
    if (r.CE) val.CE = r.CE;
    if (r.PE) val.PE = r.PE;
    val.raw.push(r.raw);
    map.set(key, val);
  });
  // convert to array sorted by strike ascending
  const arr = Array.from(map.values()).sort((a,b) => a.strike - b.strike);
  return arr;
}

// Calculate PCR for one expiry or entire chain
function calculatePCR(chainArr) {
  // PCR = sum(PE OI) / sum(CE OI)
  let peOi = 0, ceOi = 0;
  for (const s of chainArr) {
    if (s.PE && s.PE.oi) peOi += safeNum(s.PE.oi, 0);
    if (s.CE && s.CE.oi) ceOi += safeNum(s.CE.oi, 0);
  }
  const pcr = ceOi <= 0 ? null : (peOi / ceOi);
  return { peOi, ceOi, pcr };
}

// Find nearest strike(s) relative to spot
function findNearestStrikes(chainArr, spot, distanceStep = 50) {
  if (!Array.isArray(chainArr) || chainArr.length === 0) return [];
  spot = safeNum(spot, 0);
  // find index with minimum |strike - spot|
  let best = null, bestIdx = -1;
  for (let i=0;i<chainArr.length;i++){
    const d = Math.abs(chainArr[i].strike - spot);
    if (best === null || d < best) { best = d; bestIdx = i; }
  }
  // return nearest and +/- a few strikes: [idx-2 .. idx+2] bounded
  const out = [];
  for (let j = Math.max(0, bestIdx-3); j <= Math.min(chainArr.length-1, bestIdx+3); j++) out.push(chainArr[j]);
  return out;
}

// Full parse pipeline: fetch -> normalize -> map -> compute IV/Greeks per option
async function getOptionChainSummary(market, opts = {}) {
  // opts: { symbol, spot, daysToExpiry, riskFree }
  const symbol = opts.symbol || (auto_tokens && auto_tokens[market] && auto_tokens[market].symbol) || market;
  const fetchResp = await fetchOptionChainHTTP(market, { symbol });
  if (!fetchResp.ok) return { ok: false, error: fetchResp.error || "fetch_failed" };
  const rows = normalizeOptionChain(fetchResp.raw);
  if (!rows || rows.length === 0) return { ok: false, error: "no_chain_rows", raw: fetchResp.raw };
  const chainArr = buildChainMap(rows);
  // compute totals / pcr
  const pcr = calculatePCR(chainArr);
  // optionally compute implied vol and delta for nearest strikes if spot provided
  const spot = typeof opts.spot !== "undefined" ? safeNum(opts.spot, null) : null;
  const dte = typeof opts.daysToExpiry !== "undefined" ? safeNum(opts.daysToExpiry, 1) : 1;
  const rf = typeof opts.riskFree !== "undefined" ? safeNum(opts.riskFree, DEFAULT_RISK_FREE) : DEFAULT_RISK_FREE;
  const T = daysToYears(dte);
  // enhance chain with iv/mid/delta
  for (const s of chainArr) {
    // prefer mid price; fallback to ltp
    const ceMid = s.CE ? (s.CE.mid || s.CE.ltp) : null;
    const peMid = s.PE ? (s.PE.mid || s.PE.ltp) : null;
    s.CE = s.CE || null;
    s.PE = s.PE || null;
    s.CE = s.CE ? Object.assign({}, s.CE, { midPrice: ceMid }) : null;
    s.PE = s.PE ? Object.assign({}, s.PE, { midPrice: peMid }) : null;

    // IV calculations if spot and midPrice available
    if (spot !== null) {
      if (s.CE && s.CE.midPrice !== null) {
        const iv = impliedVolBisection("CE", s.CE.midPrice, spot, s.strike, T, rf);
        s.CE.iv = iv === null ? null : Number(iv.toFixed(4));
        s.CE.delta = s.CE.iv ? Number(approxDelta("CE", spot, s.strike, T, rf, s.CE.iv).toFixed(4)) : null;
      } else s.CE.iv = s.CE.delta = null;
      if (s.PE && s.PE.midPrice !== null) {
        const iv = impliedVolBisection("PE", s.PE.midPrice, spot, s.strike, T, rf);
        s.PE.iv = iv === null ? null : Number(iv.toFixed(4));
        s.PE.delta = s.PE.iv ? Number(approxDelta("PE", spot, s.strike, T, rf, s.PE.iv).toFixed(4)) : null;
      } else s.PE.iv = s.PE.delta = null;
    } else {
      if (s.CE) { s.CE.iv = null; s.CE.delta = null; }
      if (s.PE) { s.PE.iv = null; s.PE.delta = null; }
    }
  }

  // totals & summary
  const nearest = spot !== null ? findNearestStrikes(chainArr, spot) : [];
  return {
    ok: true,
    source: fetchResp.source,
    summary: {
      totalStrikes: chainArr.length,
      nearest,
      pcr,
      generatedAt: nowTS()
    },
    chain: chainArr
  };
}

// -----------------------------
// WebSocket V2 helper (feed_token-based)
// -----------------------------
//
// This is a general-purpose WS client tuned for feed_token style V2 streams.
// It supports compression/gzip auto-decode and emits parsed messages via callback.
// Reconnects on error with exponential backoff.
//

const WS_DEFAULT_RECONNECT_MS = 2000;

function createFeedWebSocket({ wsUrl, feed_token, onMessage, onOpen, onClose, onError, autoReconnect = true }) {
  if (!wsUrl) throw new Error("wsUrl required");
  let ws = null;
  let closedByUser = false;
  let reconnectMs = WS_DEFAULT_RECONNECT_MS;
  let reconnectTimer = null;

  function connect() {
    closedByUser = false;
    // append feed_token if protocol expects it
    const u = feed_token ? (wsUrl + (wsUrl.includes("?") ? "&" : "?") + "feed_token=" + encodeURIComponent(feed_token)) : wsUrl;
    ws = new WebSocket(u);
    ws.onopen = (ev) => {
      reconnectMs = WS_DEFAULT_RECONNECT_MS;
      if (onOpen) try { onOpen(ev); } catch(e){ console.error(e); }
    };
    ws.onmessage = async (msgEv) => {
      try {
        let data = msgEv.data;
        // if data is Blob or ArrayBuffer (binary) — try decode
        if (typeof data !== "string") {
          // ArrayBuffer or Blob
          const buf = data instanceof Blob ? await data.arrayBuffer() : data;
          // try ungzip
          try {
            const zbuf = Buffer.from(buf);
            // use zlib to attempt inflate
            const infl = zlib.inflateSync(zbuf);
            const txt = infl.toString("utf8");
            data = txt;
          } catch (e) {
            // not gzipped — try utf8 text
            try { data = Buffer.from(buf).toString("utf8"); } catch (ee) { data = null; }
          }
        }
        // parse JSON if possible
        let parsed = null;
        try { parsed = JSON.parse(data); } catch (e) { parsed = data; }
        if (onMessage) try { onMessage(parsed, msgEv); } catch(e){ console.error(e); }
      } catch (err) {
        if (onError) try { onError(err); } catch(e){ console.error(e); }
      }
    };
    ws.onerror = (err) => {
      if (onError) try { onError(err); } catch(e){ console.error(e); }
    };
    ws.onclose = (ev) => {
      if (onClose) try { onClose(ev); } catch(e){ console.error(e); }
      if (!closedByUser && autoReconnect) {
        // schedule reconnect with backoff
        reconnectTimer = setTimeout(() => {
          reconnectMs = Math.min(30000, Math.floor(reconnectMs * 1.6));
          connect();
        }, reconnectMs);
      }
    };
  }

  function close() {
    closedByUser = true;
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
      try { ws.close(); } catch(e) {}
    }
    ws = null;
  }

  function send(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) throw new Error("WS not open");
    const txt = (typeof obj === "string") ? obj : JSON.stringify(obj);
    ws.send(txt);
  }

  connect();
  return { close, send, getSocket: () => ws };
}

// -----------------------------
// Convenience endpoints used by Part-3 / Part-4
// -----------------------------
//
// These are simple functions (not express endpoints) that other parts will call.
// They return normalized data that Premium Engine expects.
//
// getOptionChainForEngine(market, { spot, daysToExpiry })
//
async function getOptionChainForEngine(market, params = {}) {
  const resp = await getOptionChainSummary(market, { spot: params.spot, daysToExpiry: params.daysToExpiry || 1, riskFree: params.riskFree });
  if (!resp.ok) return resp;
  // build a smaller payload for engine: strike, CE {mid, ltp, oi, iv, delta}, PE {...}
  const compact = resp.chain.map(s => ({
    strike: s.strike,
    expiry: s.expiry,
    CE: s.CE ? { mid: s.CE.midPrice, ltp: s.CE.ltp || null, oi: s.CE.oi || 0, iv: s.CE.iv || null, delta: s.CE.delta || null } : null,
    PE: s.PE ? { mid: s.PE.midPrice, ltp: s.PE.ltp || null, oi: s.PE.oi || 0, iv: s.PE.iv || null, delta: s.PE.delta || null } : null
  }));
  const pcr = calculatePCR(resp.chain);
  return { ok: true, source: resp.source, chain: compact, pcr, generatedAt: resp.summary.generatedAt };
}

// -----------------------------
// Expose utilities to later parts (attach to global object used in server.js)
// -----------------------------
if (typeof globalThis !== "undefined") {
  globalThis.optionHelpers = globalThis.optionHelpers || {};
  Object.assign(globalThis.optionHelpers, {
    fetchOptionChainHTTP,
    normalizeOptionChain,
    buildChainMap,
    getOptionChainSummary,
    getOptionChainForEngine,
    createFeedWebSocket,
    blackScholesPrice,
    impliedVolBisection,
    DEFAULT_RISK_FREE,
    midFromBidAsk,
    calculatePCR
  });
}

// If server.js expects local functions, export via module.exports when in module context
if (typeof module !== "undefined" && module.exports) {
  module.exports = Object.assign(module.exports || {}, {
    fetchOptionChainHTTP,
    normalizeOptionChain,
    buildChainMap,
    getOptionChainSummary,
    getOptionChainForEngine,
    createFeedWebSocket,
    blackScholesPrice,
    impliedVolBisection,
    DEFAULT_RISK_FREE,
    midFromBidAsk,
    calculatePCR
  });
}

// ================================
// End of Part-2
// ================================
// ================================
// Part-3 / Premium Engine, Strike Selection & API Endpoints
// ================================

// NOTE: This part expects the following to exist in the global scope (from Part-1 / Part-2):
// - app (express instance)
// - MARKET_CONFIG
// - AUTO (auto tokens fallback)
// - optionHelpers (fetchOptionChainHTTP, getOptionChainForEngine, calculatePCR, etc.)
// - computeTrend(input), buildStrikes(input, trend), normalizeInput(body), getAutoFutureLTP(market)
// - num(), clamp(), roundToStep()
// - SMART_API_KEY, SMARTAPI_BASE, session (for login status)

if (typeof optionHelpers === "undefined") {
  console.warn("optionHelpers missing — Part-2 must be inserted before Part-3");
}

// Utility: choose strikes based on trend + chain data
function choosePremiumStrikes({ market, spot, expiry_days, trend, chainCompact }) {
  // chainCompact: array of { strike, expiry, CE: {mid, ltp, oi, iv, delta}, PE: {...} }
  // strategy:
  // - derive distances from MARKET_CONFIG baseDistances scaled by expiry_days
  const cfg = MARKET_CONFIG[market] || MARKET_CONFIG["nifty"];
  const scaled = scaleDistancesByExpiry(expiry_days, cfg.baseDistances, cfg.strikeStep);

  // Decide CE/PE distance according to trend
  let ceDist, peDist;
  if (trend.main === "UPTREND") {
    ceDist = scaled.near;
    peDist = scaled.far;
  } else if (trend.main === "DOWNTREND") {
    ceDist = scaled.far;
    peDist = scaled.near;
  } else {
    ceDist = scaled.mid;
    peDist = scaled.mid;
  }

  // Compute target strike numbers (rounded to strikeStep)
  const atm = roundToStep(spot, cfg.strikeStep);
  const ceStrike = roundToStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDist, cfg.strikeStep);
  const straddleStrike = atm;

  // helper to find nearest strike object from chainCompact
  function findStrikeObj(strikeVal) {
    // chainCompact is sorted ascending by strike (Part-2 ensured)
    const s = chainCompact.find((c) => Number(c.strike) === Number(strikeVal));
    if (s) return s;
    // fallback: nearest by absolute difference
    let best = null;
    for (const c of chainCompact) {
      if (!best || Math.abs(c.strike - strikeVal) < Math.abs(best.strike - strikeVal)) best = c;
    }
    return best;
  }

  const ceObj = findStrikeObj(ceStrike);
  const peObj = findStrikeObj(peStrike);
  const straddleObj = findStrikeObj(straddleStrike);

  // Compose recommended options with calculated money management
  function makeRec(optObj, type, strikeVal) {
    // determine midPrice preference: prefer mid then ltp
    const mid = optObj && optObj[type] ? (optObj[type].mid || optObj[type].midPrice || optObj[type].ltp || null) : null;
    const iv = optObj && optObj[type] ? optObj[type].iv || null : null;
    const delta = optObj && optObj[type] ? optObj[type].delta || null : null;
    // base risk unit: proportional to distance from ATM: smaller distance => smaller premium -> adjust entry
    const distance = Math.abs(strikeVal - spot);
    const baseSteps = Math.max(1, Math.round(distance / cfg.strikeStep));
    // entry sizing: prefer smaller entry for far strikes
    const entry = Math.max(5, baseSteps * 5);
    const stopLoss = Math.max(1, Math.round(entry * 0.6));
    const target = Math.max(1, Math.round(entry * 1.5));
    return {
      type,
      strike: strikeVal,
      distance,
      midPrice: mid,
      iv,
      delta,
      entry,
      stopLoss,
      target,
      sourceStrikeObj: optObj || null
    };
  }

  const recs = [
    makeRec(ceObj, "CE", ceObj ? ceObj.strike : ceStrike),
    makeRec(peObj, "PE", peObj ? peObj.strike : peStrike),
    makeRec(straddleObj, "STRADDLE", straddleObj ? straddleObj.strike : straddleStrike),
  ];

  return { recs, atm, scaled };
}

// Premium scoring & confidence
function scoreRecommendations(recs, chainCompact, trend, spot) {
  // For each rec: compute score based on IV, OI, delta alignment with bias, distance, liquidity
  const scores = recs.map((r) => {
    let score = 50;
    // IV: moderate IV favored (not too low, not extremely high)
    if (r.iv !== null) {
      if (r.iv < 0.15) score += 5;
      else if (r.iv < 0.3) score += 10;
      else if (r.iv < 0.6) score += 5;
      else score -= 10;
    }
    // delta: alignment with trend bias
    if (trend.bias === "CE" && r.type === "CE") score += 10;
    if (trend.bias === "PE" && r.type === "PE") score += 10;
    // liquidity heuristic: presence of oi & midPrice
    const liquidity = (r.sourceStrikeObj && ((r.type === "CE" && r.sourceStrikeObj.CE && r.sourceStrikeObj.CE.oi) || (r.type === "PE" && r.sourceStrikeObj.PE && r.sourceStrikeObj.PE.oi))) ? 1 : 0;
    score += liquidity * 5;
    // distance penalty (far strikes lower score)
    const distPenalty = Math.min(20, Math.round(Math.abs(r.distance) / (spot * 0.005 + 1)));
    score -= distPenalty;
    // normalize 0-100
    score = clamp(Math.round(score), 0, 100);
    return Object.assign({}, r, { score });
  });

  // overall confidence: average
  const confidence = Math.round(scores.reduce((s, x) => s + x.score, 0) / (scores.length || 1));

  return { scored: scores, confidence };
}

// Helper: enrich strikes with option mid/iv/delta if not already present via optionHelpers
async function enrichStrikesWithChainData(market, recs) {
  // prefer to call getOptionChainForEngine and map by strike
  const chainResp = await (optionHelpers && optionHelpers.getOptionChainForEngine ? optionHelpers.getOptionChainForEngine(market, { spot: recs._spot || undefined, daysToExpiry: recs._dte || 1 }) : null);
  // if chainResp not available, rely on recs' source data
  if (!chainResp || !chainResp.ok) return recs; // nothing to enrich
  const map = new Map();
  for (const c of chainResp.chain) map.set(String(c.strike), c);
  // enrich each rec
  const out = recs.map(r => {
    const s = map.get(String(r.strike));
    if (s) {
      const copy = Object.assign({}, r);
      if (r.type === "CE" && s.CE) {
        copy.midPrice = copy.midPrice || s.CE.mid;
        copy.iv = copy.iv || s.CE.iv;
        copy.delta = copy.delta || s.CE.delta;
      } else if (r.type === "PE" && s.PE) {
        copy.midPrice = copy.midPrice || s.PE.mid;
        copy.iv = copy.iv || s.PE.iv;
        copy.delta = copy.delta || s.PE.delta;
      } else if (r.type === "STRADDLE") {
        // attempt to fill both sides
        copy.ce_mid = s.CE ? s.CE.mid : null;
        copy.pe_mid = s.PE ? s.PE.mid : null;
        copy.midPrice = copy.midPrice || (copy.ce_mid && copy.pe_mid ? (copy.ce_mid + copy.pe_mid) : copy.ce_mid || copy.pe_mid);
      }
      return copy;
    }
    return r;
  });
  return out;
}

// ==============================
// API endpoints for Premium Engine
// ==============================

// 1) Option chain summary (direct)
app.get("/api/optionchain/summary", async (req, res) => {
  const market = (req.query.market || "nifty").toString().toLowerCase();
  const spot = safeNum(req.query.spot, null);
  const dte = safeNum(req.query.expiry_days, 1);
  try {
    const resp = await optionHelpers.getOptionChainForEngine(market, { spot: spot, daysToExpiry: dte });
    if (!resp || !resp.ok) return res.json({ success: false, error: resp && resp.error ? resp.error : "no_data" });
    return res.json({ success: true, summary: resp });
  } catch (err) {
    return res.json({ success: false, error: err.message || String(err) });
  }
});

// 2) Premium recommendations endpoint
app.post("/api/premium", async (req, res) => {
  try {
    // normalize input using Part-1's normalizeInput
    const input = normalizeInput(req.body || {});
    const market = input.market;
    // if use_live requested, try to fetch live LTP to set spot
    if (input.use_live) {
      const ltpResp = await getAutoFutureLTP(market);
      if (ltpResp.ok && ltpResp.ltp) {
        input.spot = num(ltpResp.ltp, input.spot);
      } // else keep existing spot from input
    }

    // compute trend using existing engine
    const trend = computeTrend(input);

    // fetch option chain compact for engine
    const chainResp = await optionHelpers.getOptionChainForEngine(market, { spot: input.spot, daysToExpiry: input.expiry_days, riskFree: optionHelpers.DEFAULT_RISK_FREE });
    if (!chainResp || !chainResp.ok) {
      // fallback: return basic strikes computed by buildStrikes
      const fallbackStrikes = buildStrikes(input, trend);
      return res.json({
        success: true,
        message: "Calculation complete (fallback chain)",
        input,
        trend,
        strikes: fallbackStrikes,
        auto_tokens: AUTO,
        meta: { live_data_used: input.use_live, chain_found: false }
      });
    }

    // chainCompact arranged
    const chainCompact = chainResp.chain || [];
    // choose recommended strikes
    const choice = choosePremiumStrikes({ market, spot: input.spot, expiry_days: input.expiry_days, trend, chainCompact });
    // enrich recs with chain data via optionHelpers map
    let recs = await enrichStrikesWithChainData(market, choice.recs);
    // attach spot/dte for potential enrichment
    recs._spot = input.spot; recs._dte = input.expiry_days;
    // compute scoring
    const scored = scoreRecommendations(recs, chainCompact, trend, input.spot);

    // finalize format for response: include midPrice/iv/delta/entry/SL/target and scores
    const formatted = scored.scored.map((s) => ({
      type: s.type,
      strike: s.strike,
      distance: s.distance,
      midPrice: s.midPrice || null,
      iv: s.iv || null,
      delta: s.delta || null,
      entry: s.entry,
      stopLoss: s.stopLoss,
      target: s.target,
      score: s.score,
    }));

    return res.json({
      success: true,
      message: "Premium calculation complete",
      input,
      trend,
      auto_tokens: AUTO,
      pcr: chainResp.pcr || null,
      generatedAt: chainResp.generatedAt || Date.now(),
      recommendations: formatted,
      confidence: scored.confidence,
      meta: { chainSource: chainResp.source || null, chainLength: chainCompact.length }
    });
  } catch (err) {
    return res.json({ success: false, error: err.message || String(err) });
  }
});

// 3) convenience /api/strikeprice endpoint to compute mid market estimated price for a given strike
app.post("/api/strikeprice", async (req, res) => {
  // body: { market, strike, type, spot, expiry_days, riskFree }
  try {
    const market = (req.body.market || "nifty").toString().toLowerCase();
    const type = (req.body.type || "CE").toString().toUpperCase();
    const strike = num(req.body.strike, null);
    if (!strike) return res.json({ success: false, error: "strike_missing" });
    const spot = num(req.body.spot, null);
    const dte = num(req.body.expiry_days, 1);
    const rf = num(req.body.riskFree, optionHelpers.DEFAULT_RISK_FREE);
    // fetch chain to get mid/iv if available
    const chain = await optionHelpers.getOptionChainForEngine(market, { spot, daysToExpiry: dte, riskFree: rf });
    let mid = null, iv = null;
    if (chain && chain.ok) {
      const s = chain.chain.find((c) => Number(c.strike) === Number(strike));
      if (s) {
        if (type === "CE" && s.CE) { mid = s.CE.mid; iv = s.CE.iv; }
        if (type === "PE" && s.PE) { mid = s.PE.mid; iv = s.PE.iv; }
      }
    }
    // If mid not found but spot given, estimate via Black-Scholes using an assumed vol (e.g., 0.25)
    if (mid === null && spot !== null) {
      const T = daysToYears(dte);
      const assumedVol = 0.25;
      const est = blackScholesPrice(type, spot, strike, T, rf, assumedVol);
      mid = est;
      // compute implied vol from est (should be identical to assumedVol)
      iv = assumedVol;
    }
    return res.json({ success: true, market, type, strike, midPrice: mid, iv });
  } catch (err) {
    return res.json({ success: false, error: err.message || String(err) });
  }
});

// Attach premium helpers to global for debug / reuse
globalThis.premiumEngine = {
  choosePremiumStrikes,
  scoreRecommendations,
  enrichStrikesWithChainData,
  getOptionChainForEngine: optionHelpers.getOptionChainForEngine,
};

// ================================
// End of Part-3
// ================================
// ======================================================
// PART-4 — FEED-V2 WEBSOCKET (SmartAPI) + FINAL STARTUP
// ======================================================

const WebSocket = require("ws");

/*
    FEED-V2 WebSocket:
    -----------------------------------
    SmartAPI FEED-v2 format uses:
    wss://smartapisocket.angelone.in/v2/stream?token=<feedToken>&user=<clientcode>

    This WebSocket is OPTIONAL for price streaming, 
    but we integrate it FULLY here.

    It will auto-connect after login,
    and will auto-reconnect if dropped.
*/

let ws = null;
let wsConnected = false;
let wsReconnectTimer = null;

// active subscriptions map
const liveSubscriptions = new Map();

// Start WebSocket
function startFeedV2() {
    if (!session.feed_token || !SMART_USER_ID) {
        console.log("FeedV2 not starting: feed_token missing.");
        return;
    }

    const url = `wss://smartapisocket.angelone.in/v2/stream?token=${session.feed_token}&user=${SMART_USER_ID}`;
    console.log("Connecting Feed-V2:", url);

    ws = new WebSocket(url);

    ws.on("open", () => {
        wsConnected = true;
        console.log("FEED-V2 CONNECTED ✔");

        // Resubscribe previous tokens
        if (liveSubscriptions.size > 0) {
            for (const [key, sub] of liveSubscriptions) {
                ws.send(JSON.stringify(sub));
            }
        }
    });

    ws.on("message", (msg) => {
        try {
            const data = JSON.parse(msg.toString());
            console.log("Feed-V2 Tick:", data);
        } catch (err) {
            console.log("Feed-V2 Parse Error:", err.message);
        }
    });

    ws.on("close", () => {
        wsConnected = false;
        console.log("FEED-V2 DISCONNECTED ❌");
        reconnectFeed();
    });

    ws.on("error", (err) => {
        console.log("FEED-V2 ERROR:", err);
        ws.close();
    });
}

// Auto-Reconnect
function reconnectFeed() {
    if (wsReconnectTimer) return;
    wsReconnectTimer = setTimeout(() => {
        wsReconnectTimer = null;
        console.log("FEED-V2 RECONNECTING…");
        startFeedV2();
    }, 5000);
}

// Subscribe to LTP stream
function subscribeLTP(exchange, token) {
    if (!wsConnected) return;

    const sub = {
        action: "subscribe",
        key: `${exchange}|${token}`
    };

    liveSubscriptions.set(`${exchange}|${token}`, sub);
    ws.send(JSON.stringify(sub));
}

// API to subscribe
app.post("/api/stream/subscribe", (req, res) => {
    const exchange = req.body.exchange || "";
    const token = req.body.token || "";

    if (!exchange || !token)
        return res.json({ success: false, error: "Missing exchange/token" });

    subscribeLTP(exchange, token);

    return res.json({
        success: true,
        subscribed: `${exchange}|${token}`
    });
});

// =============================================
// AFTER LOGIN → START FEED-V2
// =============================================
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

    // Start websocket now
    startFeedV2();

    res.json({
        success: true,
        message: "SmartAPI Login Successful + Feed-V2 Started",
        session: {
            logged_in: true,
            expires_at: session.expires_at,
        },
    });
});

// =============================================
// FINAL SERVER START
// =============================================
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
    console.log("====================================================");
    console.log(" FINAL BACKEND READY ✔✔✔");
    console.log(" SmartAPI Login + AutoTokens + Premium Engine ");
    console.log(" Option-Chain Engine + Feed-V2 WebSocket ACTIVE");
    console.log(" Running on PORT:", PORT);
    console.log("====================================================");
});
