// engines/optionChain.js
// Robust chain fetcher: prefers instrument token lookup via global.resolveInstrumentToken
// Falls back to tradingsymbol construction if token not found.
// Uses axios with SMART API headers (ACCESS_TOKEN required in env).

const axios = require("axios");

// Market Tokens (spot + expiry detection)
const MARKET_INFO = {
  nifty: { spotToken: "99926000", exchange: "NSE", ocExchange: "NFO" },
  sensex: { spotToken: "1", exchange: "BSE", ocExchange: "BFO" },
  natural_gas: { spotToken: "224", exchange: "MCX", ocExchange: "MCX" }
};

// -------------------
// Fetch SPOT price
// -------------------
async function autoDetectSpot(market) {
  const m = MARKET_INFO[market];
  if (!m) return null;
  try {
    const res = await axios.post(
      "https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote",
      { exchange: m.exchange, symboltoken: m.spotToken },
      { headers: { "X-PrivateKey": process.env.SMART_API_KEY, "Authorization": `Bearer ${process.env.ACCESS_TOKEN}` } }
    );
    return Number(res.data?.data?.ltp || 0);
  } catch (err) {
    console.log("autoDetectSpot error:", err && err.message ? err.message : err);
    return null;
  }
}

// -------------------
// Auto Detect Expiry
// -------------------
async function autoDetectExpiry(market) {
  try {
    const res = await axios.get(`https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/expiry?exchange=${MARKET_INFO[market].ocExchange}`, {
      headers: { "X-PrivateKey": process.env.SMART_API_KEY, "Authorization": `Bearer ${process.env.ACCESS_TOKEN}` }
    });
    const arr = res.data?.data || [];
    if (!arr.length) return null;
    const nearest = arr[0];
    const today = new Date();
    const exp = new Date(nearest);
    const diff = Math.ceil((exp - today) / (1000 * 60 * 60 * 24));
    return { date: nearest, daysLeft: diff };
  } catch (err) {
    console.log("autoDetectExpiry error:", err && err.message ? err.message : err);
    return null;
  }
}

// -------------------
// Fetch single option
// Accepts either tradingsymbol OR symboltoken depending on byToken flag
// -------------------
async function fetchOption(symbolOrToken, m, byToken = false) {
  try {
    const payload = byToken ? { exchange: m.ocExchange, symboltoken: String(symbolOrToken) } : { exchange: m.ocExchange, tradingsymbol: String(symbolOrToken) };
    const r = await axios.post("https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote", payload, {
      headers: { "X-PrivateKey": process.env.SMART_API_KEY, "Authorization": `Bearer ${process.env.ACCESS_TOKEN}` },
      timeout: 8000
    });
    return {
      ltp: Number(r.data?.data?.ltp || 0),
      iv: Number(r.data?.data?.iv || 0),
      oi: Number(r.data?.data?.oi || 0),
      volume: Number(r.data?.data?.volume || 0)
    };
  } catch (err) {
    // log minimal details for debug but not too verbose
    // console.log("fetchOption error for", symbolOrToken, err && err.message ? err.message : err);
    return { ltp: 0, iv: 0, oi: 0, volume: 0 };
  }
}

// -------------------
// Fetch Option Chain strikes (preferred token-first)
// candidates: [{strike, market}, ...]
// -------------------
async function fetchChain(market, expiry, candidates) {
  const m = MARKET_INFO[market];
  if (!m) return [];

  const final = [];

  for (const c of candidates) {
    const strike = c.strike;
    // Resolve tokens via global resolver if available
    let resolvedCE = null;
    let resolvedPE = null;
    try {
      if (typeof global.resolveInstrumentToken === "function") {
        // Try CE first
        resolvedCE = global.resolveInstrumentToken(market, strike, "CE", expiry) || null;
        resolvedPE = global.resolveInstrumentToken(market, strike, "PE", expiry) || null;
      }
    } catch (e) {
      resolvedCE = null; resolvedPE = null;
    }

    // Prepare symbol names fallback style (naive fallback)
    const underlyingPrefix = market === "nifty" ? "NIFTY" : market === "sensex" ? "SENSEX" : "NATURALGAS";
    const ceSymFallback = `${underlyingPrefix}${strike}CE`;
    const peSymFallback = `${underlyingPrefix}${strike}PE`;

    // If resolved token/tradingsymbol present prefer token (byToken true)
    const ceFetch = resolvedCE && resolvedCE.token ? fetchOption(resolvedCE.token, m, true) : fetchOption(resolvedCE && resolvedCE.tradingsymbol ? resolvedCE.tradingsymbol : ceSymFallback, m, false);
    const peFetch = resolvedPE && resolvedPE.token ? fetchOption(resolvedPE.token, m, true) : fetchOption(resolvedPE && resolvedPE.tradingsymbol ? resolvedPE.tradingsymbol : peSymFallback, m, false);

    const [ce, pe] = await Promise.all([ceFetch, peFetch]);

    final.push({ strike, ce, pe });
  }

  return final;
}

module.exports = { autoDetectSpot, autoDetectExpiry, fetchChain, fetchOption };
