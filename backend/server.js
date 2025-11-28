/* ============================================================
   Trading Helper Backend (FINAL PRO VERSION)
   SmartAPI Login + Auto FUT Token via Scrip Master +
   Live FUT LTP + Trend Engine + Smart Strikes
   Markets: Nifty, Sensex, Natural Gas
   ============================================================ */

const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));

// ------------------------------------------------------------
// CONFIG (ENV से लेना होगा Render पर)
// ------------------------------------------------------------

const API_KEY = process.env.SMART_API_KEY;
const API_SECRET = process.env.SMART_API_SECRET;
const CLIENT_CODE = process.env.SMART_USER_ID;
const TOTP = process.env.SMART_TOTP;

// Login Tokens
let AUTH_TOKEN = null;
let FEED_TOKEN = null;

// Cached FUT tokens
let AUTO_TOKENS = {
    nifty: null,
    sensex: null,
    "natural gas": null
};

// -----------------------------
// Utility: SHA256
// -----------------------------
function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

// -----------------------------
// LOGIN FUNCTION
// -----------------------------
async function smartLogin() {
    try {
        const hash = sha256(CLIENT_CODE + API_SECRET + TOTP);

        const res = await fetch(
            "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/loginByPassword",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-ClientLocalIP": "127.0.0.1",
                    "X-ClientPublicIP": "127.0.0.1",
                    "X-MACAddress": "00:00:00:00:00:00",
                    "X-PrivateKey": API_KEY,
                    "Accept": "application/json",
                    "X-UserType": "USER",
                    "X-SourceID": "WEB",
                    "X-ClientID": CLIENT_CODE
                },
                body: JSON.stringify({
                    clientcode: CLIENT_CODE,
                    password: hash,
                    totp: TOTP
                })
            }
        );

        const data = await res.json();
        if (data?.data?.jwtToken) {
            AUTH_TOKEN = data.data.jwtToken;
            FEED_TOKEN = data.data.feedToken;
            console.log("✔ SmartAPI Login Success");
        } else {
            console.log("❌ Login failed", data);
        }
    } catch (err) {
        console.log("Login ERROR:", err.message);
    }
}

// -----------------------------
// Fetch Scrip Master
// -----------------------------
async function loadScripMaster() {
    try {
        const res = await fetch(
            "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        );
        const json = await res.json();

        function findFut(symbol, alias) {
            const item = json.find(
                (x) =>
                    x.symbol.toUpperCase().includes(symbol) &&
                    x.name.toUpperCase().includes("FUT") &&
                    x.exch_seg === alias
            );
            return item
                ? { token: item.token, symbol: item.symbol, expiry: item.expiry }
                : null;
        }

        AUTO_TOKENS.nifty = findFut("NIFTY", "NFO");
        AUTO_TOKENS.sensex = findFut("SENSEX", "NFO");
        AUTO_TOKENS["natural gas"] = findFut("NATURALGAS", "MCX");

        console.log("✔ Auto FUT Tokens Loaded");
    } catch (err) {
        console.log("Scrip Master ERROR:", err.message);
    }
}

// ------------------------------------------------------------
// LIVE FUTURE LTP
// ------------------------------------------------------------
async function getFutureLTP(token) {
    if (!AUTH_TOKEN) return null;

    try {
        const res = await fetch(
            "https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote/",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": AUTH_TOKEN,
                    "X-PrivateKey": API_KEY,
                    "Accept": "application/json",
                },
                body: JSON.stringify({
                    mode: "FULL",
                    exchangeTokens: { NFO: [token] }
                })
            }
        );

        const data = await res.json();
        return data?.data?.fetched?.[0]?.ltp || null;
    } catch (err) {
        return null;
    }
}

// ------------------------------------------------------------
// TREND ENGINE
// ------------------------------------------------------------
function trendEngine(input) {
    const { ema20, ema50, rsi, vwap, spot } = input;

    let main = "SIDEWAYS";
    let strength = "NEUTRAL";
    let score = 50;
    let bias = "NONE";

    if (ema20 > ema50) {
        score += 10;
    } else score -= 10;

    if (rsi > 60) {
        score += 10;
        bias = "BULLISH";
    } else if (rsi < 40) {
        score -= 10;
        bias = "BEARISH";
    }

    return {
        main: score > 60 ? "UPTREND" : score < 40 ? "DOWNTREND" : "SIDEWAYS",
        strength: score > 60 ? "STRONG" : score < 40 ? "WEAK" : "RANGE",
        score,
        bias,
        components: {
            comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
        }
    };
}

// ------------------------------------------------------------
// Generate Option Strikes (simple logic)
// ------------------------------------------------------------
function getStrikes(spot) {
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
            strike: Math.round(spot / 50) * 50,
            distance: 10,
            entry: 5,
            stopLoss: 3,
            target: 8
        }
    ];
}

// ------------------------------------------------------------
// /api/calc  (MAIN API)
// ------------------------------------------------------------
app.post("/api/calc", async (req, res) => {
    const input = req.body;

    let useSpot = input.spot;

    let liveError = null;

    if (input.use_live === true) {
        const tokenObj = AUTO_TOKENS[input.market.toLowerCase()];
        if (tokenObj?.token) {
            const ltp = await getFutureLTP(tokenObj.token);
            if (ltp) {
                useSpot = ltp;
            } else {
                liveError = "TOKEN_NOT_FOUND_OR_LTP_FAIL";
            }
        } else {
            liveError = "NO_TOKEN_FOR_MARKET";
        }
    }

    const trend = trendEngine({ ...input, spot: useSpot });
    const strikes = getStrikes(useSpot);

    return res.json({
        success: true,
        message: "Calculation complete",
        login_status: AUTH_TOKEN ? "SmartAPI Logged-In" : "Not Logged-In",
        input: { ...input, spot: useSpot },
        trend,
        strikes,
        auto_tokens: AUTO_TOKENS,
        meta: {
            live_data_used: input.use_live && !liveError,
            live_ltp: useSpot,
            live_error: liveError
        }
    });
});

// ------------------------------------------------------------
// STARTUP
// ------------------------------------------------------------
app.listen(3000, async () => {
    console.log("SERVER STARTED on 3000");
    await smartLogin();
    await loadScripMaster();
});
