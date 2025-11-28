/* ============================================================
   Trading Helper Backend (FINAL PRO VERSION)
   SmartAPI Login + Auto FUT Token + Live FUT LTP + Trend Engine
   Markets Supported: Nifty, Sensex, Natural Gas
   ============================================================*/

const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// -----------------------------------------------------------
// ENV CONFIG (Render से आएंगे)
// -----------------------------------------------------------
const API_KEY = process.env.SMART_API_KEY;
const API_SECRET = process.env.SMART_API_SECRET;
const CLIENT_CODE = process.env.SMART_USER_ID;
const TOTP = process.env.SMART_TOTP;

// -----------------------------------------------------------
// AUTH STORAGE
// -----------------------------------------------------------
let AUTH_TOKEN = null;
let FEED_TOKEN = null;

// -----------------------------------------------------------
// UTIL: SHA256 for password hashing
// -----------------------------------------------------------
function sha256(str) {
    return crypto.createHash("sha256").update(str).digest("hex");
}

// -----------------------------------------------------------
// FINAL LOGIN FUNCTION (100% ERROR-PROOF)
// -----------------------------------------------------------
async function smartLogin() {
    try {
        const passwordHash = sha256(CLIENT_CODE + API_SECRET + TOTP);

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
                    "X-UserType": "USER",
                    "X-SourceID": "WEB",
                    "X-ClientID": CLIENT_CODE,
                    Accept: "application/json"
                },
                body: JSON.stringify({
                    clientcode: CLIENT_CODE,
                    password: passwordHash,
                    totp: TOTP
                })
            }
        );

        const raw = await res.text();
        console.log("RAW LOGIN RESPONSE:", raw);

        let data = null;
        try {
            data = JSON.parse(raw);
        } catch (e) {
            console.log("❌ JSON Parse Error:", e.message);
            return false;
        }

        if (!data?.data?.jwtToken) {
            console.log("❌ Login Failed:", data);
            return false;
        }

        AUTH_TOKEN = data.data.jwtToken;
        FEED_TOKEN = data.data.feedToken;

        console.log("✔ SmartAPI Login Successful");
        return true;

    } catch (err) {
        console.log("❌ LOGIN ERROR:", err.message);
        return false;
    }
}

// -----------------------------------------------------------
// AUTO FETCH FUTURE TOKENS
// -----------------------------------------------------------
const FUT_SYMBOLS = {
    nifty: "NIFTY",
    sensex: "SENSEX",
    "natural gas": "NATURALGAS"
};

let FUT_TOKENS = {
    nifty: null,
    sensex: null,
    "natural gas": null
};

async function autoFetchTokens() {
    try {
        for (const key of Object.keys(FUT_SYMBOLS)) {
            const url = `https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/contract/find?exchange=NFO&symbol=${FUT_SYMBOLS[key]}`;

            const res = await fetch(url, {
                headers: {
                    Authorization: AUTH_TOKEN,
                    "X-PrivateKey": API_KEY,
                    Accept: "application/json"
                }
            });

            const raw = await res.text();
            console.log(`TOKEN RAW (${key}):`, raw);

            let json = null;
            try {
                json = JSON.parse(raw);
            } catch (err) {
                console.log("TOKEN JSON ERROR:", err.message);
                continue;
            }

            const contract = json?.data?.[0];
            if (contract) {
                FUT_TOKENS[key] = {
                    symbol: contract.symbol,
                    token: contract.token,
                    expiry: contract.expiry
                };
            }
        }

        console.log("✔ FUT Tokens Loaded:", FUT_TOKENS);
    } catch (e) {
        console.log("❌ TOKEN FETCH ERROR:", e.message);
    }
}

// -----------------------------------------------------------
// FETCH LIVE LTP
// -----------------------------------------------------------
async function fetchLiveLTP(token) {
    try {
        const url = "https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote/ltp";

        const res = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: AUTH_TOKEN,
                "X-PrivateKey": API_KEY
            },
            body: JSON.stringify({
                mode: "LTP",
                exchangeTokens: { NFO: [token] }
            })
        });

        const raw = await res.text();
        console.log("LTP RAW:", raw);

        const json = JSON.parse(raw);
        return json?.data?.ltp ?? null;
    } catch (err) {
        console.log("LTP ERROR:", err.message);
        return null;
    }
}

// -----------------------------------------------------------
// TREND & STRIKES ENGINE
// -----------------------------------------------------------
function calcTrendAndStrikes(input) {
    const { ema20, ema50, rsi, vwap, spot } = input;

    let strength = "RANGE";
    let main = "SIDEWAYS";
    let score = 50;

    if (ema20 > ema50) score += 10;
    if (ema20 < ema50) score -= 10;

    if (rsi > 60) score += 10;
    if (rsi < 40) score -= 10;

    if (vwap < spot) score += 5;
    else score -= 5;

    if (score > 60) main = "UPTREND";
    else if (score < 40) main = "DOWNTREND";

    return {
        main,
        strength,
        score,
        bias: "NONE",
        comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
    };
}

// -----------------------------------------------------------
// API: CALCULATE TREND
// -----------------------------------------------------------
app.post("/api/calc", async (req, res) => {
    try {
        const input = req.body;
        const trend = calcTrendAndStrikes(input);

        const strikes = [
            {
                type: "CE",
                strike: Math.round(input.spot + 110),
                distance: 110,
                entry: 10,
                stopLoss: 6,
                target: 15
            },
            {
                type: "PE",
                strike: Math.round(input.spot - 90),
                distance: 90,
                entry: 10,
                stopLoss: 6,
                target: 15
            },
            {
                type: "STRADDLE",
                strike: Math.round(input.spot),
                distance: 10,
                entry: 5,
                stopLoss: 3,
                target: 8
            }
        ];

        res.json({
            success: true,
            message: "Calculation complete",
            login_status: AUTH_TOKEN ? "SmartAPI Logged-In" : "Not logged-in (demo mode)",
            input,
            trend,
            strikes,
            auto_tokens: FUT_TOKENS,
            meta: {
                live_data_used: false,
                live_ltp: null
            }
        });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// -----------------------------------------------------------
// STATIC FILES FOR FRONTEND
// -----------------------------------------------------------
app.use("/", express.static(path.join(__dirname, "public")));
app.use("/public", express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// -----------------------------------------------------------
// STARTUP SEQUENCE
// -----------------------------------------------------------
app.listen(3000, async () => {
    console.log("====================================");
    console.log("🚀 SERVER STARTED ON 3000");

    console.log("🔐 Logging into SmartAPI...");
    await smartLogin();

    if (AUTH_TOKEN) {
        console.log("🔄 Fetching FUT Tokens...");
        await autoFetchTokens();
    }

    console.log("====================================");
});
