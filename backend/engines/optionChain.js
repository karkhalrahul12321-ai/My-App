const axios = require('axios');

// Market Tokens (spot + expiry detection)
const MARKET_INFO = {
    nifty: {
        spotToken: "99926000",
        exchange: "NSE",
        ocExchange: "NFO"
    },
    sensex: {
        spotToken: "1",
        exchange: "BSE",
        ocExchange: "BFO"
    },
    natural_gas: {
        spotToken: "224",
        exchange: "MCX",
        ocExchange: "MCX"
    }
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
            {
                exchange: m.exchange,
                symboltoken: m.spotToken
            },
            {
                headers: {
                    "X-PrivateKey": process.env.SMART_API_KEY,
                    "Authorization": `Bearer ${process.env.ACCESS_TOKEN}`
                }
            }
        );

        return Number(res.data?.data?.ltp || 0);

    } catch (err) {
        return null;
    }
}
// -------------------
// Auto Detect Expiry
// -------------------
async function autoDetectExpiry(market) {
    try {
        const res = await axios.get(
            `https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/expiry?exchange=${MARKET_INFO[market].ocExchange}`
        );

        const arr = res.data?.data || [];
        if (!arr.length) return null;

        const nearest = arr[0];

        const today = new Date();
        const exp = new Date(nearest);

        const diff = Math.ceil((exp - today) / (1000 * 60 * 60 * 24));

        return {
            date: nearest,
            daysLeft: diff
        };
    } catch (err) {
        return null;
    }
}

// -------------------
// Fetch Option Chain strikes
// -------------------
async function fetchChain(market, expiry, candidates) {

    const m = MARKET_INFO[market];
    if (!m) return [];

    const final = [];

    for (const c of candidates) {

        const base = {
            exchange: m.ocExchange,
            tradingsymbol: "",
            symboltoken: ""
        };

        // Tradingsymbol formation
        let ceSymbol = "";
        let peSymbol = "";

        if (market === "nifty") {
            ceSymbol = `NIFTY${c.strike}CE`;
            peSymbol = `NIFTY${c.strike}PE`;
        }

        if (market === "sensex") {
            ceSymbol = `SENSEX${c.strike}CE`;
            peSymbol = `SENSEX${c.strike}PE`;
        }

        if (market === "natural_gas") {
            ceSymbol = `NATURALGAS${c.strike}CE`;
            peSymbol = `NATURALGAS${c.strike}PE`;
        }

        // fetch CE + PE in parallel
        const ce = await fetchOption(ceSymbol, m);
        const pe = await fetchOption(peSymbol, m);

        final.push({
            strike: c.strike,
            ce,
            pe
        });
    }

    return final;
}

// -------------------
// Fetch single option
// -------------------
async function fetchOption(symbol, m) {
    try {
        const r = await axios.post(
            "https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote",
            {
                exchange: m.ocExchange,
                tradingsymbol: symbol
            },
            {
                headers: {
                    "X-PrivateKey": process.env.SMART_API_KEY,
                    "Authorization": `Bearer ${process.env.ACCESS_TOKEN}`
                }
            }
        );

        return {
            ltp: Number(r.data?.data?.ltp || 0),
            iv: Number(r.data?.data?.iv || 0),
            oi: Number(r.data?.data?.oi || 0),
            volume: Number(r.data?.data?.volume || 0)
        };

    } catch (err) {
        return {
            ltp: 0,
            iv: 0,
            oi: 0,
            volume: 0
        };
    }
}

module.exports = {
    autoDetectSpot,
    autoDetectExpiry,
    fetchChain
};
