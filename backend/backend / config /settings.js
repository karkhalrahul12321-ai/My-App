module.exports = {
    // -----------------------------
    // Strike distances (raw base)
    // Dynamic expiry distance logic इंजन में है
    // -----------------------------
    strikeDistances: {
        nifty: [250, 200, 150],
        sensex: [500, 400, 300],
        natural_gas: [80, 60, 50]
    },

    // -----------------------------
    // Market info (lot sizes, rounding)
    // -----------------------------
    market: {
        nifty: {
            step: 50,
            rounding: 50,
            lot: 75
        },
        sensex: {
            step: 100,
            rounding: 100,
            lot: 20
        },
        natural_gas: {
            step: 0.05,
            rounding: 0.05,
            lot: 1250
        }
    },

    // -----------------------------
    // Expiry Dynamic Adjustment
    // -----------------------------
    expiryAdjustmentPercent: 20,

    // -----------------------------
    // Greeks Weighting Logic
    // -----------------------------
    greekWeights: {
        deltaBullish: 0.9,
        deltaBearish: -0.9,
        vegaMin: 0.05,
        gammaMin: 0.03
    },

    // -----------------------------
    // Scoring Engine Weights
    // -----------------------------
    scoreWeights: {
        trend: 40,
        greeks: 25,
        volume: 15,
        optionChain: 10,
        premium: 10
    },

    // -----------------------------
    // Support–Resistance Parameters
    // -----------------------------
    sr: {
        candleLookback: 30,
        sensitivity: 0.25  // 25% rejection requirement
    },

    // -----------------------------
    // Volume Engine Parameters
    // -----------------------------
    volumeParams: {
        compareMultiplier: 1.8 // volume spike detection
    }
};
