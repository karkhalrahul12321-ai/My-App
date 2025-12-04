function calculate(ema20, ema50, rsi, vwap, spot, pcr) {

    const result = {
        isUptrend: false,
        isDowntrend: false,
        isNeutral: false,
        score: 0,
        reason: []
    };

    // --- EMA Trend ---
    if (ema20 > ema50) {
        result.score += 2;
        result.reason.push("EMA20 > EMA50 → bullish");
    } else if (ema20 < ema50) {
        result.score -= 2;
        result.reason.push("EMA20 < EMA50 → bearish");
    } else {
        result.reason.push("EMA flat → neutral");
    }

    // --- RSI Trend ---
    if (rsi > 55) {
        result.score += 1;
        result.reason.push("RSI > 55 → bullish strength");
    } else if (rsi < 45) {
        result.score -= 1;
        result.reason.push("RSI < 45 → bearish strength");
    } else {
        result.reason.push("RSI neutral zone");
    }

    // --- VWAP Confirmation ---
    if (spot > vwap) {
        result.score += 1;
        result.reason.push("Spot above VWAP → buyers control");
    } else if (spot < vwap) {
        result.score -= 1;
        result.reason.push("Spot below VWAP → sellers control");
    }

    // --- PCR Confirmation ---
    if (pcr > 1.2) {
        result.score += 1;
        result.reason.push("PCR > 1.2 → bullish support");
    } else if (pcr < 0.8) {
        result.score -= 1;
        result.reason.push("PCR < 0.8 → bearish pressure");
    }

    // --- Final Trend Decision ---
    if (result.score >= 2) {
        result.isUptrend = true;
    } else if (result.score <= -2) {
        result.isDowntrend = true;
    } else {
        result.isNeutral = true;
    }

    return result;
}

module.exports = { calculate };
