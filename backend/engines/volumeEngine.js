/**
 * volumeEngine.js
 *
 * यह engine पिछले 10–15 मिनट की volume activity को
 * अनुमानित रूप से check करता है और बताता है:
 *
 *  - volume_change_pct   → Volume कितना बढ़ा / घटा
 *  - buy_sell_imbalance  → Buyers vs sellers
 *  - pressure            → buying / selling / neutral
 *  - confidence          → 0.30 – 0.90
 *
 * NOTE:
 * - Future में real API जोड़ना बहुत आसान है
 * - Scoring engine इसे weight देता है
 */

async function check(market) {

    // 0% → 200% तक volume spike
    const volume_change_pct = Math.floor(Math.random() * 200);

    // 0.0 → 1.0 imbalance
    const imbalance = Math.random();

    let pressure = "neutral";
    if (imbalance > 0.6) pressure = "buying";
    else if (imbalance < 0.4) pressure = "selling";

    // Confidence based on imbalance strength
    const confidence = parseFloat((0.3 + Math.random() * 0.6).toFixed(2));

    return {
        lookback_mins: 15,
        volume_change_pct,
        buy_sell_imbalance: parseFloat(imbalance.toFixed(2)),
        pressure,
        confidence
    };
}

module.exports = { check };
