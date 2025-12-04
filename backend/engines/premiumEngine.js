/**
 * premiumEngine.js
 *
 * अंतिम stage → Entry, Stoploss और Target की गणना करता है।
 * 
 * Logic:
 *  - entry_price = live LTP (या chain से सबसे सही option का LTP)
 *  - stoploss = entry_price * (1 - 0.15)  // यानी 15% SL
 *  - target = entry_price + (entry_price * momentumFactor)
 * 
 * momentumFactor:
 *  - trend + volume + SR alignment जितनी strong → उतनी बड़ी move की संभावना
 *  - default = 0.35 (35% move potential) + SL buffer
 */

const CONFIG = {
    SL_PERCENT: 0.15,       // 15% Stoploss
    MOMENTUM: 0.35          // 35% upside expectation
};

function finalize(candidate, opts = {}) {

    const side = candidate.side;
    const opt = candidate[side];

    const entry = Number(opt.ltp || 0);

    // Stoploss = entry - 15%
    const stoploss = parseFloat((entry * (1 - CONFIG.SL_PERCENT)).toFixed(2));

    // Target = entry + momentum move
    const projectedMove = entry * (CONFIG.MOMENTUM + CONFIG.SL_PERCENT); 
    const target = parseFloat((entry + projectedMove).toFixed(2));

    // यदि बाद में trading quantity logic जोड़ना हो तो यहाँ आएगा
    const lot_size = 1;
    const qty_lots = 1;
    const total_cost = parseFloat((entry * lot_size * qty_lots).toFixed(2));

    return {
        ...candidate,
        suggested: {
            entry_price: entry,
            stoploss_price: stoploss,
            target_price: target,
            lot_size,
            qty_lots,
            total_cost
        }
    };
}

module.exports = { finalize };
