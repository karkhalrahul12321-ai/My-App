function roundStrike(market, price) {
    if (market === "nifty") return Math.round(price / 50) * 50;
    if (market === "sensex") return Math.round(price / 100) * 100;
    if (market === "natural_gas") return Math.round(price / 0.05) * 0.05;
    return price;
}

function baseDistances(market) {
    if (market === "nifty") return [150, 200, 250];
    if (market === "sensex") return [300, 400, 500];
    if (market === "natural_gas") return [50, 60, 80];
    return [100];
}

function expiryDecayFactor(daysLeft) {
    if (daysLeft >= 15) return 1;        // far expiry
    if (daysLeft >= 7) return 0.7;       // mid expiry
    if (daysLeft >= 3) return 0.4;       // near expiry
    if (daysLeft >= 1) return 0.2;       // very near expiry
    return 0.1;                          // expiry day → ATM के बिल्कुल पास
}

function generateCandidates(market, spot, expiry) {

    let daysLeft = 7;
    if (expiry && expiry.daysLeft) daysLeft = expiry.daysLeft;

    const factor = expiryDecayFactor(daysLeft);
    const distances = baseDistances(market).map(d => d * factor);

    const atm = roundStrike(market, spot);

    const cands = [
        atm,
        roundStrike(market, spot + distances[0]),
        roundStrike(market, spot - distances[0]),
        roundStrike(market, spot + distances[1]),
        roundStrike(market, spot - distances[1]),
        roundStrike(market, spot + distances[2]),
        roundStrike(market, spot - distances[2])
    ];

    const unique = [...new Set(cands)];

    return unique.map(s => ({
        strike: s,
        market
    }));
}

module.exports = { generateCandidates, roundStrike };
