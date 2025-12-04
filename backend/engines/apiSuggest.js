const trend = require('./trendEngine');
const strikeUtils = require('./strikeUtils');
const optionChain = require('./optionChain');
const greeks = require('./greeksEngine');
const scoring = require('./scoringEngine');
const premium = require('./premiumEngine');
const sr = require('./supportResistanceEngine');
const futures = require('./futuresEngine');
const volume = require('./volumeEngine');

async function handler(input) {

    if (!input || !input.market) {
        return { ok: false, error: 'market required' };
    }

    const market = input.market.toLowerCase();

    // Auto Spot
    const spot = input.spot || await optionChain.autoDetectSpot(market);

    // Auto Expiry
    const expiry = input.expiry || await optionChain.autoDetectExpiry(market);
  // Trend Calculation
    const trendRes = trend.calculate(
        input.ema20,
        input.ema50,
        input.rsi,
        input.vwap,
        spot,
        input.pcr
    );

    // Strike Candidates (ATM + near ATM)
    const candidates = strikeUtils.generateCandidates(market, spot, expiry);

    // Fetch Chain (LTP, IV, OI, Volume)
    const chain = await optionChain.fetchChain(market, expiry, candidates);

    // Greeks Engine
    await greeks.augmentChainWithGreeks(chain, spot, expiry);

    // SR Engine
    const srData = await sr.analyze(market, spot, expiry);

    // Futures Confirmation
    const fut = await futures.check(market);

    // Volume Pressure Engine
    const vol = await volume.check(market);

    // Final Scoring (Top 3)
    const scored = scoring.scoreCandidates(chain, trendRes, srData, fut, vol);
    const top3 = scored.slice(0, 3);

    // Premium Engine → Entry, SL, Target
    const final = top3.map(c =>
        premium.finalize(c, {
            budget_per_trade: input.budget_per_trade || null
        })
    );

    return {
        ok: true,
        market: input.market,
        spot,
        expiry,
        trend: trendRes,
        support_resistance: srData,
        futures_confirmation: fut,
        volume_trend: vol,
        suggestions: final,
        meta: {
            candidates_evaluated: chain.length
        }
    };
}

module.exports = { handler };
