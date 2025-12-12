// apiSuggest.js
const optionChain = require("./optionchain");
const greeksEngine = require("./greeksEngine");
const strikeUtils = require("./strikeUtils");
const scoringEngine = require("./scoringEngine");
const trendEngine = require("./trendEngine");
const supportEngine = require("./supportResistanceEngine");
const volumeEngine = require("./volumeEngine");
const futuresEngine = require("./futuresEngine");
const premiumEngine = require("./premiumEngine");

module.exports = async function generateSuggestion(input) {
  try {
    const { market, spot, expiry, ema20, ema50, rsi, vwap } = input;

    // TREND ENGINE
    const trend = trendEngine({ ema20, ema50, rsi, vwap });

    // SUPPORT RESISTANCE
    const sr = supportEngine(spot);

    // VOLUME TREND
    const vol = volumeEngine();

    // FUTURES CONFIRMATION
    const fut = futuresEngine();

    // OPTION CHAIN (LTP, OI, Volume)
    const chain = await optionChain(market, expiry);

    // STRIKE SELECTION
    const strikes = strikeUtils(market, spot);

    // GREKS + THEORY VALUES
    const greeks = greeksEngine(strikes, spot);

    // PREMIUM ENGINE
    const prem = premiumEngine(chain, strikes);

    // SCORING ENGINE (trend + volume + SR + greeks + premium)
    const final = scoringEngine({
      strikes,
      trend,
      volume: vol,
      supportResistance: sr,
      futures: fut,
      greeks,
      premium: prem
    });

    return {
      success: true,
      entry: {
        ok: true,
        market,
        spot,
        expiry,
        trend,
        support_resistance: sr,
        volume_trend: vol,
        futures_confirmation: fut,
        suggestions: final,
        meta: { candidates_evaluated: strikes.length }
      }
    };
  } catch (err) {
    return {
      success: false,
      error: "Engine failed",
      details: err.message
    };
  }
};
