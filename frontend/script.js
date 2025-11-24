const qs = id => document.getElementById(id);

function getServer() {
    const s = qs('server').value.trim();
    return s !== "" ? s : "";
}

function formatResult(j) {
    if (!j) return "कोई डेटा नहीं मिला।";

    if (!j.success) {
        return (j.message || "Calculation failed") +
            (j.error ? "\nError: " + j.error : "");
    }

    const lines = [];

    // Market Trend
    if (j.trend) {
        lines.push("Market Trend");
        const t = j.trend;
        const score = (typeof t.score === "number") ? t.score.toFixed(1) : t.score;
        lines.push((t.main || "") + (t.strength ? " (" + t.strength + ")" : ""));
        if (score) {
            lines.push("Score: " + score + " / 10");
        }
        lines.push("");
        // Direction
        lines.push("Direction");
        if (t.bias && t.bias !== "NONE") {
            const dirText = t.bias === "CE" ? "CE (Call side bias)" :
                t.bias === "PE" ? "PE (Put side bias)" :
                    t.bias;
            lines.push(dirText);
        } else {
            lines.push("No clear CE / PE bias (sideways / range)");
        }
        lines.push("");
        // Trend Analysis
        lines.push("Trend Analysis");
        const c = t.components || {};
        if (c.ema_gap) lines.push("EMA Gap: " + c.ema_gap);
        if (c.vwap) lines.push("VWAP Position: " + c.vwap);
        if (c.rsi) lines.push("RSI Level: " + c.rsi);
        if (c.price_structure) lines.push("Price Structure: " + c.price_structure);
        if (c.expiry_effect) lines.push("Expiry Effect: " + c.expiry_effect);
        lines.push("");
        // Summary
        lines.push("Summary");
        if (t.comment) lines.push(t.comment);
        lines.push("");
    }

    // Recommended Strikes
    const strikes = j.strikes || [];
    lines.push("Recommended Strikes");
    if (strikes.length === 0) {
        lines.push("कोई strike सुझाई नहीं गई (NO_TRADE ज़ोन हो सकता है)।");
    } else {
        strikes.forEach((s, idx) => {
            const num = idx + 1;
            const ty = s.type || "";
            const st = s.strike != null ? String(s.strike) : "";
            lines.push(num + ") " + ty + " – " + st);

            const entry = s.entry != null ? String(s.entry) : "";
            const sl = s.stopLoss != null ? String(s.stopLoss) : "";
            const tgt = s.target != null ? String(s.target) : "";

            if (entry || sl || tgt) {
                if (entry) lines.push("   Entry: " + entry);
                if (sl) lines.push("   Stoploss: " + sl);
                if (tgt) lines.push("   Target: " + tgt);
            }
            if (s.distance != null) {
                lines.push("   Distance from spot: " + s.distance);
            }
            lines.push("");
        });
    }

    // Meta info
    if (j.meta) {
        lines.push("Notes");
        if (j.meta.note) lines.push(j.meta.note);
        if (j.meta.live_data_used) {
            lines.push("Live data source: Angel One SmartAPI (future integration).");
        } else {
            lines.push("Live data अभी formula-आधारित है (demo mode).");
        }
    }

    return lines.join("\n");
}

async function calc() {
    const server = getServer();

    const url = server
        ? server + "/api/calc"
        : "/api/calc";

    const payload = {
        ema20: Number(qs('ema20').value) || 0,
        ema50: Number(qs('ema50').value) || 0,
        rsi: Number(qs('rsi').value) || 0,
        vwap: Number(qs('vwap').value) || 0,
        spot: Number(qs('spot').value) || 0,
        market: qs('market').value,
        expiry_days: Number(qs('expiry').value) || 7,
        use_live: qs('useLive').checked
    };

    qs('out').textContent = 'Calculating...';

    try {
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const j = await r.json();
        const txt = formatResult(j);
        qs('out').textContent = txt;

    } catch (e) {
        qs('out').textContent = "Network error: " + e.message;
    }
}

document.getElementById('calc').addEventListener('click', calc);
