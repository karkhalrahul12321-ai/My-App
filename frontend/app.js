/* ============================================================
   GLOBAL: LOAD THEME + ACCENT
============================================================ */
function applyTheme(theme) {
    if (!theme) return;
    document.body.setAttribute("data-theme", theme);
}

function applyAccent(accent) {
    if (!accent) return;
    document.body.setAttribute("data-accent", accent);
}

/* Load theme + accent on page load */
(function () {
    const savedTheme = localStorage.getItem("app-theme") || "soft";
    const savedAccent = localStorage.getItem("app-accent") || "blue";

    applyTheme(savedTheme);
    applyAccent(savedAccent);

    const themeSelect = document.getElementById("themeSelect");
    const accentSelect = document.getElementById("accentSelect");

    if (themeSelect) themeSelect.value = savedTheme;
    if (accentSelect) accentSelect.value = savedAccent;
})();

/* ============================================================
   SAVE SETTINGS (in settings.html)
============================================================ */
function saveSettings() {
    const theme = document.getElementById("themeSelect").value;
    const accent = document.getElementById("accentSelect").value;
    const pin = document.getElementById("tradePin").value;

    localStorage.setItem("app-theme", theme);
    localStorage.setItem("app-accent", accent);

    if (pin.trim()) localStorage.setItem("trade-pin", pin.trim());

    alert("✅ Settings Saved!");
}

/* Back button */
function goBack() {
    window.location.href = "index.html";
}

/* ============================================================
   SERVER URL CHECK
============================================================ */
async function checkServerURL() {
    const urlInput = document.getElementById("serverURL");
    const statusText = document.getElementById("serverStatus");

    const url = urlInput.value.trim();
    if (!url) {
        statusText.innerText = "❗ Server URL required";
        return false;
    }

    statusText.innerText = "Checking...";

    try {
        const res = await fetch(url + "/ping");
        const data = await res.json();

        if (data.status === "ok") {
            statusText.innerText = "✅ Connected";
            return true;
        } else {
            statusText.innerText = "❗ Invalid Response";
            return false;
        }
    } catch (e) {
        statusText.innerText = "❗ Not Reachable";
        return false;
    }
}

/* ============================================================
   CALCULATION ENGINE
============================================================ */
document.getElementById("calcBtn")?.addEventListener("click", calculate);

async function calculate() {
    const isServerOK = await checkServerURL();
    if (!isServerOK) {
        alert("❗ पहले Server URL सेट करो (SmartAPI backend)");
        return;
    }

    const ema20 = Number(document.getElementById("ema20").value);
    const ema50 = Number(document.getElementById("ema50").value);
    const rsi = Number(document.getElementById("rsi").value);
    const vw = Number(document.getElementById("vw").value);
    const ltp = Number(document.getElementById("ltp").value);

    if (!ema20 || !ema50 || !rsi || !vw || !ltp) {
        alert("❗ सभी Inputs भरें");
        return;
    }

    /* SIMPLE TREND ENGINE (Your Existing Logic) */
    let trend = "SIDEWAYS";
    let strength = "RANGE";
    let score = 0;

    if (ema20 > ema50) {
        trend = "BULLISH";
        score += 10;
    }
    if (ema20 < ema50) {
        trend = "BEARISH";
        score -= 10;
    }

    if (rsi > 60) strength = "STRONG";
    if (rsi < 40) strength = "WEAK";

    /* UPDATE UI */
    document.getElementById("trendText").innerText = trend;
    document.getElementById("strengthText").innerText = strength;
    document.getElementById("priceSrc").innerText = ltp;

    /* Show extra summary */
    document.getElementById("sumTrend").innerText = trend;
    document.getElementById("sumStrength").innerText = strength;
    document.getElementById("sumBias").innerText = trend === "BULLISH" ? "CALL BIAS" :
                                                    trend === "BEARISH" ? "PUT BIAS" :
                                                    "NEUTRAL";
    document.getElementById("sumScore").innerText = score;

    /* Generate Strike Cards */
    generateStrikes(ltp);
}

/* ============================================================
   STRIKE CARDS
============================================================ */
function generateStrikes(ltp) {
    const grid = document.getElementById("strikeGrid");
    grid.innerHTML = "";

    const strikes = [
        { type: "CE", strike: ltp + 100 },
        { type: "PE", strike: ltp - 100 },
        { type: "Straddle", strike: Math.round(ltp / 100) * 100 }
    ];

    strikes.forEach(s => {
        const card = `
            <div class="strike-card">
                <div class="strike-header">
                    <span>${s.strike}</span>
                    <span class="strike-type ${s.type.toLowerCase()}">${s.type}</span>
                </div>
                <div class="strike-line"><span>Distance</span><span>${Math.abs(ltp - s.strike)}</span></div>
                <div class="strike-line"><span>Signal</span><span>${s.type}</span></div>
            </div>
        `;
        grid.innerHTML += card;
    });
}

/* ============================================================
   JSON TOGGLE
============================================================ */
document.getElementById("toggleJsonBtn")?.addEventListener("click", () => {
    const box = document.getElementById("jsonBox");
    if (box.classList.contains("hidden")) {
        box.classList.remove("hidden");
        toggleJsonBtn.textContent = "Hide JSON";
    } else {
        box.classList.add("hidden");
        toggleJsonBtn.textContent = "Show JSON";
    }
});
