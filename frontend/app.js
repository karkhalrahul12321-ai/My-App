// ===============================
// Trading Helper - FINAL app.js
// ===============================

// ---------------
// DOM SHORTCUTS
// ---------------
const $ = (id) => document.getElementById(id);

// Inputs
const ema20 = $("ema20");
const ema50 = $("ema50");
const rsi = $("rsi");
const vwap = $("vwap");
const spot = $("spot");
const expiryDays = $("expiryDays");
const marketSelect = $("marketSelect");
const useLive = $("useLive");

// Buttons
const calcBtn = $("calcBtn");
const checkLoginBtn = $("checkLoginBtn");
const openSettings = $("openSettings");
const openSettings2 = $("openSettings2");

// Output areas
const trendContent = $("trendContent");
const strikesContent = $("strikesContent");
const metaCard = $("metaCard");
const metaContent = $("metaContent");
const jsonOutput = $("jsonOutput");

// Toggle meta info
const toggleMeta = $("toggleMeta");
let metaVisible = true;

// Load saved server URL
const serverUrl = $("serverUrl");
serverUrl.value = localStorage.getItem("serverUrl") || "";

// Save URL automatically
serverUrl.addEventListener("input", () => {
    localStorage.setItem("serverUrl", serverUrl.value.trim());
});

// ----------------------------
// OPEN SmartAPI SETTINGS PAGE
// ----------------------------
openSettings.onclick = () => (window.location.href = "settings.html");
openSettings2.onclick = () => (window.location.href = "settings.html");

// ------------------------------
// CHECK LOGIN STATUS ON RENDER
// ------------------------------
async function checkLogin() {
    const url = serverUrl.value.trim();
    if (!url) {
        checkLoginBtn.innerText = "Set Server URL";
        return;
    }

    checkLoginBtn.innerText = "Checking...";

    try {
        const r = await fetch(url + "/api/login/status");
        const data = await r.json();

        if (data.logged_in) {
            checkLoginBtn.innerText = "SmartAPI Logged-In";
            checkLoginBtn.classList.add("ok");
        } else {
            checkLoginBtn.innerText = "Not Logged-In";
            checkLoginBtn.classList.remove("ok");
        }
    } catch (err) {
        checkLoginBtn.innerText = "Server Error";
        checkLoginBtn.classList.remove("ok");
    }
}

setTimeout(checkLogin, 800);

// ------------------------------
// META INFO HIDE/SHOW
// ------------------------------
toggleMeta.onclick = () => {
    metaVisible = !metaVisible;
    metaCard.style.display = metaVisible ? "block" : "none";
    toggleMeta.innerText = metaVisible ? "🔽 Hide Meta Info" : "▶ Show Meta Info";
};

// ------------------------------
// MAIN CALCULATION
// ------------------------------
calcBtn.onclick = async () => {
    const base = serverUrl.value.trim();
    if (!base) {
        alert("Please enter Server URL first.");
        return;
    }

    calcBtn.innerText = "Calculating...";
    calcBtn.disabled = true;

    try {
        const body = {
            ema20: ema20.value,
            ema50: ema50.value,
            rsi: rsi.value,
            vwap: vwap.value,
            spot: spot.value,
            market: marketSelect.value,
            expiry_days: expiryDays.value,
            use_live: useLive.checked
        };

        const r = await fetch(base + "/api/calc", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        const data = await r.json();
        updateUI(data);

    } catch (err) {
        alert("Error connecting to server: " + err.message);
    }

    calcBtn.innerText = "⚡ CALCULATE";
    calcBtn.disabled = false;
};

// ------------------------------
// UPDATE UI WITH RESULT
// ------------------------------
function updateUI(data) {
    // RAW JSON
    jsonOutput.textContent = JSON.stringify(data, null, 2);

    if (!data.success) {
        trendContent.innerHTML = `<p class='error'>${data.error}</p>`;
        strikesContent.innerHTML = "";
        metaContent.innerHTML = "";
        return;
    }

    // ---------------------
    // Trend Result
    // ---------------------
    const t = data.trend;

    trendContent.innerHTML = `
        <div class='trend-title'>${t.main}</div>
        <div class='trend-sub'>${t.strength}</div>
        <div class='trend-line'>
            <span>Score: ${t.score}</span>
            <span>Bias: ${t.bias}</span>
        </div>
        <div class='trend-small'>${t.components.ema_gap} • ${t.components.rsi} • ${t.components.vwap} • ${t.components.price_structure} • ${t.components.expiry}</div>
    `;

    // ---------------------
    // Smart Strikes
    // ---------------------
    const s = data.strikes;

    strikesContent.innerHTML = `
        <div class="strike-box">
            <h3>CE Strike</h3>
            <p>Strike: ${s[0].strike}</p>
            <p>Entry: ${s[0].entry}</p>
            <p>SL: ${s[0].stopLoss}</p>
            <p>Target: ${s[0].target}</p>
        </div>

        <div class="strike-box">
            <h3>PE Strike</h3>
            <p>Strike: ${s[1].strike}</p>
            <p>Entry: ${s[1].entry}</p>
            <p>SL: ${s[1].stopLoss}</p>
            <p>Target: ${s[1].target}</p>
        </div>

        <div class="strike-box">
            <h3>Straddle</h3>
            <p>Strike: ${s[2].strike}</p>
            <p>Entry: ${s[2].entry}</p>
            <p>SL: ${s[2].stopLoss}</p>
            <p>Target: ${s[2].target}</p>
        </div>
    `;

    // ---------------------
    // Meta Info
    // ---------------------
    const m = data.meta;

    metaContent.innerHTML = `
        <p><b>Live Data Used:</b> ${m.live_data_used ? "Yes" : "No"}</p>
        <p><b>Live LTP:</b> ${m.live_ltp || "-"}</p>
        <p><b>Status:</b> ${data.login_status}</p>
    `;
}

// END FILE
