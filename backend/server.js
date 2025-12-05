// =======================
//   IMPORTS
// =======================
const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const cors = require("cors");
const { authenticator } = require("otplib"); // NEW — correct TOTP library
const path = require("path");

dotenv.config();

// =======================
//   APP INIT
// =======================
const app = express();
app.use(express.json());
app.use(cors());

// =======================
// SMARTAPI LOGIN STORES
// =======================
let AUTH = {
  jwt: null,
  refreshToken: null,
  clientCode: process.env.SMART_USER_ID,
  apiKey: process.env.SMART_API_KEY,
  secret: process.env.SMART_API_SECRET,
  totp: process.env.SMART_TOTP
};

// =======================
//   Generate TOTP
// =======================
function generateTOTP() {
  try {
    return authenticator.generate(AUTH.totp);
  } catch (err) {
    console.log("TOTP ERROR:", err);
    return null;
  }
}

// =======================
//  SMARTAPI LOGIN FUNCTION
// =======================
async function smartLogin() {
  try {
    const totp = generateTOTP();
    if (!totp) return { success: false, msg: "TOTP generation failed" };

    const res = await axios.post("https://api.smartapi.in/v1/login", {
      clientCode: AUTH.clientCode,
      password: AUTH.secret,
      totp
    }, {
      headers: { "X-API-KEY": AUTH.apiKey }
    });

    if (res.data.status === false) {
      return { success: false, msg: res.data.message };
    }

    AUTH.jwt = res.data.data.jwtToken;
    AUTH.refreshToken = res.data.data.refreshToken;

    console.log("SMARTAPI LOGIN SUCCESS");
    return { success: true, msg: "Login successful", data: res.data.data };

  } catch (err) {
    console.log("LOGIN ERROR:", err.message);
    return { success: false, msg: "Login failed: " + err.message };
  }
}

// =======================
//  LOGIN ROUTE (CALLED FROM SETTINGS PAGE)
// =======================
app.post("/api/login", async (req, res) => {
  const out = await smartLogin();
  res.json(out);
});

// =======================
//  TEST ROUTE
// =======================
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, msg: "Backend running fine" });
});

// =======================
//  FRONTEND SERVE
// =======================
const frontendPath = path.join(__dirname, "../frontend");

app.use(express.static(frontendPath));

app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =======================
//  START SERVER
// =======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("🚀 Trading Backend + Frontend LIVE on:", PORT);
});
