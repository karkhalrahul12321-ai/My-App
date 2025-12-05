const express = require("express");
const path = require("path");
const axios = require("axios");
const crypto = require("crypto-js");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();  // Render auto-loads .env

const app = express();
app.use(express.json());
app.use(cors());

// Static frontend (VERY IMPORTANT)
app.use(express.static(path.join(__dirname, "../public")));

// TOTP Generator
function generateTOTP(secret) {
  const epoch = Math.floor(Date.now() / 1000);
  const time = Math.floor(epoch / 30);
  const key = crypto.enc.Base64.parse(secret);
  const msg = crypto.enc.Hex.parse(time.toString(16).padStart(16, "0"));
  const hash = crypto.HmacSHA1(msg, key);
  const offset = hash.words[4] & 0xf;
  const binary =
    ((hash.words[offset] & 0x7fffffff) >> 0).toString(10);
  return binary.substring(binary.length - 6);
}

// ----------------------------------------
// LOGIN API (Always uses .env values)
// ----------------------------------------
app.post("/login", async (req, res) => {
  try {
    const client_code = process.env.SMART_USER_ID;
    const api_key = process.env.SMART_API_KEY;
    const password = process.env.SMART_API_SECRET;
    const totp_secret = process.env.SMART_TOTP;

    if (!client_code || !api_key || !password || !totp_secret) {
      return res.status(500).json({
        success: false,
        message: "Backend missing .env login values!",
      });
    }

    const totp = generateTOTP(totp_secret);

    const body = {
      clientcode: client_code,
      password: password,
      totp: totp,
    };

    const apiRes = await axios.post(
      "https://apiconnect.angelone.in/rest/secure/angelbroking/user/v1/loginByPassword",
      body,
      {
        headers: {
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-PrivateKey": api_key,
        },
      }
    );

    res.json({ success: true, data: apiRes.data });

  } catch (err) {
    console.error("Login error:", err.response?.data || err.message);
    res.status(500).json({
      success: false,
      message: "Login failed",
      error: err.response?.data || err.message,
    });
  }
});


// ----------------------------------------
// DEFAULT HOME ROUTE (App check purpose)
// ----------------------------------------
app.get("/", (req, res) => {
  res.json({ ok: true, msg: "Trading backend running successfully" });
});

// ----------------------------------------
// SERVER START
// ----------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Backend running on port ${PORT}`)
);
