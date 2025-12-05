///////////////////////////////////////////////
// Imports
///////////////////////////////////////////////
const express = require("express");
const path = require("path");
const axios = require("axios");
const cors = require("cors");
const dotenv = require("dotenv");
const crypto = require("crypto-js");

dotenv.config({ path: ".env" });   // <-- Render backend root .env

///////////////////////////////////////////////
// Create App
///////////////////////////////////////////////
const app = express();
app.use(express.json());
app.use(cors());

///////////////////////////////////////////////
// Static Frontend Serve
///////////////////////////////////////////////
// IMPORTANT: backend/server.js से frontend का सही path
app.use(express.static(path.join(__dirname, "../frontend")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

///////////////////////////////////////////////
// Helper: TOTP Generator
///////////////////////////////////////////////
function generateTOTP(secret) {
  const epoch = Math.floor(Date.now() / 1000);
  const time = Math.floor(epoch / 30);

  const key = Buffer.from(secret, "ascii");
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(0, 0);
  msg.writeUInt32BE(time, 4);

  const hmac = require("crypto").createHmac("sha1", key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0xf;

  const otp =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (otp % 1000000).toString().padStart(6, "0");
}

///////////////////////////////////////////////
// LOGIN API — Uses only .env (no frontend fields)
///////////////////////////////////////////////
app.post("/login", async (req, res) => {
  try {
    const client_code = process.env.SMART_API_KEY;
    const password = process.env.SMART_API_SECRET;
    const totp_secret = process.env.SMART_TOTP;

    if (!client_code || !password || !totp_secret) {
      return res.status(500).json({
        success: false,
        message: "Backend missing .env login values",
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
          "X-PrivateKey": process.env.SMART_API_KEY,
        },
      }
    );

    return res.json({ success: true, data: apiRes.data });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Login failed",
      error: err.response?.data || err.message,
    });
  }
});

///////////////////////////////////////////////
// HEALTH CHECK for Render
///////////////////////////////////////////////
app.get("/ping", (req, res) => {
  res.json({ ok: true, msg: "Trading backend running successfully" });
});

///////////////////////////////////////////////
// Start Server
///////////////////////////////////////////////
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
