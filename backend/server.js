/* -------------------------------------------------------
   IMPORTS
-------------------------------------------------------- */
const express = require("express");
const path = require("path");
const axios = require("axios");
const crypto = require("crypto-js");
const cors = require("cors");
const dotenv = require("dotenv");
const { generateTOTP } = require("./totp");

/* -------------------------------------------------------
   LOAD ENV
-------------------------------------------------------- */
dotenv.config();

/* -------------------------------------------------------
   CREATE APP
-------------------------------------------------------- */
const app = express();
app.use(express.json());
app.use(cors());

/* -------------------------------------------------------
   SMARTAPI LOGIN  (ALWAYS ENV-BASED)
-------------------------------------------------------- */
app.post("/login", async (req, res) => {
  try {
    const clientcode = process.env.SMART_API_KEY;
    const password = process.env.SMART_API_SECRET;
    const totp_secret = process.env.SMART_TOTP;

    if (!clientcode || !password || !totp_secret) {
      return res.status(500).json({
        success: false,
        message: "Missing .env login values",
      });
    }

    const totp = generateTOTP(totp_secret);

    const body = {
      clientcode: clientcode,
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
          "X-PrivateKey": password     // IMPORTANT: यही सही key है
        },
      }
    );

    return res.json({
      success: true,
      data: apiRes.data,
    });
  } catch (err) {
    console.error("Login error:", err.response?.data || err.message);
    return res.status(500).json({
      success: false,
      message: "Login failed",
      error: err.response?.data || err.message,
    });
  }
});

/* -------------------------------------------------------
   STATIC FRONTEND SERVING  (VERY IMPORTANT)
-------------------------------------------------------- */
app.use(express.static(path.join(__dirname, "../frontend")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

/* -------------------------------------------------------
   START SERVER
-------------------------------------------------------- */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("Trading backend running successfully on port", PORT);
});
