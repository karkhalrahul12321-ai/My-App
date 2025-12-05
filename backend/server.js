//-----------------------------------------
// Imports
//-----------------------------------------
const express = require("express");
const path = require("path");
const axios = require("axios");
const crypto = require("crypto-js");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config({ path: "../.env" });

//-----------------------------------------
// Create Express App
//-----------------------------------------
const app = express();
app.use(express.json());
app.use(cors());

//-----------------------------------------
// Static Frontend Serve (VERY IMPORTANT)
//-----------------------------------------
app.use(express.static(path.join(__dirname, "..", "frontend")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "frontend", "index.html"));
});

//-----------------------------------------
// SmartAPI LOGIN ROUTE
//-----------------------------------------
app.post("/api/login", async (req, res) => {
  try {
    const { apiKey, apiSecret, totp, userId } = req.body;

    if (!apiKey || !apiSecret || !totp || !userId) {
      return res.json({ success: false, error: "Missing login fields" });
    }

    const payload = {
      clientcode: userId,
      password: apiSecret,
      totp: totp
    };

    const loginUrl = `https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/login`;

    const headers = {
      "X-ClientLocalIP": "127.0.0.1",
      "X-ClientPublicIP": "127.0.0.1",
      "X-MACAddress": "00:00:00:00",
      "X-PrivateKey": apiKey,
      "Accept": "application/json",
      "Content-Type": "application/json"
    };

    const response = await axios.post(loginUrl, payload, { headers });

    return res.json({ success: true, data: response.data });
  } catch (err) {
    return res.json({ success: false, error: err.message || "Login failed" });
  }
});

//-----------------------------------------
// Dummy engines (to avoid missing-module errors)
//-----------------------------------------
app.post("/api/calc", (req, res) => {
  res.json({
    success: true,
    message: "Calculation completed",
    result: {
      trend: "SIDEWAYS",
      score: 45,
      strikes: {
        ce: 100,
        pe: 200,
        straddle: 150
      }
    }
  });
});

//-----------------------------------------
// Server Health
//-----------------------------------------
app.get("/api/health", (req, res) => {
  res.json({ ok: true, msg: "Backend running successfully" });
});

//-----------------------------------------
// Start Server
//-----------------------------------------
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log("Trading Backend LIVE on:", PORT);
});
