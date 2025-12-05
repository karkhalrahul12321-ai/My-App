/* -------------------------------------------------------
   IMPORTS
-------------------------------------------------------- */
const express = require("express");
const path = require("path");
const axios = require("axios");
const cors = require("cors");
const dotenv = require("dotenv");
const { generateTOTP } = require("./totp");

/* -------------------------------------------------------
   ENV
-------------------------------------------------------- */
dotenv.config();

/* -------------------------------------------------------
   APP INIT
-------------------------------------------------------- */
const app = express();
app.use(express.json());
app.use(cors());

/* -------------------------------------------------------
   LOGIN (FRONTEND-BASED) — SAME AS YOUR ORIGINAL SERVER
-------------------------------------------------------- */
app.post("/login", async (req, res) => {
  try {
    const { client_code, password, totp } = req.body;

    // ORIGINAL VALIDATION — SAME AS YOUR ZIP SERVER
    if (!client_code || !password || !totp) {
      return res.status(400).json({
        success: false,
        message: "Missing login fields!",
      });
    }

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
          "X-PrivateKey": process.env.SMART_API_SECRET, 
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
   STATIC FRONTEND SERVING (AS IN YOUR ORIGINAL SERVER)
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
  console.log("Backend running on port", PORT);
});
