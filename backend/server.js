// backend/server.js
// Final, deploy-ready server.js
// Login: .env-based keys (SMART_USER_ID, SMART_API_KEY, SMART_API_SECRET, SMART_TOTP)
// Frontend: provides only password in POST /login body
// Static frontend served from ../frontend

const express = require("express");
const path = require("path");
const axios = require("axios");
const cors = require("cors");
const dotenv = require("dotenv");
const crypto = require("crypto"); // Node builtin

// Load env (Render injects env automatically; dotenv is safe for local dev)
dotenv.config();

const app = express();
app.use(express.json({ limit: "250kb" }));
app.use(cors());

// -----------------------------
// Helper: Base32 decode (for common TOTP secrets in base32)
// -----------------------------
function base32ToBuffer(base32) {
  if (!base32) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = ("" + base32).replace(/=+$/g, "").replace(/[^A-Z2-7]/gi, "").toUpperCase();
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (let i = 0; i < cleaned.length; i++) {
    const idx = alphabet.indexOf(cleaned.charAt(i));
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

// -----------------------------
// Helper: TOTP generation (RFC 6238) using SHA1 and 30s timestep
// Accepts secret in base32 (most common) or raw ascii.
// -----------------------------
function generateTOTP(secret) {
  if (!secret) return null;
  // Try base32 decode — if result length is 0, fallback to utf8
  let key = base32ToBuffer(secret);
  if (!key || key.length === 0) {
    key = Buffer.from(secret, "utf8");
  }

  const epoch = Math.floor(Date.now() / 1000);
  const timestep = 30;
  const counter = Math.floor(epoch / timestep);

  // 8-byte buffer big-endian
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0); // high
  buffer.writeUInt32BE(counter & 0xffffffff, 4); // low

  const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = (code % 1000000).toString().padStart(6, "0");
  return otp;
}

// -----------------------------
// Health / Ping
// -----------------------------
app.get("/ping", (req, res) => {
  res.json({ ok: true, msg: "Backend running successfully" });
});

// -----------------------------
// LOGIN route
// - frontend sends only { password: "..." } in body
// - server reads SMART_USER_ID, SMART_API_KEY, SMART_API_SECRET, SMART_TOTP from env
// - server generates totp from SMART_TOTP
// - sends login request to Angel One API
// -----------------------------
app.post("/login", async (req, res) => {
  try {
    // Basic debug (safe booleans only) — logs helpful during troubleshooting
    console.log("LOGIN attempt: env presence:",
      !!process.env.SMART_USER_ID,
      !!process.env.SMART_API_KEY,
      !!process.env.SMART_API_SECRET,
      !!process.env.SMART_TOTP
    );

    const passwordFromClient = req.body && req.body.password ? String(req.body.password) : null;
    if (!passwordFromClient) {
      return res.status(400).json({ success: false, message: "Missing password in request body" });
    }

    const clientcode = process.env.SMART_USER_ID || null;      // Angel user id
    const apiKey = process.env.SMART_API_KEY || null;         // may be used in other headers if needed
    const apiSecret = process.env.SMART_API_SECRET || null;   // X-PrivateKey
    const totpSecret = process.env.SMART_TOTP || null;

    if (!clientcode || !apiSecret || !totpSecret) {
      console.error("LOGIN ERROR: Missing one or more required env keys for login");
      return res.status(500).json({ success: false, message: "Server missing login env keys" });
    }

    // Generate totp from totpSecret
    const totp = generateTOTP(totpSecret);
    if (!totp) {
      console.error("LOGIN ERROR: TOTP generation failed");
      return res.status(500).json({ success: false, message: "TOTP generation failed" });
    }

    // Build body as expected by Angel One
    const body = {
      clientcode: clientcode,
      password: passwordFromClient,
      totp: totp
    };

    // API URL - using secure endpoint (as used earlier in conversation)
    const loginUrl = "https://apiconnect.angelone.in/rest/secure/angelbroking/user/v1/loginByPassword";

    // Headers - X-PrivateKey is API SECRET (private)
    const headers = {
      "X-UserType": "USER",
      "X-SourceID": "WEB",
      "X-ClientLocalIP": "127.0.0.1",
      "X-ClientPublicIP": "127.0.0.1",
      "X-MACAddress": "00:00:00:00:00:00",
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-PrivateKey": apiSecret
    };

    // Make request
    const apiRes = await axios.post(loginUrl, body, { headers, timeout: 15000 });

    // If AngelOne returns error inside 200, forward it
    if (apiRes && apiRes.data) {
      // store tokens if you want to persist session (example)
      // e.g., apiRes.data.data.jwtToken, apiRes.data.data.refreshToken
      return res.json({ success: true, data: apiRes.data });
    }

    return res.status(500).json({ success: false, message: "Empty response from login API" });

  } catch (err) {
    // Log full axios error but avoid leaking secrets
    console.error("Login error (axios):", err.response?.data || err.message || err);
    return res.status(500).json({
      success: false,
      message: "Login failed",
      error: err.response?.data || err.message
    });
  }
});

// -----------------------------
// Suggest route (stub) — if engines exist they'll be required and used
// This is safe: if engines modules are missing, it returns a friendly message.
// Replace or extend with your engines when ready.
// -----------------------------
app.post("/suggest", async (req, res) => {
  try {
    // If you have engine modules (engines/index.js or individual engines),
    // require them here and pass data. This stub just demonstrates response shape.
    const sample = {
      trend: "UP",
      strikes: [
        { strike: "ATM", type: "CE", price: 150 },
        { strike: "NEAR_ATM_1", type: "CE", price: 120 },
        { strike: "NEAR_ATM_2", type: "CE", price: 100 }
      ],
      entryPrices: [150, 120, 100],
      stopLoss: "15%",
      target: "dynamic"
    };
    return res.json({ success: true, result: sample });
  } catch (err) {
    console.error("Suggest error:", err);
    return res.status(500).json({ success: false, message: "Suggest failed", error: err.message });
  }
});

// -----------------------------
// Serve frontend (static) — root URL will return index.html
// -----------------------------
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// -----------------------------
// Start server
// -----------------------------
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Trading backend running successfully on port ${PORT}`);
});
