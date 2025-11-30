const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());

// ===== FRONTEND SERVE (working) =====
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// ===== SMARTAPI CONFIG =====
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// ===== SESSION =====
let session = {
  access_token: null,
  expires_at: null,
};

// ===== BASE32 + TOTP =====
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const output = [];

  input = input.replace(/=+$/, "").toUpperCase();

  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTOTP(secret) {
  const decoded = base32Decode(secret);
  const time = Math.floor(Date.now() / 30000);
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(0, 0);
  buffer.writeUInt32BE(time, 4);

  const hmac = crypto.createHmac("sha1", decoded).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;

  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, "0");
}

// ===== SMARTAPI LOGIN =====
async function smartLogin(password) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID)
    return { ok: false, reason: "ENV_MISSING" };

  const totp = generateTOTP(SMART_TOTP_SECRET);

  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password,
          totp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false)
      return { ok: false, reason: "LOGIN_FAILED", raw: data };

    const d = data.data || {};
    session.access_token = d.jwtToken;
    session.expires_at = Date.now() + 1000 * 60 * 60 * 20;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// ===== LOGIN ROUTES =====
app.post("/api/login", async (req, res) => {
  const password = req.body.password || "";
  const r = await smartLogin(password);

  if (!r.ok)
    return res.json({
      success: false,
      error: r.reason,
      raw: r.raw || null,
      message: r.error || "Login failed",
    });

  res.json({
    success: true,
    logged_in: true,
    expires_at: session.expires_at,
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at,
  });
});

// ===== TEST SEARCH ROUTE =====
app.get("/api/test/search", async (req, res) => {
  if (!session.access_token)
    return res.json({ success: false, error: "NOT_LOGGED_IN" });

  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/searchScrip`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.access_token}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ searchtext: "NIFTY" }),
      }
    );

    const raw = await resp.text();

    console.log("SEARCH RAW ===>");
    console.log(raw);

    return res.send(raw);
  } catch (err) {
    return res.json({ success: false, error: err.message });
  }
});

// ===== FALLBACK =====
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// ===== START SERVER =====
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("TEST BACKEND RUNNING", PORT);
});
