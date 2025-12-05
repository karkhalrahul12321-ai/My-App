// backend/smartapi.js
// SmartAPI login wrapper using TOTP (option A).
// Exports an async function loginSmartAPI({ userId, apiKey, apiSecret, totpSecret })
// Returns: { success: true, data: { ... } } or throws Error

const axios = require('axios');
const { generateTOTP } = require('./totp');

const DEFAULT_SMARTAPI_BASE = 'https://openapi.angelbroking.com'; // placeholder, change if your endpoint different

async function loginSmartAPI({ userId, apiKey, apiSecret, totpSecret, baseUrl }) {
  if (!userId || !apiKey || !apiSecret || !totpSecret) {
    throw new Error('Missing credentials (userId/apiKey/apiSecret/totpSecret required)');
  }

  const API_BASE = baseUrl || DEFAULT_SMARTAPI_BASE;

  try {
    // 1) generate TOTP
    const totpCode = generateTOTP(totpSecret, { step: 30, digits: 6, algo: 'sha1' });

    // 2) Prepare login payload
    // NOTE: The exact keys depend on the SmartAPI you're using. Typical Angel/SmartAPI login fields:
    //   userID (or userid), api_key, password or totp, etc.
    // Adjust below keys to match your frontend's request fields.
    const payload = {
      // example fields — change to match your broker API
      userID: userId,
      apiKey: apiKey,
      secretKey: apiSecret,   // if required
      totp: totpCode
    };

    // 3) Call SmartAPI login endpoint
    // You must verify the real login path your broker expects. Many variants:
    //  - /token or /session or /client/v3/login etc.
    // For safety, try the common "session" endpoint: /session (change if needed)
    const loginUrl = `${API_BASE}/session`; // <--- adjust if your endpoint differs

    const resp = await axios.post(loginUrl, payload, {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 10000
    });

    // 4) Validate response
    if (!resp || !resp.data) {
      throw new Error('Empty response from SmartAPI login');
    }

    // Typical success shape will differ by vendor. Return the whole response.data to the caller.
    return { success: true, data: resp.data };
  } catch (err) {
    // normalize error
    let message = 'SmartAPI login error';
    if (err.response && err.response.data) {
      // attach server-provided message if available
      message = `SmartAPI error: ${JSON.stringify(err.response.data)}`;
    } else if (err.message) {
      message = err.message;
    }
    // rethrow with normalized message
    const e = new Error(message);
    e.original = err;
    throw e;
  }
}

module.exports = {
  loginSmartAPI
};
