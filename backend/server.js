// ------------------------------------------------------
// SmartAPI Login
// ------------------------------------------------------
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }

  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

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
          password: tradingPassword,
          totp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);
    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};

    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    // DEBUG (safe)
    console.log("DEBUG: After Login SESSION =>", {
      access_token: !!session.access_token,
      feed_token: !!session.feed_token,
      expires_at: session.expires_at
    });

    return { ok: !!session.access_token && !!session.feed_token };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}
// ------------------------------------------------------
// Start WebSocket when tokens are ready
// ------------------------------------------------------
async function startWebsocketIfReady() {

  // DEBUG (safe)
  console.log("DEBUG: Before WS Start SESSION =>", {
    access_token: !!session.access_token,
    feed_token: !!session.feed_token,
    expires_at: session.expires_at
  });

  if (wsClient && wsStatus.connected) return;

  if (!session.feed_token || !session.access_token) {
    console.log("WS WAIT: No tokens yet...");
    return;
  }

  try {
    wsClient = new WebSocket(WS_URL, { perMessageDeflate: false });

    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;
      console.log("WS: CONNECTED");

      const auth = {
        feedToken: session.feed_token,
        clientCode: SMART_USER_ID,
        jwtToken: session.access_token
      };

      wsClient.send(JSON.stringify({ action: "authenticate", data: auth }));
    });

    wsClient.on("message", (msg) => {
      wsStatus.lastMsgAt = Date.now();
      // (old logic continues as it is)
    });

    wsClient.on("close", () => {
      wsStatus.connected = false;
      wsClient = null;
      console.log("WS: CLOSED");
    });

    wsClient.on("error", (err) => {
      wsStatus.lastError = err?.message || "unknown";
      console.log("WS ERROR:", err?.message);
    });

  } catch (err) {
    console.log("WS START EXCEPTION:", err);
  }
}
