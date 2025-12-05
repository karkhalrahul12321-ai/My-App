app.post("/login", async (req, res) => {
  try {
    // ALWAYS use .env for login (no frontend fields needed)
    const client_code = process.env.SMART_API_KEY;
    const password = process.env.SMART_API_SECRET;
    const totp_secret = process.env.SMART_TOTP;

    if (!client_code || !password || !totp_secret) {
      return res.status(500).json({
        success: false,
        message: "Backend missing .env login values!",
      });
    }

    // Generate TOTP
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
