
Trading App (Render-ready)
--------------------------
Deploy steps:
1. Upload this ZIP to Render -> New Web Service -> Deploy from ZIP
2. Set Environment Variables on Render:
   SMART_API_KEY, SMART_API_SECRET, SMART_TOTP, SMART_USER_ID, SMARTAPI_BASE (optional)
3. Click Deploy. After build, open the provided URL.
4. Paste the Render URL into the Server URL box in the frontend (or leave blank if hosting same)
5. Enter EMA/RSI/VWAP/Spot and press Calculate.

Security:
- Put your keys only in Render's environment variables. Do NOT paste them in the frontend.
