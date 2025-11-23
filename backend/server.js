
const express = require('express');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
app.use(express.static('frontend'));

// Config / env
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || 'https://apiconnect.angelone.in';
const API_KEY = process.env.SMART_API_KEY || '';
const API_SECRET = process.env.SMART_API_SECRET || '';
const TOTP_SECRET = process.env.SMART_TOTP || '';
const USER_ID = process.env.SMART_USER_ID || '';

// Simple in-memory token store (non-persistent)
let session = { access_token: null, refresh_token: null, expires_at: 0 };

function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, output = [];
  input = input.replace(/=+$/,'').toUpperCase().replace(/[^A-Z2-7]/g,'');
  for (let i=0;i<input.length;i++) {
    value = (value<<5) | alphabet.indexOf(input[i]);
    bits +=5;
    if(bits >=8){
      output.push((value >>> (bits-8)) & 0xFF);
      bits -=8;
    }
  }
  return Buffer.from(output);
}

function generateTOTP(secret) {
  try {
    const key = base32Decode(secret);
    const epoch = Math.floor(Date.now() / 1000);
    const time = Math.floor(epoch / 30);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(time / Math.pow(2,32)),0); // high (usually 0)
    buf.writeUInt32BE(time & 0xFFFFFFFF,4); // low
    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const code = ( (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000 ).toString();
    return code.padStart(6,'0');
  } catch (e) {
    return null;
  }
}

async function loginIfNeeded() {
  // If we have a token still valid for >10 minutes, skip
  if(session.access_token && session.expires_at - Date.now() > 10*60*1000) return true;
  if(!API_KEY || !API_SECRET || !TOTP_SECRET || !USER_ID) return false;
  const totp = generateTOTP(TOTP_SECRET);
  if(!totp) return false;
  const url = SMARTAPI_BASE.replace(/\/$/,'') + '/rest/auth/angelbroking/user/v1/loginByPassword';
  const payload = {
    clientcode: USER_ID,
    password: API_SECRET,
    totp: totp
  };
  const headers = {
    'Content-Type':'application/json',
    'X-PrivateKey': API_KEY,
    'X-SourceID': 'WEB',
    'X-ClientLocalIP': '127.0.0.1',
    'X-ClientPublicIP': '127.0.0.1'
  };
  try {
    const resp = await fetch(url, { method:'POST', headers, body: JSON.stringify(payload), timeout: 10000 });
    const data = await resp.json();
    // SmartAPI responses vary; capture some fields if present
    if(data && (data.data || data.status)) {
      // try common fields
      session.access_token = data.data && data.data.jwtToken ? data.data.jwtToken : (data.data && data.data.access_token) || null;
      session.refresh_token = data.data && data.data.refresh_token ? data.data.refresh_token : null;
      // set conservative expiry 23 hours from now
      session.expires_at = Date.now() + 23*3600*1000;
      return true;
    } else {
      return false;
    }
  } catch (e) {
    return false;
  }
}

// Simple trend and strike logic (same rules as discussed)
function computeTrend(ema20, ema50, rsi, vwap, spot) {
  ema20 = Number(ema20); ema50 = Number(ema50); rsi = Number(rsi); vwap = Number(vwap); spot = Number(spot);
  if(isNaN(ema20)||isNaN(ema50)||isNaN(rsi)||isNaN(vwap)||isNaN(spot)) return { side: 'NEUTRAL', reason:'invalid inputs' };
  if(ema20 > ema50 && spot > vwap && rsi > 50) return { side: 'CE', reason:'EMA20>EMA50, Spot>VWAP, RSI>50' };
  if(ema20 < ema50 && spot < vwap && rsi < 50) return { side: 'PE', reason:'EMA20<EMA50, Spot<VWAP, RSI<50' };
  if(ema20 > ema50) return { side:'CE', reason:'EMA20>EMA50' };
  if(ema20 < ema50) return { side:'PE', reason:'EMA20<EMA50' };
  return { side:'NEUTRAL', reason:'No clear trend' };
}

function buildStrikes(spot, market, expiryDays, side, settings) {
  const baseDistances = settings && settings.strikeDistances ? settings.strikeDistances : { nifty:[250,200,150], sensex:[500,400,300], natural_gas:[80,60,50] };
  const bases = baseDistances[market] || baseDistances['nifty'];
  const factor = Math.max(0.2, expiryDays/30);
  const distances = bases.map(b => Math.round(b * factor));
  const strikes = distances.map(d => side === 'CE' ? Math.round(spot + d) : Math.round(spot - d));
  return strikes;
}

app.get('/health', (req,res)=>{
  res.json({ ok:true, hasToken: !!session.access_token, expiresAt: session.expires_at });
});

app.post('/api/signal', async (req,res)=>{
  const p = req.body || {};
  const ema20 = p.ema20, ema50 = p.ema50, rsi = p.rsi, vwap = p.vwap, spot = p.spot;
  const market = p.market || 'nifty';
  const expiryDays = Math.max(1, Number(p.expiry_days || 7));
  const useLive = !!p.use_live;

  const trend = computeTrend(ema20, ema50, rsi, vwap, spot);

  // Attempt login if live requested
  let fetchError = null;
  let iv = null;
  if(useLive) {
    const ok = await loginIfNeeded();
    if(!ok) fetchError = 'login_failed_or_missing_env';
    else {
      // example: attempt to fetch option chain or iv - provider endpoints differ; this is best-effort
      try {
        const url = SMARTAPI_BASE.replace(/\/$/,'') + '/secure/marketdata/optionChain?symbol=' + encodeURIComponent(market);
        const r = await fetch(url, { headers: { 'Authorization': 'Bearer '+session.access_token, 'x-api-key': API_KEY } , timeout:8000 });
        if(r.ok){
          const j = await r.json();
          // try to read iv if available
          iv = j.iv || (j.data && j.data.iv) || null;
        } else {
          fetchError = 'live_fetch_http_'+r.status;
        }
      } catch(e){
        fetchError = 'live_fetch_exception';
      }
    }
  }

  const settings = JSON.parse(fs.readFileSync('./backend/settings.json','utf8'));
  const strikes = buildStrikes(Number(spot), market, expiryDays, trend.side==='NEUTRAL' ? 'CE' : trend.side, settings);
  const strikeOptions = strikes.map(s => {
    const intrinsic = Math.max(0, Math.abs(spot - s));
    const estPremium = iv ? Math.max(2, Math.round((intrinsic * (iv/100) * 0.12) + 0.5)) : Math.max(2, Math.round(intrinsic/20 + 0.5));
    return { strike: s, estimated_premium: estPremium, stop_loss: Math.round(estPremium*2), target: Math.round(estPremium*4) };
  });

  res.json({ status: fetchError ? 'fallback' : 'ok', fetchError, trend, strikes: strikeOptions, expiryDays, market });
});

// Settings endpoints for frontend to read/update
app.get('/api/settings', (req,res)=>{
  try{
    const s = JSON.parse(fs.readFileSync('./backend/settings.json','utf8'));
    res.json({ok:true, settings:s});
  }catch(e){ res.json({ok:false}); }
});

app.post('/api/settings', (req,res)=>{
  try{
    fs.writeFileSync('./backend/settings.json', JSON.stringify(req.body, null,2));
    res.json({ok:true});
  }catch(e){ res.json({ok:false}); }
});

// Serve frontend index
app.get('/', (req,res)=>{
  res.sendFile(__dirname + '/frontend/index.html');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('Server running on port '+PORT));
