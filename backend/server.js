/* ============================
   PART–1 : BASE + MASTER + UTILS + DEBUG
   ============================ */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const DEBUG = true;
function dbg(...args) { if (DEBUG) console.log("[DEBUG]", ...args); }

/* ENV */
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* Global State */
global.instrumentMaster = [];

let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null
};

let lastKnown = { spot: null, updatedAt: 0, prevSpot: null };

/* Load Scrip Master */
async function loadMasterOnline() {
  try {
    const url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
    const r = await fetch(url);
    const j = await r.json().catch(()=>null);

    if (Array.isArray(j) && j.length > 5000) {
      global.instrumentMaster = j;
      console.log("MASTER LOADED ✔ count =", j.length);
    } else {
      console.log("MASTER FAILED → empty or invalid");
    }
  } catch (e) {
    console.log("MASTER LOAD ERROR =", e);
  }
}
loadMasterOnline();
setInterval(loadMasterOnline, 60 * 60 * 1000);

/* UTILITIES */
function safeNum(n){ n = Number(n); return isFinite(n) ? n : 0; }
function tsOf(e){ return String(e.tradingsymbol || e.symbol || e.name || "").toUpperCase().trim(); }
function itypeOf(e){ return String(e.instrumenttype || e.instrumentType || e.type || "").toUpperCase().trim(); }
function parseExpiryDate(v){
  if(!v) return null;
  const m = moment(String(v).trim(), [
    "YYYY-MM-DD","YYYYMMDD","DD-MMM-YYYY","DDMMYYYY","DD-MM-YYYY",moment.ISO_8601
  ], true);
  return m.isValid() ? m.toDate() : null;
}
function isTokenSane(t) {
  if(t===undefined || t===null) return false;
  const s = String(t).replace(/\D/g,"");
  return Number(s) > 0;
}
/* ============================
   PART–2 : LOGIN + WS + SPOT
   ============================ */

function base32Decode(input){
  if(!input) return Buffer.from([]);
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  input=input.replace(/=+$/,"").toUpperCase();
  let bits=0,val=0,out=[];
  for(let ch of input){
    let idx=alphabet.indexOf(ch);
    if(idx<0) continue;
    val=(val<<5)|idx;
    bits+=5;
    if(bits>=8){
      out.push((val>>>(bits-8))&255);
      bits-=8;
    }
  }
  return Buffer.from(out);
}

function generateTOTP(secret){
  try{
    const key=base32Decode(secret);
    const time=Math.floor(Date.now()/30000);
    const buf=Buffer.alloc(8); buf.writeUInt32BE(0,0); buf.writeUInt32BE(time,4);
    const hmac=crypto.createHmac("sha1",key).update(buf).digest();
    const off=hmac[hmac.length-1]&0xf;
    const code=((hmac[off]&0x7f)<<24)|((hmac[off+1]&0xff)<<16)|((hmac[off+2]&0xff)<<8)|(hmac[off+3]&0xff);
    return (code%1000000).toString().padStart(6,"0");
  }catch(e){
    return null;
  }
}

/* SMART LOGIN */
async function smartApiLogin(password){
  if(!password) return { ok:false, reason:"PASSWORD_MISSING" };
  const totp = generateTOTP(SMART_TOTP_SECRET);
  dbg("Generated TOTP =", totp);

  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        "X-UserType":"USER",
        "X-SourceID":"WEB",
        "X-ClientLocalIP":"127.0.0.1",
        "X-ClientPublicIP":"127.0.0.1",
        "X-PrivateKey": SMART_API_KEY
      },
      body: JSON.stringify({ clientcode: SMART_USER_ID, password, totp })
    });

    const j = await resp.json().catch(()=>null);

    dbg("LOGIN RESPONSE =", j);

    if(!j || j.status === false)
      return { ok:false, reason:"LOGIN_FAILED", raw:j };

    session.access_token = j.data?.jwtToken || null;
    session.refresh_token = j.data?.refreshToken || null;
    session.feed_token = j.data?.feedToken || null;

    dbg("LOGIN SUCCESS → AT =", session.access_token, "FT =", session.feed_token);

    setTimeout(()=> startWebsocketIfReady(), 1500);

    return { ok:true };
  }
  catch(e){
    dbg("LOGIN EXCEPTION =", e);
    return { ok:false, reason:"EXCEPTION", error:String(e) };
  }
}

/* -------- WEBSOCKET -------- */

const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";
let wsClient = null;
let wsStatus = { connected:false, lastMsgAt:0, subs:[], reconnects:0 };

async function startWebsocketIfReady(){
  if(wsClient && wsStatus.connected) return;
  if(!session.feed_token || !session.access_token){
    dbg("WS waiting for tokens...");
    return;
  }

  dbg("WS CONNECT →", WS_URL);
  wsClient = new WebSocket(WS_URL, {
    headers:{
      Authorization: session.access_token,
      "x-api-key": SMART_API_KEY,
      "x-client-code": SMART_USER_ID,
      "x-feed-token": session.feed_token
    }
  });

  wsClient.on("open", ()=>{
    dbg("WS OPENED ✔");
    wsStatus.connected = true;

    const auth = { task:"auth", channel:"websocket", token: session.feed_token, user: SMART_USER_ID };
    dbg("WS AUTH SEND →", auth);

    wsClient.send(JSON.stringify(auth));

    setTimeout(()=> subscribeCoreSymbols(), 1200);
  });

  wsClient.on("message", raw=>{
    wsStatus.lastMsgAt = Date.now();
    let msg=null;
    try{ msg=JSON.parse(raw); }catch{}

    dbg("WS MSG =", msg?.data?.tradingsymbol, msg?.data?.ltp);
  });

  wsClient.on("error", err=>{
    dbg("WS ERROR =", err);
  });

  wsClient.on("close", code=>{
    dbg("WS CLOSED =", code);
    wsStatus.connected=false;
  });
}

/* -------- SPOT RESOLVER (with debug) -------- */

async function fetchLTPFromToken(exchange, tradingsymbol, token){
  dbg("LTP REQUEST →", {exchange, tradingsymbol, token});
  try {
    const r = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`, {
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        Authorization: session.access_token,
        "X-PrivateKey": SMART_API_KEY,
        "X-UserType":"USER",
        "X-SourceID":"WEB"
      },
      body: JSON.stringify({
        exchange, tradingsymbol,
        symboltoken: String(token||"")
      })
    });

    const j = await r.json().catch(()=>null);
    dbg("LTP RESPONSE →", tradingsymbol, j?.data?.ltp);

    const l = Number(j?.data?.ltp || j?.data?.lastPrice || 0);
    return l > 0 ? l : null;
  }
  catch(e){
    dbg("LTP ERROR →", e);
    return null;
  }
}
/* ============================
   PART–3 : TOKEN RESOLVER (DEBUG MODE)
   ============================ */

async function resolveInstrumentToken(symbol, expiry="", strike=0, type="FUT"){
  dbg("\n-----------------------------------------");
  dbg("TOKEN RESOLVE REQUEST →", {symbol, expiry, strike, type});
  dbg("-----------------------------------------");

  let master = global.instrumentMaster;
  if(!Array.isArray(master) || master.length < 1000){
    dbg("MASTER EMPTY → reloading...");
    await loadMasterOnline();
    master = global.instrumentMaster;
  }

  const wantSym = symbol.toUpperCase();
  const wantType = type.toUpperCase();
  const wantStrike = Number(strike||0);

  /* First filter broad candidates */
  const candidates = master.filter(it=>{
    const ts = tsOf(it);
    return ts.includes(wantSym);
  });

  dbg("CANDIDATES COUNT =", candidates.length);

  if(!candidates.length) return null;

  /* EXTRA DEBUG: print first 10 candidates */
  dbg("SAMPLE CANDIDATES:");
  candidates.slice(0,10).forEach((x,i)=>{
    dbg(i, tsOf(x), x.instrumenttype, x.token);
  });

  /* 1) EXACT tradingsymbol match */
  const exact = candidates.find(it => tsOf(it) === wantSym);
  if(exact && isTokenSane(exact.token)){
    dbg("MATCH: EXACT TS →", tsOf(exact), exact.token);
    return { instrument: exact, token:String(exact.token) };
  }

  /* 2) OPTION Matching */
  if(wantType === "CE" || wantType === "PE"){
    dbg("MODE: OPTION RESOLVE");

    const side = wantType;
    let opts = candidates.filter(it=>{
      const ts = tsOf(it);
      const itype = itypeOf(it);

      if(!ts.endsWith(side) && !itype.includes(side)) return false;

      const st = Number(it.strike || it.strikePrice || 0);
      if(Math.abs(st - wantStrike) > 1) return false;

      return isTokenSane(it.token);
    });

    dbg("OPTIONS FOUND =", opts.length);

    if(opts.length){
      opts.sort((a,b)=>{
        const ea = parseExpiryDate(a.expiry);
        const eb = parseExpiryDate(b.expiry);
        return Math.abs(ea - Date.now()) - Math.abs(eb - Date.now());
      });

      dbg("OPTION PICKED →", tsOf(opts[0]), opts[0].token);
      return { instrument: opts[0], token:String(opts[0].token) };
    }
  }

  /* 3) FUTURES Matching */
  if(wantType === "FUT"){
    dbg("MODE: FUTURE RESOLVE");

    let futs = candidates.filter(it=>{
      const itype = itypeOf(it);
      if(!itype.includes("FUT")) return false;
      return isTokenSane(it.token);
    });

    dbg("FUTS FOUND =", futs.length);

    if(futs.length){
      futs.sort((a,b)=>{
        const ea = parseExpiryDate(a.expiry);
        const eb = parseExpiryDate(b.expiry);
        return Math.abs(ea - Date.now()) - Math.abs(eb - Date.now());
      });
      dbg("FUT PICKED →", tsOf(futs[0]), futs[0].token);
      return { instrument: futs[0], token:String(futs[0].token) };
    }
  }

  /* 4) fallback */
  dbg("NO STRICT MATCH → searching fallback");

  const fb = candidates.find(it=>isTokenSane(it.token));
  if(fb){
    dbg("FALLBACK PICKED →", tsOf(fb), fb.token);
    return { instrument: fb, token:String(fb.token) };
  }

  dbg("NO TOKEN RESOLVED");
  return null;
}
/* ============================
   PART–4 : ENTRY ENGINE + ROUTES
   ============================ */

async function fetchOptionLTP(symbol, strike, type){
  dbg("OPTION LTP REQUEST →", {symbol, strike, type});
  const expiry = detectExpiryForSymbol(symbol).currentWeek;

  const tok = await resolveInstrumentToken(symbol, expiry, strike, type);
  dbg("OPTION TOKEN →", tok);

  if(!tok) return null;

  const ltp = await fetchLTPFromToken(tok.instrument.exchange || "NFO", tok.instrument.tradingsymbol, tok.token);
  dbg("OPTION LTP =", ltp);
  return ltp;
}

async function subscribeCoreSymbols(){
  dbg("SUBSCRIBE CORE SYMBOLS...");
  const symbols = ["NIFTY", "SENSEX", "NATURALGAS"];
  const expiry = detectExpiryForSymbol("NIFTY").currentWeek;

  const tokens = [];

  for (let s of symbols) {
    const tok = await resolveInstrumentToken(s, expiry, 0, "FUT");
    dbg("SUB TOKEN:", s, tok);

    if(tok && tok.token) tokens.push(String(tok.token));
  }

  dbg("FINAL SUB TOKENS =", tokens);

  if(wsClient && tokens.length){
    const sub = {
      task:"cn",
      channel:{
        instrument_tokens: tokens,
        feed_type:"ltp"
      }
    };

    wsClient.send(JSON.stringify(sub));
    wsStatus.subs = tokens;

    console.log("WS SUBSCRIBED →", tokens);
  }
}

/* CALC ROUTE */
app.post("/api/calc", async (req,res)=>{
  dbg("\n===== CALC REQUEST =====");
  dbg(req.body);

  const { market="NIFTY", ema20, ema50, vwap, rsi, spot, expiry_days } = req.body;

  let finalSpot = null;

  if(lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000){
    finalSpot = lastKnown.spot;
    dbg("SPOT SOURCE = LIVE WS →", finalSpot);
  }
  else if(spot){
    finalSpot = Number(spot);
    dbg("SPOT SOURCE = MANUAL →", finalSpot);
  }
  else{
    const fb = await resolveSpot(market);
    dbg("SPOT SOURCE = AUTO RESOLVE →", fb);
    finalSpot = fb;
  }

  if(!finalSpot){
    dbg("SPOT FAIL");
    return res.json({success:false, error:"Spot could not be resolved"});
  }

  /* simple trend */
  const trend = { direction:"UP", dummy:true }; // simplified for example

  /* strikes */
  const atm = Math.round(finalSpot/50)*50;

  const ce = await fetchOptionLTP(market, atm, "CE");
  const pe = await fetchOptionLTP(market, atm, "PE");

  dbg("CE LTP =", ce, "PE LTP =", pe);

  if(!ce || !pe){
    return res.json({
      success:true,
      entry:{ allowed:false, reason:"OPTION_LTP_FAIL", trend }
    });
  }

  return res.json({
    success:true,
    entry:{
      allowed:true,
      direction:"UP",
      atm,
      ce,
      pe
    }
  });
});

/* LOGIN */
app.post("/api/login", async (req,res)=>{
  const p = req.body.password || "";
  const r = await smartApiLogin(p);
  return res.json(r.ok ? {success:true} : {success:false, error:r.reason});
});

/* WS STATUS */
app.get("/api/ws/status",(req,res)=>{
  return res.json({
    connected: wsStatus.connected,
    subs: wsStatus.subs,
    lastMsgAt: wsStatus.lastMsgAt
  });
});

app.get("/", (req,res)=>res.send("Rahul Backend Active ✔ DEBUG MODE"));


/* START SERVER */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log("SERVER LIVE ON", PORT));
