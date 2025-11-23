
const qs = id => document.getElementById(id);
function getServer(){ const s = qs('server').value.trim(); return s? s.replace(/\/$/,'') : '';}
async function calc(){
  const server = getServer();
  const url = server? server + '/api/signal' : '/api/signal';
  const payload = {
    ema20: Number(qs('ema20').value)||0,
    ema50: Number(qs('ema50').value)||0,
    rsi: Number(qs('rsi').value)||0,
    vwap: Number(qs('vwap').value)||0,
    spot: Number(qs('spot').value)||0,
    market: qs('market').value,
    expiry_days: Number(qs('expiry').value)||7,
    use_live: qs('useLive').checked
  };
  qs('out').textContent = 'Calculating...';
  try{
    const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    const j = await r.json();
    qs('out').textContent = JSON.stringify(j,null,2);
  }catch(e){ qs('out').textContent = 'Network error: '+e.message; }
}
document.getElementById('calc').addEventListener('click', calc);
