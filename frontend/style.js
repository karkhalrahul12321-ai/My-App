/* =============================
   GLOBAL BASE
============================= */
:root {
  --accent: #00e4ff;

  --bg-dark: #0b0f19;
  --card-dark: #131a2a;
  --text-dark: #e6ecff;

  --bg-light: #ffffff;
  --card-light: #f2f2f2;
  --text-light: #1a1a1a;

  --glass-bg: rgba(255, 255, 255, 0.10);
  --glass-blur: blur(12px);

  --neon-glow: 0 0 12px var(--accent), 0 0 28px var(--accent);
}

/* REMOVE DEFAULT MARGINS */
body {
  margin: 0;
  padding: 0;
  font-family: system-ui, Arial, sans-serif;
  background: var(--bg-dark);
  color: var(--text-dark);
}

/* APP WRAPPER */
.app {
  max-width: 420px;
  margin: auto;
  padding: 18px;
}

/* =============================
   THEMES
============================= */

body.theme-dark {
  background: var(--bg-dark);
  color: var(--text-dark);
}

body.theme-light {
  background: var(--bg-light) !important;
  color: var(--text-light) !important;
}

body.theme-light .card {
  background: var(--card-light);
  color: var(--text-light);
}

body.theme-neon {
  background: #000;
  color: #fff;
}

body.theme-neon .card {
  background: #050b13;
  border: 1px solid var(--accent);
  box-shadow: var(--neon-glow);
}

body.theme-glass {
  background: url('https://i.ibb.co/vQqkDQZ/blur-bg.jpg') center/cover fixed;
  color: #fff;
  backdrop-filter: var(--glass-blur);
}

body.theme-glass .card {
  background: var(--glass-bg);
  backdrop-filter: var(--glass-blur);
  border: 1px solid rgba(255,255,255,0.25);
}

/* =============================
   UI ELEMENTS
============================= */

.title {
  font-size: 24px;
  font-weight: bold;
  margin-bottom: 10px;
}

input, select {
  width: 100%;
  padding: 10px;
  font-size: 15px;
  border-radius: 8px;
  border: 1px solid #444;
  background: #111722;
  color: #fff;
}

.theme-light input,
.theme-light select {
  background: #fff;
  color: #000;
  border: 1px solid #ccc;
}

.grid {
  display: flex;
  gap: 10px;
  margin-bottom: 12px;
}

.card {
  padding: 15px;
  background: var(--card-dark);
  border-radius: 12px;
  margin-bottom: 15px;
}

.btn {
  width: 100%;
  padding: 12px;
  background: var(--accent);
  color: #000;
  font-weight: bold;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  cursor: pointer;
}

.btn-secondary {
  background: #333;
  color: #eee;
  margin-top: 10px;
}

.theme-light .btn-secondary {
  background: #ddd;
  color: #000;
}

#toggleOut {
  background: #222;
  color: #aaa;
  margin-bottom: 8px;
}

/* =============================
   OUTPUT BOX
============================= */

#outputBox {
  background: #050a14;
  padding: 12px;
  border-radius: 10px;
  font-size: 13px;
  white-space: pre-wrap;
  max-height: 400px;
  overflow-y: auto;
  border: 1px solid #333;
}

.theme-light #outputBox {
  background: #fff;
  color: #000;
}

.hidden {
  display: none;
}

/* =============================
   HEADER BAR
============================= */
.header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 15px;
}

.small-btn {
  padding: 6px 10px;
  background: #444;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
}

.theme-light .small-btn {
  background: #ccc;
  color: #000;
}

/* ACCENT COLOR UI */
#colorPick {
  margin-top: 8px;
  width: 100%;
  height: 40px;
  border: none;
  padding: 0;
  background: transparent;
}
