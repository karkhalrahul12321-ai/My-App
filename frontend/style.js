/* =========================================
   Trading Helper FINAL UI (THEME + COLOR)
   Supports:
   - Dark / Light / Neon / Glassmorphism themes
   - Accent color picker (CSS variable)
   - Big Output Window
   ========================================= */

:root {
  --accent: #27f3c2;

  /* LIGHT THEME DEFAULTS */
  --bg-light: #f7f7f7;
  --text-light: #0f172a;
  --card-light: white;
  --border-light: #ddd;

  /* DARK THEME DEFAULTS */
  --bg-dark: #080b14;
  --text-dark: #e8eeff;
  --card-dark: #101727;
  --border-dark: rgba(255, 255, 255, 0.12);

  /* GLASS THEME */
  --glass-bg: rgba(255, 255, 255, 0.08);
  --glass-border: rgba(255, 255, 255, 0.2);
}

/* =====================
   BASE COMMON LAYOUT
   ===================== */
body {
  margin: 0;
  padding: 25px 14px;
  font-family: system-ui, sans-serif;
  transition: all 0.25s ease;
}

/* Container */
.main-box {
  max-width: 480px;
  margin: auto;
  padding: 18px;
  border-radius: 20px;
  transition: 0.25s;
}

/* =====================
   THEMES
   ===================== */

/* DARK THEME */
body[data-theme="dark"] {
  background: radial-gradient(circle at top, #19233b 0, #060a14 60%, #03050c 100%);
  color: var(--text-dark);
}

body[data-theme="dark"] .main-box {
  background: var(--card-dark);
  border: 1px solid var(--border-dark);
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

/* LIGHT THEME */
body[data-theme="light"] {
  background: var(--bg-light);
  color: var(--text-light);
}

body[data-theme="light"] .main-box {
  background: var(--card-light);
  border: 1px solid var(--border-light);
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
}

/* NEON THEME */
body[data-theme="neon"] {
  background: #02050a;
  color: #dffcff;
}

body[data-theme="neon"] .main-box {
  background: #050b18;
  border: 1px solid rgba(0, 255, 255, 0.4);
  box-shadow: 0 0 25px var(--accent);
}

/* GLASS THEME */
body[data-theme="glass"] {
  background: url("https://i.imgur.com/7pQzLhA.jpeg") center/cover fixed;
  color: #f0f8ff;
}

body[data-theme="glass"] .main-box {
  background: var(--glass-bg);
  border: 1px solid var(--glass-border);
  backdrop-filter: blur(12px);
  box-shadow: 0 0 25px rgba(255, 255, 255, 0.15);
}

/* =====================
   TITLES
   ===================== */
.title {
  font-size: 26px;
  font-weight: bold;
  margin-bottom: 4px;
}

.sub {
  font-size: 14px;
  opacity: 0.7;
  margin-bottom: 16px;
}

/* =====================
   INPUT GRID
   ===================== */
.grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}

.grid div label {
  font-size: 12px;
  opacity: 0.7;
}

input, select {
  width: 100%;
  padding: 10px;
  font-size: 15px;
  margin-top: 4px;
  border-radius: 10px;
  border: 1px solid rgba(255,255,255,0.15);
  outline: none;
  transition: 0.2s;
}

/* Theme-based inputs */
body[data-theme="light"] input,
body[data-theme="light"] select {
  background: #fff;
  border: 1px solid #ccc;
  color: #000;
}

body[data-theme="dark"] input,
body[data-theme="dark"] select,
body[data-theme="neon"] input,
body[data-theme="neon"] select {
  background: #0b1120;
  color: #e6ecff;
  border: 1px solid rgba(255,255,255,0.15);
}

body[data-theme="glass"] input,
body[data-theme="glass"] select {
  background: rgba(0,0,0,0.4);
  color: white;
  backdrop-filter: blur(6px);
  border: 1px solid rgba(255,255,255,0.25);
}

/* =====================
   CHECKBOX ROW
   ===================== */
.chk-row {
  margin-top: 6px;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* =====================
   BUTTONS
   ===================== */
.btn {
  width: 100%;
  padding: 13px;
  margin-top: 18px;
  font-size: 17px;
  border-radius: 14px;
  border: none;
  cursor: pointer;
  font-weight: 600;
  background: var(--accent);
  color: black;
  transition: 0.15s;
}

.btn:hover {
  opacity: 0.9;
  transform: translateY(-2px);
}

/* SECONDARY */
.btn-secondary {
  background: rgba(255,255,255,0.12);
  color: white;
  margin-top: 10px;
}

body[data-theme="light"] .btn-secondary {
  background: #ddd;
  color: #000;
}

/* =====================
   OUTPUT BOX (BIG)
   ===================== */
.output {
  margin-top: 22px;
  padding: 15px;
  border-radius: 14px;
  font-size: 14px;
  white-space: pre-wrap;
  overflow-y: auto;
  background: rgba(0,0,0,0.75);
  color: #d0ffdd;
  border: 1px solid rgba(255,255,255,0.15);
  height: 380px;      /* BIGGER OUTPUT WINDOW */
}

body[data-theme="light"] .output {
  background: #fff;
  color: #222;
  border-color: #ccc;
}

body[data-theme="neon"] .output {
  background: rgba(0,0,0,0.85);
  border-color: var(--accent);
  box-shadow: 0 0 20px var(--accent);
}

body[data-theme="glass"] .output {
  background: rgba(0,0,0,0.55);
  backdrop-filter: blur(10px);
}

/* =====================
   SETTINGS PAGE
   ===================== */
#settingsPage {
  display: none;
}

/* Hide scrollbar in modern style */
.output::-webkit-scrollbar {
  width: 6px;
}
.output::-webkit-scrollbar-thumb {
  background: var(--accent);
  border-radius: 4px;
}
