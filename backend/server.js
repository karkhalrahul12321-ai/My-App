require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Parse JSON body
app.use(express.json());

// Serve frontend build
app.use(express.static(path.join(__dirname, '../frontend/dist')));

// Health API
app.get('/api/health', (req, res) => {
  res.send({ ok: true, msg: "Trading backend running successfully" });
});

// Suggestion Engine Route
const suggest = require('./engines/apiSuggest');
app.post('/api/suggest-strikes', async (req, res) => {
  try {
    const output = await suggest.handler(req.body);
    res.json(output);
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// Serve frontend (catch-all)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/dist/index.html'));
});

// Start server
app.listen(port, () => {
  console.log("🚀 Trading Backend + Frontend LIVE on:", port);
});
