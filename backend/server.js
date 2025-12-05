require('dotenv').config();
const express = require('express');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Health API
app.get('/', (req, res) => {
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

// Start Server
app.listen(port, () => {
  console.log("🚀 Trading Backend LIVE on:", port);
});
