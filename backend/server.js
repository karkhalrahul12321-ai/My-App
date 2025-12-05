require("dotenv").config();
const express = require("express");
const path = require("path");
const app = express();

const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// =========================
// HEALTH CHECK
// =========================
app.get("/health", (req, res) => {
  res.send({ ok: true, msg: "Trading backend running successfully" });
});

// =========================
// BACKEND API ROUTE
// =========================
const suggest = require("./engines/apiSuggest");

app.post("/api/suggest-strikes", async (req, res) => {
  try {
    const output = await suggest.handler(req.body);
    res.json(output);
  } catch (err) {
    console.error("ERROR:", err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// =========================
// FRONTEND SERVING
// =========================

// Serve static frontend files (HTML/JS/CSS)
app.use(express.static(path.join(__dirname, "../frontend")));

// Handle all frontend routes → load index.html
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

// =========================
// START SERVER
// =========================
app.listen(port, () => {
  console.log("🚀 Trading Backend + Frontend LIVE on:", port);
});
