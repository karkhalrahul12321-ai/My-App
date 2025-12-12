// server.js — Part 1 of 2
// Integrated with engines/apiSuggest (which orchestrates all sub-engines).
// Ensure your engines folder is at ./engines and apiSuggest.js exists.
// References: apiSuggest (orchestrator), optionChain, greeksEngine. 3 4 5

const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- Engines import (single entrypoint) ---
let suggestEngine;
try {
  suggestEngine = require("./engines/apiSuggest");
} catch (e) {
  console.error("Failed to load engines/apiSuggest. Make sure ./engines/apiSuggest.js exists.", e);
  // Keep server running but mark suggestEngine as unavailable.
  suggestEngine = null;
}

// --- Middleware ---
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// --- Frontend static (optional) ---
const frontendPath = path.join(__dirname, "public"); // adjust if your frontend build is elsewhere
if (fs.existsSync(frontendPath)) {
  app.use(express.static(frontendPath));
}

// --- Simple logger for incoming requests (light) ---
app.use((req, res, next) => {
  // avoid logging bodies for large requests in production
  console.log(`${new Date().toISOString()} → ${req.method} ${req.originalUrl}`);
  next();
});

// --- Helper: safe JSON response ---
function safeJson(res, obj, status = 200) {
  res.status(status).json(obj);
}
// server.js — Part 2 of 2 (continued)

// --- Root route: serve frontend index.html if exists, otherwise a simple message ---
app.get("/", (req, res) => {
  try {
    const indexFile = path.join(frontendPath, "index.html");
    if (fs.existsSync(indexFile)) {
      return res.sendFile(indexFile);
    } else {
      return res.send("Rahul Backend OK — LIVE WebSocket & Engines Enabled 🚀");
    }
  } catch (e) {
    return res.send("Rahul Backend OK — LIVE WebSocket & Engines Enabled 🚀");
  }
});

// --- Health / Ping endpoints ---
app.get("/health", (req, res) => safeJson(res, { ok: true, env: process.env.NODE_ENV || "development" }));
app.get("/ping", (req, res) => safeJson(res, { ok: true, ts: Date.now() }));

// --- Primary Intelligent Engine Route (/api/suggest) ---
app.post("/api/suggest", async (req, res) => {
  if (!suggestEngine) {
    return safeJson(res, { ok: false, error: "Suggest engine not loaded on server" }, 500);
  }

  try {
    // Basic validation: ensure market present or spot provided
    const body = req.body || {};
    if (!body.market) {
      return safeJson(res, { ok: false, error: "Missing required field: market" }, 400);
    }

    const result = await suggestEngine.handler(body);
    // Expect result.ok true/false per apiSuggest contract
    return safeJson(res, result);
  } catch (err) {
    console.error("Error in /api/suggest:", err && err.stack ? err.stack : err);
    return safeJson(res, { ok: false, error: "Internal engine error" }, 500);
  }
});

// --- Optional lightweight endpoints for debugging / manual calls ---
// Forward-compatible simple wrapper to detect spot / expiry via optionChain if needed
app.post("/api/auto/spot", async (req, res) => {
  try {
    const optionChain = require("./engines/optionChain");
    const market = (req.body && req.body.market) || req.query.market;
    if (!market) return safeJson(res, { ok: false, error: "market required" }, 400);
    const spot = await optionChain.autoDetectSpot(market.toLowerCase());
    return safeJson(res, { ok: true, market, spot });
  } catch (e) {
    console.error("auto/spot error:", e);
    return safeJson(res, { ok: false, error: "failed to fetch spot" }, 500);
  }
});

app.post("/api/auto/expiry", async (req, res) => {
  try {
    const optionChain = require("./engines/optionChain");
    const market = (req.body && req.body.market) || req.query.market;
    if (!market) return safeJson(res, { ok: false, error: "market required" }, 400);
    const expiry = await optionChain.autoDetectExpiry(market.toLowerCase());
    return safeJson(res, { ok: true, market, expiry });
  } catch (e) {
    console.error("auto/expiry error:", e);
    return safeJson(res, { ok: false, error: "failed to fetch expiry" }, 500);
  }
});

// --- Global error handler (final) ---
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  safeJson(res, { ok: false, error: "Unhandled server error" }, 500);
});

// --- Unhandled rejections / exceptions logging (keep process alive on render)
process.on("unhandledRejection", (reason, p) => {
  console.error("Unhandled Rejection at Promise:", p, "reason:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception thrown:", err && err.stack ? err.stack : err);
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} — ENV=${process.env.NODE_ENV || "development"}`);
  if (!suggestEngine) {
    console.warn("Warning: suggestEngine not loaded — /api/suggest will return 500 until engines are available.");
  }
});

module.exports = app;
