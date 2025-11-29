const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3003;

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    service: "notification-service",
    timestamp: new Date().toISOString(),
  });
});

// Import routes
const slackRoutes = require("./routes/slackRoutes");

// Use routes
app.use("/api/slack", slackRoutes);

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    message: "Notification Service API",
    version: "1.0.0",
    endpoints: {
      health: "/health",
      slack: "/api/slack",
    },
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Error:", err);
  res.status(err.status || 500).json({
    error: {
      message: err.message || "Internal Server Error",
      status: err.status || 500,
    },
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: {
      message: "Route not found",
      status: 404,
    },
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Notification Service running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/health`);
  console.log(`💬 Slack API: http://localhost:${PORT}/api/slack`);
});

module.exports = app;
