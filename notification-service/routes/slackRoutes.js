const express = require("express");
const router = express.Router();
const slackController = require("../controllers/slackController");

// Test Slack connection
router.get("/test", slackController.testConnection);

// List available channels
router.get("/channels", slackController.listChannels);

// Send a simple message
router.post("/send", slackController.sendMessage);

// Send a threat intelligence alert
router.post("/alert", slackController.sendThreatAlert);

// Send a custom block message
router.post("/blocks", slackController.sendBlockMessage);

module.exports = router;
