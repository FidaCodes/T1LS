const { WebClient } = require("@slack/web-api");

// Initialize Slack client
const slackClient = new WebClient(process.env.SLACK_BOT_TOKEN);

/**
 * Send a message to a Slack channel
 * @param {string} channelId - The Slack channel ID
 * @param {string} text - Plain text message (fallback)
 * @param {Array} blocks - Slack Block Kit blocks (optional)
 */
const sendMessage = async (req, res) => {
  try {
    const { channelId, text, blocks } = req.body;

    // Validation
    if (!channelId) {
      return res.status(400).json({
        success: false,
        error: "channelId is required",
      });
    }

    if (!text && !blocks) {
      return res.status(400).json({
        success: false,
        error: "Either text or blocks must be provided",
      });
    }

    // Prepare message payload
    const messagePayload = {
      channel: channelId,
      text: text || "New notification",
    };

    // Add blocks if provided
    if (blocks && Array.isArray(blocks)) {
      messagePayload.blocks = blocks;
    }

    // Send message via Slack API
    const result = await slackClient.chat.postMessage(messagePayload);

    res.status(200).json({
      success: true,
      message: "Message sent successfully",
      data: {
        channel: result.channel,
        timestamp: result.ts,
        messageId: result.message?.ts,
      },
    });
  } catch (error) {
    console.error("Error sending Slack message:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Failed to send message",
      details: error.data || null,
    });
  }
};

/**
 * Send a threat intelligence alert to Slack
 * @param {string} channelId - The Slack channel ID
 * @param {Object} alertData - Threat intelligence data
 */
const sendThreatAlert = async (req, res) => {
  try {
    const { channelId, alertData } = req.body;

    // Validation
    if (!channelId) {
      return res.status(400).json({
        success: false,
        error: "channelId is required",
      });
    }

    if (!alertData) {
      return res.status(400).json({
        success: false,
        error: "alertData is required",
      });
    }

    // Extract alert information
    const { ioc, iocType, verdict, confidence, sources, timestamp, analyst } =
      alertData;

    // Determine color based on verdict
    const getColor = (verdict) => {
      switch (verdict?.toLowerCase()) {
        case "malicious":
          return "#dc2626"; // Red
        case "suspicious":
          return "#f59e0b"; // Orange
        case "clean":
        case "benign":
          return "#10b981"; // Green
        default:
          return "#6b7280"; // Gray
      }
    };

    // Build Slack blocks
    const blocks = [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: "🚨 Threat Intelligence Alert",
          emoji: true,
        },
      },
      {
        type: "section",
        fields: [
          {
            type: "mrkdwn",
            text: `*IOC:*\n\`${ioc || "N/A"}\``,
          },
          {
            type: "mrkdwn",
            text: `*Type:*\n${iocType || "Unknown"}`,
          },
          {
            type: "mrkdwn",
            text: `*Verdict:*\n${verdict || "Unknown"}`,
          },
          {
            type: "mrkdwn",
            text: `*Confidence:*\n${confidence || 0}%`,
          },
        ],
      },
      {
        type: "divider",
      },
    ];

    // Add sources section if available
    if (sources && Object.keys(sources).length > 0) {
      const sourceFields = Object.entries(sources).map(([source, data]) => ({
        type: "mrkdwn",
        text: `*${source}:*\n${data.verdict || "N/A"}`,
      }));

      blocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: "*Threat Intelligence Sources:*",
        },
      });

      blocks.push({
        type: "section",
        fields: sourceFields.slice(0, 10), // Limit to 10 fields
      });
    }

    // Add footer
    blocks.push({
      type: "context",
      elements: [
        {
          type: "mrkdwn",
          text: `Analyzed by: ${analyst || "AI Threat Intelligence"} | ${
            timestamp || new Date().toISOString()
          }`,
        },
      ],
    });

    // Send message with attachment for color
    const result = await slackClient.chat.postMessage({
      channel: channelId,
      text: `Threat Alert: ${ioc} - ${verdict}`,
      blocks: blocks,
      attachments: [
        {
          color: getColor(verdict),
          fallback: `Threat Alert: ${ioc} - ${verdict}`,
        },
      ],
    });

    res.status(200).json({
      success: true,
      message: "Threat alert sent successfully",
      data: {
        channel: result.channel,
        timestamp: result.ts,
      },
    });
  } catch (error) {
    console.error("Error sending threat alert:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Failed to send threat alert",
      details: error.data || null,
    });
  }
};

/**
 * Send a custom block message to Slack
 * @param {string} channelId - The Slack channel ID
 * @param {Array} blocks - Slack Block Kit blocks
 * @param {string} text - Fallback text
 */
const sendBlockMessage = async (req, res) => {
  try {
    const { channelId, blocks, text } = req.body;

    // Validation
    if (!channelId) {
      return res.status(400).json({
        success: false,
        error: "channelId is required",
      });
    }

    if (!blocks || !Array.isArray(blocks) || blocks.length === 0) {
      return res.status(400).json({
        success: false,
        error: "blocks array is required and must not be empty",
      });
    }

    // Send message
    const result = await slackClient.chat.postMessage({
      channel: channelId,
      text: text || "New message",
      blocks: blocks,
    });

    res.status(200).json({
      success: true,
      message: "Block message sent successfully",
      data: {
        channel: result.channel,
        timestamp: result.ts,
      },
    });
  } catch (error) {
    console.error("Error sending block message:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Failed to send block message",
      details: error.data || null,
    });
  }
};

/**
 * Test Slack connection
 */
const testConnection = async (req, res) => {
  try {
    const result = await slackClient.auth.test();

    res.status(200).json({
      success: true,
      message: "Slack connection successful",
      data: {
        botId: result.user_id,
        botName: result.user,
        teamId: result.team_id,
        teamName: result.team,
      },
    });
  } catch (error) {
    console.error("Error testing Slack connection:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Failed to connect to Slack",
      details: error.data || null,
    });
  }
};

/**
 * List available channels
 */
const listChannels = async (req, res) => {
  try {
    const result = await slackClient.conversations.list({
      types: "public_channel,private_channel",
      limit: 100,
    });

    const channels = result.channels.map((channel) => ({
      id: channel.id,
      name: channel.name,
      isPrivate: channel.is_private,
      isMember: channel.is_member,
    }));

    res.status(200).json({
      success: true,
      message: "Channels retrieved successfully",
      data: {
        channels: channels,
        count: channels.length,
      },
    });
  } catch (error) {
    console.error("Error listing channels:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Failed to list channels",
      details: error.data || null,
    });
  }
};

module.exports = {
  sendMessage,
  sendThreatAlert,
  sendBlockMessage,
  testConnection,
  listChannels,
};
