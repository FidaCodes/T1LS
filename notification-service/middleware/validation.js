/**
 * Validation middleware for Slack requests
 */

/**
 * Validate Slack message request
 */
const validateSlackMessage = (req, res, next) => {
  const { channelId, text, blocks } = req.body;

  if (!channelId) {
    return res.status(400).json({
      success: false,
      error: "channelId is required",
      details: {
        received: req.body,
        expected: {
          channelId: "string (required)",
          text: "string (required if no blocks)",
          blocks: "array (optional)",
        },
      },
    });
  }

  if (!text && (!blocks || !Array.isArray(blocks) || blocks.length === 0)) {
    return res.status(400).json({
      success: false,
      error: "Either text or blocks must be provided",
      details: {
        received: req.body,
        expected: {
          channelId: "string (required)",
          text: "string (required if no blocks)",
          blocks: "array (required if no text)",
        },
      },
    });
  }

  next();
};

/**
 * Validate threat alert request
 */
const validateThreatAlert = (req, res, next) => {
  const { channelId, alertData } = req.body;

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

  // Validate alertData structure
  const requiredFields = ["ioc", "verdict"];
  const missingFields = requiredFields.filter((field) => !alertData[field]);

  if (missingFields.length > 0) {
    return res.status(400).json({
      success: false,
      error: `Missing required fields in alertData: ${missingFields.join(
        ", "
      )}`,
      details: {
        received: alertData,
        required: ["ioc", "verdict"],
        optional: ["iocType", "confidence", "sources", "timestamp", "analyst"],
      },
    });
  }

  next();
};

/**
 * Validate block message request
 */
const validateBlockMessage = (req, res, next) => {
  const { channelId, blocks } = req.body;

  if (!channelId) {
    return res.status(400).json({
      success: false,
      error: "channelId is required",
    });
  }

  if (!blocks || !Array.isArray(blocks)) {
    return res.status(400).json({
      success: false,
      error: "blocks must be an array",
    });
  }

  if (blocks.length === 0) {
    return res.status(400).json({
      success: false,
      error: "blocks array cannot be empty",
    });
  }

  // Validate each block has a type
  const invalidBlocks = blocks.filter((block, index) => !block.type);
  if (invalidBlocks.length > 0) {
    return res.status(400).json({
      success: false,
      error: "All blocks must have a type property",
      details: {
        invalidBlocks: invalidBlocks,
        validTypes: [
          "header",
          "section",
          "divider",
          "context",
          "actions",
          "image",
        ],
      },
    });
  }

  next();
};

/**
 * Request logging middleware
 */
const logRequest = (req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);

  if (req.method !== "GET" && req.body) {
    // Log body but hide sensitive data
    const sanitizedBody = { ...req.body };
    if (sanitizedBody.channelId) {
      sanitizedBody.channelId = sanitizedBody.channelId.substring(0, 3) + "...";
    }
    console.log("  Body:", JSON.stringify(sanitizedBody, null, 2));
  }

  next();
};

module.exports = {
  validateSlackMessage,
  validateThreatAlert,
  validateBlockMessage,
  logRequest,
};
