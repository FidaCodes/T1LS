/**
 * Slack Block Builder Utilities
 * Helper functions to create Slack Block Kit blocks
 */

/**
 * Create a header block
 * @param {string} text - Header text
 */
const createHeader = (text) => ({
  type: "header",
  text: {
    type: "plain_text",
    text: text,
    emoji: true,
  },
});

/**
 * Create a section block with text
 * @param {string} text - Markdown text
 */
const createSection = (text) => ({
  type: "section",
  text: {
    type: "mrkdwn",
    text: text,
  },
});

/**
 * Create a section block with fields
 * @param {Array} fields - Array of field objects with text
 */
const createFieldsSection = (fields) => ({
  type: "section",
  fields: fields.map((field) => ({
    type: "mrkdwn",
    text: field,
  })),
});

/**
 * Create a divider block
 */
const createDivider = () => ({
  type: "divider",
});

/**
 * Create a context block (footer-like)
 * @param {Array} elements - Array of text strings
 */
const createContext = (elements) => ({
  type: "context",
  elements: elements.map((text) => ({
    type: "mrkdwn",
    text: text,
  })),
});

/**
 * Create an actions block with buttons
 * @param {Array} buttons - Array of button objects
 */
const createActions = (buttons) => ({
  type: "actions",
  elements: buttons.map((btn) => ({
    type: "button",
    text: {
      type: "plain_text",
      text: btn.text,
      emoji: true,
    },
    value: btn.value || btn.text,
    action_id: btn.actionId || `button_${Date.now()}`,
    style: btn.style || "primary",
  })),
});

/**
 * Create a threat alert block structure
 * @param {Object} data - Threat data
 */
const createThreatAlertBlocks = (data) => {
  const {
    title = "🚨 Threat Alert",
    ioc,
    iocType,
    verdict,
    confidence,
    severity,
    description,
    sources = {},
    timestamp,
    analyst,
  } = data;

  const blocks = [];

  // Header
  blocks.push(createHeader(title));

  // Main info section
  const mainFields = [];
  if (ioc) mainFields.push(`*IOC:*\n\`${ioc}\``);
  if (iocType) mainFields.push(`*Type:*\n${iocType}`);
  if (verdict) mainFields.push(`*Verdict:*\n${verdict}`);
  if (confidence !== undefined)
    mainFields.push(`*Confidence:*\n${confidence}%`);

  if (mainFields.length > 0) {
    blocks.push(createFieldsSection(mainFields));
  }

  // Description
  if (description) {
    blocks.push(createSection(`*Description:*\n${description}`));
  }

  blocks.push(createDivider());

  // Sources section
  if (Object.keys(sources).length > 0) {
    blocks.push(createSection("*Threat Intelligence Sources:*"));

    const sourceFields = Object.entries(sources)
      .slice(0, 8) // Limit to 8 sources
      .map(([source, data]) => {
        const verdict = data.verdict || "N/A";
        const extra = data.count ? ` (${data.count})` : "";
        return `*${source}:*\n${verdict}${extra}`;
      });

    if (sourceFields.length > 0) {
      blocks.push(createFieldsSection(sourceFields));
    }
  }

  // Footer
  const footerElements = [];
  if (analyst) footerElements.push(`👤 ${analyst}`);
  if (timestamp) footerElements.push(`🕒 ${timestamp}`);

  if (footerElements.length > 0) {
    blocks.push(createContext(footerElements));
  }

  return blocks;
};

/**
 * Get color based on verdict
 * @param {string} verdict - Verdict string
 */
const getVerdictColor = (verdict) => {
  const v = verdict?.toLowerCase();
  switch (v) {
    case "malicious":
    case "malware":
      return "#dc2626"; // Red
    case "suspicious":
    case "warning":
      return "#f59e0b"; // Orange
    case "clean":
    case "benign":
    case "safe":
      return "#10b981"; // Green
    case "unknown":
    case "skipped":
      return "#6b7280"; // Gray
    default:
      return "#6b7280";
  }
};

/**
 * Get emoji based on verdict
 * @param {string} verdict - Verdict string
 */
const getVerdictEmoji = (verdict) => {
  const v = verdict?.toLowerCase();
  switch (v) {
    case "malicious":
    case "malware":
      return "🔴";
    case "suspicious":
    case "warning":
      return "🟡";
    case "clean":
    case "benign":
    case "safe":
      return "🟢";
    case "unknown":
    case "skipped":
      return "⚪";
    default:
      return "⚪";
  }
};

/**
 * Format timestamp to readable string
 * @param {string} timestamp - ISO timestamp
 */
const formatTimestamp = (timestamp) => {
  try {
    const date = new Date(timestamp);
    return date.toLocaleString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZoneName: "short",
    });
  } catch (error) {
    return timestamp;
  }
};

module.exports = {
  createHeader,
  createSection,
  createFieldsSection,
  createDivider,
  createContext,
  createActions,
  createThreatAlertBlocks,
  getVerdictColor,
  getVerdictEmoji,
  formatTimestamp,
};
