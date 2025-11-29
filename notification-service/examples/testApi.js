/**
 * Example usage of the Notification Service API
 * Run this after starting the server: npm run dev
 */

const BASE_URL = "http://localhost:3003";

// Replace with your actual Slack channel ID
const CHANNEL_ID = "C12345678"; // Get this from /api/slack/channels endpoint

/**
 * Test Slack connection
 */
async function testConnection() {
  console.log("\n🧪 Testing Slack connection...");

  try {
    const response = await fetch(`${BASE_URL}/api/slack/test`);
    const result = await response.json();

    console.log("✅ Connection test result:", result);
    return result;
  } catch (error) {
    console.error("❌ Connection test failed:", error.message);
  }
}

/**
 * List available channels
 */
async function listChannels() {
  console.log("\n📋 Listing channels...");

  try {
    const response = await fetch(`${BASE_URL}/api/slack/channels`);
    const result = await response.json();

    console.log("✅ Available channels:", result.data?.channels);
    return result;
  } catch (error) {
    console.error("❌ List channels failed:", error.message);
  }
}

/**
 * Send a simple text message
 */
async function sendSimpleMessage() {
  console.log("\n💬 Sending simple message...");

  try {
    const response = await fetch(`${BASE_URL}/api/slack/send`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        channelId: CHANNEL_ID,
        text: "Hello from Threat Intel Bot! 👋 This is a test message.",
      }),
    });

    const result = await response.json();
    console.log("✅ Message sent:", result);
    return result;
  } catch (error) {
    console.error("❌ Send message failed:", error.message);
  }
}

/**
 * Send a threat intelligence alert
 */
async function sendThreatAlert() {
  console.log("\n🚨 Sending threat alert...");

  try {
    const response = await fetch(`${BASE_URL}/api/slack/alert`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        channelId: CHANNEL_ID,
        alertData: {
          ioc: "malicious-domain.example.com",
          iocType: "domain",
          verdict: "malicious",
          confidence: 95,
          sources: {
            VirusTotal: {
              verdict: "malicious",
              count: 45,
            },
            AbuseIPDB: {
              verdict: "suspicious",
              confidence: 85,
            },
            URLScan: {
              verdict: "malicious",
              score: 100,
            },
            Shodan: {
              verdict: "open_ports",
              count: 3,
            },
          },
          timestamp: new Date().toISOString(),
          analyst: "AI Threat Intelligence System",
        },
      }),
    });

    const result = await response.json();
    console.log("✅ Threat alert sent:", result);
    return result;
  } catch (error) {
    console.error("❌ Send threat alert failed:", error.message);
  }
}

/**
 * Send a custom block message
 */
async function sendCustomBlockMessage() {
  console.log("\n🎨 Sending custom block message...");

  try {
    const response = await fetch(`${BASE_URL}/api/slack/blocks`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        channelId: CHANNEL_ID,
        text: "Custom Security Alert",
        blocks: [
          {
            type: "header",
            text: {
              type: "plain_text",
              text: "🎯 Custom Security Alert",
              emoji: true,
            },
          },
          {
            type: "section",
            fields: [
              {
                type: "mrkdwn",
                text: "*Severity:*\nHigh",
              },
              {
                type: "mrkdwn",
                text: "*Status:*\nActive",
              },
              {
                type: "mrkdwn",
                text: "*Priority:*\nP1",
              },
              {
                type: "mrkdwn",
                text: "*Assigned:*\nSecurity Team",
              },
            ],
          },
          {
            type: "divider",
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: "*Description:*\nMultiple failed login attempts detected from suspicious IP address `192.168.1.100`. This may indicate a brute force attack in progress.",
            },
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: "*Recommended Action:*\n• Block the IP address\n• Review access logs\n• Notify affected users\n• Enable additional authentication factors",
            },
          },
          {
            type: "context",
            elements: [
              {
                type: "mrkdwn",
                text: `🕒 Detected at ${new Date().toLocaleString()}`,
              },
            ],
          },
        ],
      }),
    });

    const result = await response.json();
    console.log("✅ Custom block message sent:", result);
    return result;
  } catch (error) {
    console.error("❌ Send custom block failed:", error.message);
  }
}

/**
 * Send a message with multiple IOCs
 */
async function sendMultipleIOCsAlert() {
  console.log("\n🔍 Sending multiple IOCs alert...");

  try {
    const response = await fetch(`${BASE_URL}/api/slack/blocks`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        channelId: CHANNEL_ID,
        text: "Multiple IOCs Detected",
        blocks: [
          {
            type: "header",
            text: {
              type: "plain_text",
              text: "🚨 Multiple IOCs Detected",
              emoji: true,
            },
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: "*Campaign Detection:* APT-2024-001\n*Confidence:* 98%",
            },
          },
          {
            type: "divider",
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: "*Malicious Domains:*",
            },
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: "🔴 `evil-phishing-site.com`\n🔴 `malware-download.net`\n🔴 `fake-banking-portal.org`",
            },
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: "*Malicious IPs:*",
            },
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: "🔴 `192.0.2.1` - C2 Server\n🔴 `198.51.100.42` - Malware Distribution\n🔴 `203.0.113.99` - Data Exfiltration",
            },
          },
          {
            type: "divider",
          },
          {
            type: "context",
            elements: [
              {
                type: "mrkdwn",
                text: `⚡ Automated Detection | ${new Date().toLocaleString()}`,
              },
            ],
          },
        ],
      }),
    });

    const result = await response.json();
    console.log("✅ Multiple IOCs alert sent:", result);
    return result;
  } catch (error) {
    console.error("❌ Send multiple IOCs failed:", error.message);
  }
}

/**
 * Run all examples
 */
async function runAllExamples() {
  console.log("🚀 Running all notification service examples...\n");
  console.log("⚠️  Make sure to update CHANNEL_ID in this file!\n");

  // Test connection first
  await testConnection();

  // List channels to help find the right channel ID
  await listChannels();

  // Wait a bit between requests
  await new Promise((resolve) => setTimeout(resolve, 2000));

  // Send different types of messages
  await sendSimpleMessage();
  await new Promise((resolve) => setTimeout(resolve, 2000));

  await sendThreatAlert();
  await new Promise((resolve) => setTimeout(resolve, 2000));

  await sendCustomBlockMessage();
  await new Promise((resolve) => setTimeout(resolve, 2000));

  await sendMultipleIOCsAlert();

  console.log("\n✨ All examples completed!");
}

// Run examples if this file is executed directly
if (require.main === module) {
  runAllExamples().catch(console.error);
}

module.exports = {
  testConnection,
  listChannels,
  sendSimpleMessage,
  sendThreatAlert,
  sendCustomBlockMessage,
  sendMultipleIOCsAlert,
};
