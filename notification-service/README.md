# Notification Service

A Node.js/Express service for sending Slack notifications, specifically designed for threat intelligence alerts.

## Features

- ✅ Send simple text messages to Slack channels
- ✅ Send rich Block Kit messages with custom formatting
- ✅ Send formatted threat intelligence alerts
- ✅ Test Slack connection
- ✅ List available Slack channels
- ✅ RESTful API endpoints

## Setup

### 1. Create a Slack App

1. Go to https://api.slack.com/apps
2. Click "Create New App" → "From scratch"
3. Name your app (e.g., "Threat Intel Bot")
4. Select your workspace
5. Click "Create App"

### 2. Configure Bot Permissions

1. In your app settings, go to "OAuth & Permissions"
2. Under "Scopes" → "Bot Token Scopes", add these permissions:
   - `chat:write` - Send messages
   - `chat:write.public` - Send messages to public channels
   - `channels:read` - View public channels
   - `groups:read` - View private channels
   - `im:read` - View direct messages
   - `mpim:read` - View group direct messages

### 3. Install App to Workspace

1. Go to "OAuth & Permissions"
2. Click "Install to Workspace"
3. Authorize the app
4. Copy the "Bot User OAuth Token" (starts with `xoxb-`)

### 4. Configure Environment Variables

1. Copy `.env.example` to `.env`:

   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your Slack Bot Token:
   ```env
   PORT=3003
   SLACK_BOT_TOKEN=xoxb-your-bot-token-here
   ```

### 5. Install Dependencies

```bash
npm install
```

### 6. Start the Service

```bash
# Development mode with auto-reload
npm run dev

# Production mode
npm start
```

The service will start on `http://localhost:3003`

## API Endpoints

### Test Connection

```http
GET /api/slack/test
```

Tests the Slack connection and returns bot information.

**Response:**

```json
{
  "success": true,
  "message": "Slack connection successful",
  "data": {
    "botId": "U12345678",
    "botName": "threat-intel-bot",
    "teamId": "T12345678",
    "teamName": "Your Workspace"
  }
}
```

### List Channels

```http
GET /api/slack/channels
```

Returns a list of available Slack channels.

**Response:**

```json
{
  "success": true,
  "message": "Channels retrieved successfully",
  "data": {
    "channels": [
      {
        "id": "C12345678",
        "name": "general",
        "isPrivate": false,
        "isMember": true
      }
    ],
    "count": 1
  }
}
```

### Send Simple Message

```http
POST /api/slack/send
Content-Type: application/json

{
  "channelId": "C12345678",
  "text": "Hello from Threat Intel Bot!"
}
```

**Parameters:**

- `channelId` (required): The Slack channel ID
- `text` (required if no blocks): Plain text message
- `blocks` (optional): Slack Block Kit blocks array

**Response:**

```json
{
  "success": true,
  "message": "Message sent successfully",
  "data": {
    "channel": "C12345678",
    "timestamp": "1234567890.123456"
  }
}
```

### Send Threat Intelligence Alert

```http
POST /api/slack/alert
Content-Type: application/json

{
  "channelId": "C12345678",
  "alertData": {
    "ioc": "malicious.example.com",
    "iocType": "domain",
    "verdict": "malicious",
    "confidence": 85,
    "sources": {
      "VirusTotal": {
        "verdict": "malicious",
        "count": 10
      },
      "AbuseIPDB": {
        "verdict": "suspicious",
        "confidence": 75
      }
    },
    "timestamp": "2025-10-11T12:00:00Z",
    "analyst": "AI System"
  }
}
```

**Parameters:**

- `channelId` (required): The Slack channel ID
- `alertData` (required): Object containing:
  - `ioc`: The indicator of compromise
  - `iocType`: Type of IOC (ip, domain, hash, url)
  - `verdict`: malicious, suspicious, clean, benign
  - `confidence`: Confidence score (0-100)
  - `sources`: Object with threat intelligence sources
  - `timestamp`: ISO timestamp
  - `analyst`: Name of the analyst or system

**Response:**

```json
{
  "success": true,
  "message": "Threat alert sent successfully",
  "data": {
    "channel": "C12345678",
    "timestamp": "1234567890.123456"
  }
}
```

### Send Custom Block Message

```http
POST /api/slack/blocks
Content-Type: application/json

{
  "channelId": "C12345678",
  "text": "Fallback text",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "Custom Alert"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Important:* This is a custom message"
      }
    }
  ]
}
```

**Parameters:**

- `channelId` (required): The Slack channel ID
- `blocks` (required): Array of Slack Block Kit blocks
- `text` (optional): Fallback text for notifications

**Response:**

```json
{
  "success": true,
  "message": "Block message sent successfully",
  "data": {
    "channel": "C12345678",
    "timestamp": "1234567890.123456"
  }
}
```

## Slack Block Kit

For creating custom block messages, use the [Slack Block Kit Builder](https://app.slack.com/block-kit-builder/).

### Example Blocks

```json
[
  {
    "type": "header",
    "text": {
      "type": "plain_text",
      "text": "🎯 Security Alert",
      "emoji": true
    }
  },
  {
    "type": "section",
    "fields": [
      {
        "type": "mrkdwn",
        "text": "*Severity:*\nHigh"
      },
      {
        "type": "mrkdwn",
        "text": "*Status:*\nActive"
      }
    ]
  },
  {
    "type": "divider"
  },
  {
    "type": "section",
    "text": {
      "type": "mrkdwn",
      "text": "A new threat has been detected. Please investigate immediately."
    }
  }
]
```

## Error Handling

All endpoints return consistent error responses:

```json
{
  "success": false,
  "error": "Error message",
  "details": {}
}
```

Common HTTP status codes:

- `200` - Success
- `400` - Bad Request (validation error)
- `500` - Internal Server Error

## Finding Your Channel ID

1. Open Slack in a web browser
2. Navigate to the channel
3. Look at the URL: `https://app.slack.com/client/T12345678/C12345678`
4. The last part (`C12345678`) is your channel ID

Or use the `/api/slack/channels` endpoint to list all available channels.

## Integration Example

```javascript
// Send a simple message
const response = await fetch("http://localhost:3003/api/slack/send", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    channelId: "C12345678",
    text: "Test message from my app!",
  }),
});

const result = await response.json();
console.log(result);
```

## Security Notes

- Keep your `SLACK_BOT_TOKEN` secure and never commit it to version control
- Use environment variables for all sensitive configuration
- The `.env` file is already in `.gitignore`
- Only grant necessary Slack permissions to your bot

## Troubleshooting

### "not_in_channel" error

Your bot needs to be invited to the channel. Type `/invite @your-bot-name` in the Slack channel.

### "invalid_auth" error

Your `SLACK_BOT_TOKEN` is incorrect or expired. Generate a new one from the Slack App settings.

### "channel_not_found" error

The channel ID is incorrect. Use the `/api/slack/channels` endpoint to find the correct ID.

## License

ISC
