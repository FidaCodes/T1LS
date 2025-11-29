# 🚀 Quick Start Guide - Notification Service

## Step 1: Get Your Slack Bot Token

1. Go to **https://api.slack.com/apps**
2. Click **"Create New App"** → **"From scratch"**
3. Name it: `Threat Intel Bot` (or any name you prefer)
4. Select your workspace
5. Click **"Create App"**

## Step 2: Add Bot Permissions

1. In your app settings, go to **"OAuth & Permissions"** (left sidebar)
2. Scroll down to **"Scopes"** → **"Bot Token Scopes"**
3. Click **"Add an OAuth Scope"** and add these:
   - ✅ `chat:write` - Send messages
   - ✅ `chat:write.public` - Send messages to public channels
   - ✅ `channels:read` - View public channels
   - ✅ `groups:read` - View private channels (optional)

## Step 3: Install App to Your Workspace

1. Scroll up to **"OAuth Tokens for Your Workspace"**
2. Click **"Install to Workspace"**
3. Click **"Allow"**
4. Copy the **"Bot User OAuth Token"** (starts with `xoxb-`)

## Step 4: Configure Environment

1. Open `.env` file in the notification-service folder
2. Paste your token:
   ```env
   PORT=3003
   SLACK_BOT_TOKEN=xoxb-your-actual-token-here
   ```

## Step 5: Start the Service

```bash
# Make sure you're in the notification-service directory
cd /Users/oumar/Desktop/Kuwait/notification-service

# Start the service
npm run dev
```

You should see:

```
🚀 Notification Service running on port 3003
📡 Health check: http://localhost:3003/health
💬 Slack API: http://localhost:3003/api/slack
```

## Step 6: Find Your Channel ID

### Option A: Using the API

1. With the service running, open your browser
2. Go to: http://localhost:3003/api/slack/channels
3. Find your channel in the list and copy its ID (e.g., `C12345678`)

### Option B: From Slack URL

1. Open Slack in a web browser
2. Click on the channel you want to use
3. Look at the URL: `https://app.slack.com/client/T12345678/C12345678`
4. The last part is your channel ID (e.g., `C12345678`)

## Step 7: Invite Bot to Channel

⚠️ **Important:** Your bot must be a member of the channel!

1. Go to your Slack channel
2. Type: `/invite @threat-intel-bot` (use your actual bot name)
3. Press Enter

## Step 8: Test the Service

### Quick Test in Browser

Visit: http://localhost:3003/api/slack/test

You should see bot information if everything is configured correctly.

### Send Your First Message

#### Using the Test Script:

```bash
# Update the CHANNEL_ID in examples/testApi.js first!
node examples/testApi.js
```

#### Using cURL:

```bash
curl -X POST http://localhost:3003/api/slack/send \
  -H "Content-Type: application/json" \
  -d '{
    "channelId": "C12345678",
    "text": "Hello from Threat Intel Bot! 🎉"
  }'
```

#### Using Postman:

1. Import `postman_collection.json`
2. Update the `channelId` in each request
3. Send the "Send Simple Message" request

## 🎯 Available API Endpoints

| Method | Endpoint              | Description               |
| ------ | --------------------- | ------------------------- |
| GET    | `/health`             | Check service status      |
| GET    | `/api/slack/test`     | Test Slack connection     |
| GET    | `/api/slack/channels` | List available channels   |
| POST   | `/api/slack/send`     | Send simple message       |
| POST   | `/api/slack/alert`    | Send threat alert         |
| POST   | `/api/slack/blocks`   | Send custom block message |

## 📝 Example API Calls

### Send a Simple Message

```javascript
fetch("http://localhost:3003/api/slack/send", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    channelId: "C12345678",
    text: "Test message!",
  }),
});
```

### Send a Threat Alert

```javascript
fetch("http://localhost:3003/api/slack/alert", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    channelId: "C12345678",
    alertData: {
      ioc: "malicious.com",
      iocType: "domain",
      verdict: "malicious",
      confidence: 95,
      sources: {
        VirusTotal: { verdict: "malicious", count: 45 },
        AbuseIPDB: { verdict: "suspicious" },
      },
      timestamp: new Date().toISOString(),
      analyst: "AI System",
    },
  }),
});
```

### Send Custom Blocks

```javascript
fetch("http://localhost:3003/api/slack/blocks", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    channelId: "C12345678",
    text: "Alert",
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: "🚨 Security Alert" },
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: "*Status:* Active" },
      },
    ],
  }),
});
```

## 🔧 Troubleshooting

### Error: "not_in_channel"

**Solution:** Invite your bot to the channel:

```
/invite @your-bot-name
```

### Error: "invalid_auth"

**Solution:** Your token is incorrect or expired. Get a new one from Slack App settings.

### Error: "channel_not_found"

**Solution:** Check your channel ID using the `/api/slack/channels` endpoint.

### Bot not responding?

**Solution:**

1. Check if the service is running (`npm run dev`)
2. Verify your `SLACK_BOT_TOKEN` in `.env`
3. Make sure bot has required permissions
4. Check service logs for errors

## 🎨 Creating Custom Messages

Use the [Slack Block Kit Builder](https://app.slack.com/block-kit-builder/) to design your messages visually, then copy the JSON to use in your API calls.

## 📚 Next Steps

1. ✅ Service is running
2. ✅ Bot can send messages
3. 🔄 Integrate with ai-threatintel service (future)
4. 🔄 Add more notification templates
5. 🔄 Add webhook support for external systems

## 💡 Tips

- Keep your `SLACK_BOT_TOKEN` secret - never commit it to git
- Use the `/api/slack/test` endpoint to verify configuration
- Start with simple text messages, then move to block messages
- Check the examples folder for more use cases

## 📞 Need Help?

- Check the full README.md for detailed documentation
- Review examples in the `examples/` folder
- Visit Slack API docs: https://api.slack.com/
- Test with Postman collection: `postman_collection.json`

---

**Service Ready!** 🎉 Your notification service is now set up and ready to send Slack messages!
