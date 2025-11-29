# 📋 Notification Service - Complete Setup Summary

## ✅ What Was Created

### 1. **Core Files**

- ✅ `server.js` - Express server with CORS, error handling, and routes
- ✅ `package.json` - Dependencies and scripts configured
- ✅ `.env` - Environment variables (add your SLACK_BOT_TOKEN)
- ✅ `.env.example` - Template for environment variables
- ✅ `.gitignore` - Configured to ignore sensitive files

### 2. **Controllers** (`controllers/`)

- ✅ `slackController.js` - 5 main functions:
  - `sendMessage()` - Send simple text or block messages
  - `sendThreatAlert()` - Send formatted threat intelligence alerts
  - `sendBlockMessage()` - Send custom Slack Block Kit messages
  - `testConnection()` - Test Slack API connection
  - `listChannels()` - Get all available channels

### 3. **Routes** (`routes/`)

- ✅ `slackRoutes.js` - RESTful API endpoints:
  - `GET /api/slack/test` - Test connection
  - `GET /api/slack/channels` - List channels
  - `POST /api/slack/send` - Send message
  - `POST /api/slack/alert` - Send threat alert
  - `POST /api/slack/blocks` - Send block message

### 4. **Utilities** (`utils/`)

- ✅ `blockBuilder.js` - Helper functions for Slack blocks:
  - `createHeader()` - Header blocks
  - `createSection()` - Text sections
  - `createFieldsSection()` - Multi-column fields
  - `createDivider()` - Horizontal dividers
  - `createContext()` - Footer-like context
  - `createActions()` - Button actions
  - `createThreatAlertBlocks()` - Auto-generate threat alert blocks
  - `getVerdictColor()` - Color coding by severity
  - `getVerdictEmoji()` - Emoji by verdict type
  - `formatTimestamp()` - Human-readable dates

### 5. **Middleware** (`middleware/`)

- ✅ `validation.js` - Request validation:
  - `validateSlackMessage()` - Validate message requests
  - `validateThreatAlert()` - Validate alert data
  - `validateBlockMessage()` - Validate block structure
  - `logRequest()` - Request logging with sanitization

### 6. **Examples** (`examples/`)

- ✅ `testApi.js` - Complete test suite:
  - Test connection
  - List channels
  - Send simple messages
  - Send threat alerts
  - Send custom blocks
  - Send multiple IOCs alert

### 7. **Documentation**

- ✅ `README.md` - Complete API documentation
- ✅ `QUICKSTART.md` - Step-by-step setup guide
- ✅ `postman_collection.json` - Postman API collection

### 8. **NPM Packages Installed**

```json
{
  "@slack/web-api": "^7.0.0", // Official Slack SDK
  "express": "^4.18.2", // Web framework
  "dotenv": "^16.3.1", // Environment variables
  "cors": "^2.8.5", // CORS middleware
  "morgan": "^1.10.0", // HTTP logging
  "nodemon": "^3.0.1" // Dev auto-reload
}
```

## 📁 Project Structure

```
notification-service/
├── server.js                    # Main server file
├── package.json                 # Dependencies & scripts
├── .env                         # Environment variables (add your token!)
├── .env.example                 # Environment template
├── .gitignore                   # Git ignore rules
├── README.md                    # Full documentation
├── QUICKSTART.md                # Quick setup guide
├── postman_collection.json      # Postman API tests
│
├── controllers/
│   └── slackController.js       # 5 Slack functions
│
├── routes/
│   └── slackRoutes.js          # API endpoints
│
├── middleware/
│   └── validation.js           # Request validation
│
├── utils/
│   └── blockBuilder.js         # Block helper functions
│
└── examples/
    └── testApi.js              # Test script
```

## 🎯 Key Features Implemented

### 1. **Send Simple Messages**

```javascript
POST /api/slack/send
{
  "channelId": "C12345678",
  "text": "Hello World!"
}
```

### 2. **Send Threat Alerts**

```javascript
POST /api/slack/alert
{
  "channelId": "C12345678",
  "alertData": {
    "ioc": "malicious.com",
    "iocType": "domain",
    "verdict": "malicious",
    "confidence": 95,
    "sources": {
      "VirusTotal": { "verdict": "malicious", "count": 45 }
    }
  }
}
```

### 3. **Send Custom Blocks**

```javascript
POST /api/slack/blocks
{
  "channelId": "C12345678",
  "blocks": [
    { "type": "header", "text": { "type": "plain_text", "text": "Alert" } },
    { "type": "section", "text": { "type": "mrkdwn", "text": "*Important*" } }
  ]
}
```

### 4. **Test Connection**

```javascript
GET / api / slack / test;
// Returns bot info if configured correctly
```

### 5. **List Channels**

```javascript
GET / api / slack / channels;
// Returns all channels your bot can see
```

## 🚀 How to Use

### 1. **Start the Service**

```bash
cd /Users/oumar/Desktop/Kuwait/notification-service
npm run dev
```

### 2. **Configure .env**

Add your Slack Bot Token to `.env`:

```env
PORT=3003
SLACK_BOT_TOKEN=xoxb-your-actual-token-here
```

### 3. **Test the Service**

```bash
# Option 1: Run test script
node examples/testApi.js

# Option 2: Use cURL
curl http://localhost:3003/api/slack/test

# Option 3: Import Postman collection
# Open postman_collection.json in Postman
```

## 🔗 Integration Ready

The service is designed to be easily integrated with your `ai-threatintel` service:

### From Python (ai-threatintel):

```python
import requests

def send_slack_alert(ioc_data):
    response = requests.post(
        'http://localhost:3003/api/slack/alert',
        json={
            'channelId': 'C12345678',
            'alertData': {
                'ioc': ioc_data['ioc'],
                'iocType': ioc_data['type'],
                'verdict': ioc_data['verdict'],
                'confidence': ioc_data['confidence'],
                'sources': ioc_data['sources'],
                'timestamp': datetime.now().isoformat(),
                'analyst': 'AI Threat Intelligence'
            }
        }
    )
    return response.json()
```

### From JavaScript (backend-service):

```javascript
async function sendThreatAlert(alertData) {
  const response = await fetch("http://localhost:3003/api/slack/alert", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      channelId: process.env.SLACK_CHANNEL_ID,
      alertData: alertData,
    }),
  });
  return response.json();
}
```

## 📊 API Response Format

All endpoints return consistent JSON:

**Success:**

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

**Error:**

```json
{
  "success": false,
  "error": "Error message",
  "details": {}
}
```

## 🔒 Security Features

- ✅ Environment variables for sensitive data
- ✅ CORS enabled for cross-origin requests
- ✅ Request validation middleware
- ✅ Error handling middleware
- ✅ Sanitized logging (hides sensitive data)
- ✅ .gitignore configured for .env

## 🎨 Customization Options

The service is fully customizable:

1. **Add new endpoints** in `routes/slackRoutes.js`
2. **Create new functions** in `controllers/slackController.js`
3. **Build custom blocks** using `utils/blockBuilder.js`
4. **Add validation** in `middleware/validation.js`

## 📝 Next Steps

1. ✅ Get Slack Bot Token from https://api.slack.com/apps
2. ✅ Add token to `.env` file
3. ✅ Start the service: `npm run dev`
4. ✅ Test connection: `GET /api/slack/test`
5. ✅ Find your channel ID: `GET /api/slack/channels`
6. ✅ Invite bot to channel: `/invite @your-bot`
7. ✅ Send test message
8. 🔄 Integrate with ai-threatintel (future)

## 🆘 Troubleshooting

| Issue               | Solution                                          |
| ------------------- | ------------------------------------------------- |
| "not_in_channel"    | Invite bot: `/invite @bot-name`                   |
| "invalid_auth"      | Check your SLACK_BOT_TOKEN                        |
| "channel_not_found" | Use correct channel ID from `/api/slack/channels` |
| Service won't start | Check PORT is available (default: 3003)           |
| No response         | Check service is running: `npm run dev`           |

## 📚 Resources

- **Slack API Docs:** https://api.slack.com/
- **Block Kit Builder:** https://app.slack.com/block-kit-builder/
- **Slack Web API:** https://api.slack.com/methods
- **Express Docs:** https://expressjs.com/

## ✨ What Makes This Service Great

1. **Clean Architecture** - Follows MVC pattern like backend-service
2. **Comprehensive** - Handles simple messages, alerts, and custom blocks
3. **Well Documented** - README, QUICKSTART, and inline comments
4. **Production Ready** - Error handling, validation, logging
5. **Easy to Test** - Examples, Postman collection, test endpoints
6. **Flexible** - Easy to extend and customize
7. **Secure** - Environment variables, sanitized logs

## 🎉 You're All Set!

Your notification service is complete and ready to send Slack messages. Just add your `SLACK_BOT_TOKEN` to the `.env` file and start the service!

**Happy coding! 🚀**
