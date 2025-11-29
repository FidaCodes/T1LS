# Threat Intelligence Analyzer 🔍

An advanced threat intelligence analysis tool that collects IOC (Indicators of Compromise) data from multiple sources and uses AI to classify threats as **MALICIOUS**, **SUSPICIOUS**, or **BENIGN**.

## Features 🚀

- **Multi-Source Intelligence**: Integrates with VirusTotal, AbuseIPDB, and MISP
- **AI-Powered Classification**: Uses OpenAI GPT-4 for intelligent threat analysis
- **Multiple IOC Types**: Supports IPs, domains, and file hashes (MD5, SHA1, SHA256)
- **Flexible Output**: Report format or JSON for integration
- **Batch Processing**: Analyze multiple IOCs from a file
- **Interactive Mode**: Real-time threat analysis

## Setup Instructions 📋

### 1. Activate Virtual Environment

```bash
source threat_intel_env/bin/activate
```

### 2. Configure API Keys

Copy the `.env.example` file to `.env` and add your API keys:

```bash
cp .env.example .env
# Edit .env with your favorite editor
```

### 3. Get Free API Keys 🔑

#### VirusTotal (Recommended)

1. Go to https://www.virustotal.com/gui/join-us
2. Create an account
3. Get your API key from your profile
4. **Free tier**: 1,000 requests/day

#### AbuseIPDB (For IP reputation)

1. Go to https://www.abuseipdb.com/register
2. Create an account
3. Get your API key from the dashboard
4. **Free tier**: 1,000 requests/day

#### OpenAI (Required for classification)

1. Go to https://platform.openai.com/
2. Create an account and add billing
3. Get your API key
4. **Cost**: ~$0.01-0.03 per analysis

### 4. MISP Access (Optional) 🗄️

MISP is more complex to access:

#### Option A: Public MISP Communities

- Some universities and security communities provide access
- Usually requires approval and membership
- Search for "public MISP instances" or security communities

#### Option B: MISP Hosting Services

- Several companies provide hosted MISP instances
- Paid but professionally managed

#### Option C: Self-Hosted MISP

- Install your own MISP instance
- Free but requires technical setup
- Good for learning and testing

## Usage Examples 📝

### Single IOC Analysis

```bash
# Analyze an IP address
python main.py 8.8.8.8

# Analyze a domain
python main.py suspicious-domain.com

# Analyze a file hash
python main.py d41d8cd98f00b204e9800998ecf8427e
```

### Interactive Mode

```bash
python main.py --interactive
```

### Batch Processing

```bash
# Create a file with IOCs (one per line)
echo "8.8.8.8
malware-domain.com
d41d8cd98f00b204e9800998ecf8427e" > iocs.txt

# Process the file
python main.py --file iocs.txt
```

### JSON Output

```bash
python main.py 8.8.8.8 --format json
```

## Sample Output 📊

```
🔍 Analyzing IOC: 8.8.8.8
--------------------------------------------------
✅ Collected data from 2 source(s): virustotal, abuseipdb
🤖 Classifying threat using AI...

============================================================
                 THREAT INTELLIGENCE ANALYSIS REPORT
============================================================

IOC: 8.8.8.8
Type: IP
Analysis Date: 2025-01-09T...

----------------------------------------
CLASSIFICATION RESULTS
----------------------------------------
Classification: BENIGN
Confidence Score: 95/100

Reasoning: This IP address (8.8.8.8) is Google's public DNS server.
VirusTotal shows 0 malicious detections out of 85 engines, and
AbuseIPDB shows 0% abuse confidence with minimal reports. This is
a legitimate infrastructure service.

Key Indicators:
  • Zero malicious detections from antivirus engines
  • Well-known legitimate service (Google DNS)
  • Low abuse confidence score
  • Minimal security reports

Recommendations: This IP can be considered safe for normal use.

----------------------------------------
SOURCE DATA SUMMARY
----------------------------------------

VIRUSTOTAL:
  Malicious Detections: 0/85

ABUSEIPDB:
  Abuse Confidence: 0%
  Total Reports: 1
============================================================
```

## Understanding Classifications 🎯

- **MALICIOUS**: Clear evidence of malicious activity

  - High detection rates from security vendors
  - Confirmed malware samples
  - High abuse confidence scores

- **SUSPICIOUS**: Potential threat indicators

  - Some detections but not conclusive
  - Moderate abuse reports
  - Unusual behavior patterns

- **BENIGN**: No significant threat indicators
  - Clean reputation across sources
  - Known legitimate services
  - No or minimal security reports

## Troubleshooting 🔧

### No Data Collected

- Check your API keys in `.env`
- Verify internet connection
- Some APIs have rate limits

### OpenAI Classification Errors

- Verify your OpenAI API key
- Check your account has billing enabled
- Ensure you have API credits

### MISP Connection Issues

- Verify MISP URL and credentials
- Check if the MISP instance is accessible
- Some instances require IP whitelisting

## File Structure 📁

```
MISP-test/
├── main.py                    # Main application
├── threat_intel_collector.py  # Intelligence collection
├── threat_classifier.py       # AI classification
├── .env                       # Your API keys
├── .env.example              # Template
├── threat_intel_env/         # Virtual environment
└── README.md                 # This file
```

## API Costs 💰

- **VirusTotal**: Free (1K/day) or $500/month for unlimited
- **AbuseIPDB**: Free (1K/day) or paid plans available
- **OpenAI**: ~$0.01-0.03 per analysis (GPT-4)
- **MISP**: Free if self-hosted, varies for hosted solutions

## Contributing 🤝

Feel free to:

- Add more threat intelligence sources
- Improve the AI classification prompts
- Add support for more IOC types
- Create better reporting formats

## Security Notes 🔒

- Keep your API keys secure
- Don't commit `.env` to version control
- Be mindful of API rate limits
- Some IOCs might be sensitive - handle appropriately
