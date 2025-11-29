import mongoose from "mongoose";
import dotenv from "dotenv";
import Asset from "./models/Asset.js";
import AssetActivity from "./models/AssetActivity.js";
import ThreatAnalysis from "./models/ThreatAnalysis.js";
import User from "./models/User.js";

dotenv.config();

const sampleAssets = [
  {
    deviceId: "WS-001",
    deviceName: "DESKTOP-OUMAR-01",
    deviceType: "workstation",
    owner: "Oumar Dimnang",
    department: "IT Security",
    ipAddress: "192.168.1.100",
    macAddress: "00:1B:44:11:3A:B7",
    operatingSystem: "Windows 11 Pro",
    location: "Kuwait City HQ - Floor 3",
    status: "active",
    tags: ["security-team", "admin-access"],
  },
  {
    deviceId: "SRV-DB-01",
    deviceName: "Production-Database-Server",
    deviceType: "server",
    owner: "Mohammad Fakhir",
    department: "Database Administration",
    ipAddress: "10.0.1.50",
    macAddress: "00:50:56:A1:2B:3C",
    operatingSystem: "Ubuntu Server 22.04",
    location: "Data Center - Rack A12",
    status: "active",
    tags: ["critical", "production", "database"],
  },
  {
    deviceId: "WS-042",
    deviceName: "Adeel-MacBook-Pro",
    deviceType: "workstation",
    owner: "Adeel Ahsan",
    department: "Finance",
    ipAddress: "192.168.2.42",
    macAddress: "A4:5E:60:E8:9F:12",
    operatingSystem: "macOS Sonoma",
    location: "Kuwait City HQ - Floor 2",
    status: "compromised",
    riskScore: 85,
    tags: ["finance", "sensitive-data", "infected"],
  },
  {
    deviceId: "MOB-015",
    deviceName: "Manal-iPhone-15",
    deviceType: "mobile",
    owner: "Manal Murad",
    department: "Executive",
    ipAddress: "192.168.10.15",
    macAddress: "8C:85:90:12:AB:CD",
    operatingSystem: "iOS 17",
    location: "Mobile",
    status: "active",
    tags: ["executive", "vip", "mobile"],
  },
  {
    deviceId: "SRV-WEB-01",
    deviceName: "Public-Web-Server",
    deviceType: "server",
    owner: "Nahla Nabil",
    department: "DevOps",
    ipAddress: "203.0.113.45",
    macAddress: "00:0C:29:3A:4B:5C",
    operatingSystem: "CentOS 8",
    location: "Cloud - AWS us-east-1",
    status: "investigating",
    riskScore: 72,
    tags: ["public-facing", "web", "dmz"],
  },
  {
    deviceId: "IOT-SENSOR-08",
    deviceName: "Building-Temp-Sensor",
    deviceType: "iot",
    owner: "Oumar Dimnang",
    department: "Operations",
    ipAddress: "192.168.50.8",
    macAddress: "B8:27:EB:12:34:56",
    operatingSystem: "Embedded Linux",
    location: "Kuwait City HQ - HVAC Room",
    status: "active",
    tags: ["iot", "monitoring"],
  },
  {
    deviceId: "WS-028",
    deviceName: "DESKTOP-MANAL-W11",
    deviceType: "workstation",
    owner: "Manal Murad",
    department: "Marketing",
    ipAddress: "192.168.3.28",
    macAddress: "D4:6D:6D:12:5A:8B",
    operatingSystem: "Windows 10 Pro",
    location: "Kuwait City HQ - Floor 1",
    status: "active",
    tags: ["marketing", "standard-user"],
  },
  {
    deviceId: "SRV-MAIL-01",
    deviceName: "Exchange-Mail-Server",
    deviceType: "server",
    owner: "Mohammad Fakhir",
    department: "IT Infrastructure",
    ipAddress: "10.0.1.25",
    macAddress: "00:50:56:B2:3C:4D",
    operatingSystem: "Windows Server 2022",
    location: "Data Center - Rack B05",
    status: "active",
    tags: ["critical", "email", "exchange"],
  },
  {
    deviceId: "WS-067",
    deviceName: "LAPTOP-NAHLA-PRO",
    deviceType: "workstation",
    owner: "Nahla Nabil",
    department: "Legal",
    ipAddress: "192.168.4.67",
    macAddress: "AC:DE:48:00:11:22",
    operatingSystem: "Windows 11 Pro",
    location: "Kuwait City HQ - Floor 4",
    status: "investigating",
    riskScore: 58,
    tags: ["legal", "confidential"],
  },
  {
    deviceId: "NET-RTR-01",
    deviceName: "Core-Router-Main",
    deviceType: "network-device",
    owner: "Oumar Dimnang",
    department: "IT Infrastructure",
    ipAddress: "10.0.0.1",
    macAddress: "00:1E:BD:12:34:56",
    operatingSystem: "Cisco IOS",
    location: "Data Center - Main Rack",
    status: "active",
    tags: ["critical", "network", "infrastructure"],
  },
  {
    deviceId: "WS-089",
    deviceName: "DESKTOP-ADEEL-HR",
    deviceType: "workstation",
    owner: "Adeel Ahsan",
    department: "HR",
    ipAddress: "192.168.5.89",
    macAddress: "98:E7:F4:3B:2A:1C",
    operatingSystem: "Windows 11 Pro",
    location: "Kuwait City HQ - Floor 2",
    status: "active",
    tags: ["hr", "sensitive-data"],
  },
  {
    deviceId: "SRV-FILE-01",
    deviceName: "Central-File-Server",
    deviceType: "server",
    owner: "Mohammad Fakhir",
    department: "IT Infrastructure",
    ipAddress: "10.0.1.100",
    macAddress: "00:0C:29:5F:6E:7D",
    operatingSystem: "Windows Server 2019",
    location: "Data Center - Rack C08",
    status: "active",
    tags: ["critical", "file-server", "smb"],
  },
  {
    deviceId: "MOB-023",
    deviceName: "Manal-Galaxy-S24",
    deviceType: "mobile",
    owner: "Manal Murad",
    department: "Sales",
    ipAddress: "192.168.10.23",
    macAddress: "4C:77:CB:AA:BB:CC",
    operatingSystem: "Android 14",
    location: "Mobile",
    status: "active",
    tags: ["sales", "mobile", "byod"],
  },
  {
    deviceId: "WS-103",
    deviceName: "UNKNOWN-WORKSTATION-103",
    deviceType: "workstation",
    owner: "Unknown User",
    department: "Unknown",
    ipAddress: "192.168.99.103",
    macAddress: "00:00:00:00:00:00",
    operatingSystem: "Unknown",
    location: "Unknown",
    status: "compromised",
    riskScore: 95,
    tags: ["unauthorized", "malware", "ransomware"],
  },
  {
    deviceId: "IOT-CAM-12",
    deviceName: "Security-Camera-Entrance",
    deviceType: "iot",
    owner: "Nahla Nabil",
    department: "Operations",
    ipAddress: "192.168.50.12",
    macAddress: "44:A9:2C:12:34:56",
    operatingSystem: "Embedded",
    location: "Building Entrance",
    status: "active",
    tags: ["iot", "security-camera", "surveillance"],
  },
];

const sampleActivities = [
  // Normal Activities
  {
    deviceId: "WS-001",
    activityType: "login",
    description: "User Oumar logged in successfully",
    sourceIp: "192.168.1.100",
    username: "oumar.dimnang",
    severity: "info",
  },
  {
    deviceId: "SRV-DB-01",
    activityType: "file-access",
    description: "Database file accessed",
    fileName: "production_db_backup.sql",
    username: "mohammad.fakhir",
    severity: "info",
  },
  {
    deviceId: "WS-001",
    activityType: "process-execution",
    description: "Powershell script executed",
    processName: "powershell.exe",
    username: "oumar.dimnang",
    severity: "low",
  },
  {
    deviceId: "MOB-015",
    activityType: "data-transfer",
    description: "Email synchronization",
    sourceIp: "192.168.10.15",
    destinationIp: "172.217.14.206",
    severity: "info",
  },
  {
    deviceId: "WS-028",
    activityType: "login",
    description: "User Manal logged in",
    sourceIp: "192.168.3.28",
    username: "manal.muraf",
    severity: "info",
  },
  {
    deviceId: "WS-089",
    activityType: "file-access",
    description: "Accessed employee records",
    fileName: "HR_Records_2024.xlsx",
    username: "adeel.ahsan",
    severity: "info",
  },

  // Malicious Activities - C2 Communication
  {
    deviceId: "WS-042",
    activityType: "network-connection",
    description: "Outbound connection to known C2 server",
    sourceIp: "192.168.2.42",
    destinationIp: "185.220.101.45", // Known Tor exit node
    destinationPort: 443,
    protocol: "HTTPS",
    severity: "critical",
  },
  {
    deviceId: "WS-042",
    activityType: "network-connection",
    description: "Connection to suspicious Russian IP",
    sourceIp: "192.168.2.42",
    destinationIp: "89.108.83.196", // Example malicious IP
    destinationPort: 8080,
    protocol: "HTTP",
    severity: "high",
  },
  {
    deviceId: "WS-103",
    activityType: "network-connection",
    description: "Beaconing detected - regular connections to external host",
    sourceIp: "192.168.99.103",
    destinationIp: "45.142.120.10",
    destinationPort: 443,
    protocol: "HTTPS",
    severity: "critical",
  },

  // Malicious Activities - DNS Queries
  {
    deviceId: "WS-042",
    activityType: "dns-query",
    description: "DNS query for known phishing domain",
    domain: "secure-login-verify-account.xyz",
    severity: "high",
  },
  {
    deviceId: "WS-103",
    activityType: "dns-query",
    description: "DNS query for malware distribution domain",
    domain: "download-free-software-now.tk",
    severity: "critical",
  },
  {
    deviceId: "WS-067",
    activityType: "dns-query",
    description: "Suspicious DGA domain query",
    domain: "xj4k2m9qp1r7s.info",
    severity: "high",
  },
  {
    deviceId: "WS-042",
    activityType: "dns-query",
    description: "DNS query for known iCloud phishing domain",
    domain: "br-icloud.com.br",
    severity: "critical",
  },
  {
    deviceId: "WS-028",
    activityType: "dns-query",
    description: "Multiple DNS queries to iCloud phishing domain",
    domain: "br-icloud.com.br",
    severity: "high",
  },
  {
    deviceId: "MOB-015",
    activityType: "dns-query",
    description: "Mobile device queried suspicious iCloud phishing domain",
    domain: "br-icloud.com.br",
    severity: "high",
  },

  // Malicious Activities - Web Requests
  {
    deviceId: "SRV-WEB-01",
    activityType: "http-request",
    description: "SQL injection attempt detected",
    sourceIp: "198.51.100.23",
    url: "https://example.com/api/users?id=1' OR '1'='1",
    severity: "high",
  },
  {
    deviceId: "SRV-WEB-01",
    activityType: "http-request",
    description: "Path traversal attack attempt",
    sourceIp: "203.0.113.50",
    url: "https://example.com/../../etc/passwd",
    severity: "high",
  },
  {
    deviceId: "WS-042",
    activityType: "http-request",
    description: "Access to known malicious URL",
    url: "http://malware-download-site.ru/payload.exe",
    severity: "critical",
  },
  {
    deviceId: "WS-042",
    activityType: "http-request",
    description:
      "User accessed iCloud phishing page - credentials potentially compromised",
    url: "https://br-icloud.com.br/login",
    domain: "br-icloud.com.br",
    sourceIp: "192.168.2.42",
    severity: "critical",
  },
  {
    deviceId: "WS-028",
    activityType: "http-request",
    description: "HTTP request to iCloud phishing domain",
    url: "https://br-icloud.com.br/verify-account",
    domain: "br-icloud.com.br",
    sourceIp: "192.168.3.28",
    severity: "critical",
  },
  {
    deviceId: "MOB-015",
    activityType: "http-request",
    description: "Mobile device accessed iCloud phishing page",
    url: "https://br-icloud.com.br/",
    domain: "br-icloud.com.br",
    sourceIp: "192.168.10.15",
    severity: "high",
  },

  // Malicious Activities - File Operations
  {
    deviceId: "WS-103",
    activityType: "file-access",
    description: "Suspicious file hash detected",
    fileName: "invoice_2024.pdf.exe",
    fileHash: "44d88612fea8a8f36de82e1278abb02f",
    username: "unknown",
    severity: "critical",
  },
  {
    deviceId: "WS-042",
    activityType: "file-access",
    description: "Known malware hash detected",
    fileName: "system32.dll",
    fileHash: "e99a18c428cb38d5f260853678922e03",
    username: "adeel.ahsan",
    severity: "critical",
  },
  {
    deviceId: "WS-103",
    activityType: "process-execution",
    description: "Ransomware process detected",
    processName: "wannacry.exe",
    username: "unknown",
    severity: "critical",
  },

  // Malicious Activities - Authentication
  {
    deviceId: "SRV-WEB-01",
    activityType: "authentication-failure",
    description: "Multiple failed SSH login attempts - brute force attack",
    sourceIp: "45.142.120.10",
    username: "root",
    severity: "critical",
  },
  {
    deviceId: "SRV-MAIL-01",
    activityType: "authentication-failure",
    description: "Failed login attempts from anomalous location",
    sourceIp: "103.85.24.15",
    username: "admin",
    severity: "high",
  },
  {
    deviceId: "SRV-DB-01",
    activityType: "privilege-escalation",
    description: "Unauthorized privilege escalation attempt",
    username: "guest",
    severity: "critical",
  },

  // Malicious Activities - Data Exfiltration
  {
    deviceId: "WS-042",
    activityType: "data-transfer",
    description: "Large data transfer to external IP - possible exfiltration",
    sourceIp: "192.168.2.42",
    destinationIp: "89.108.83.196",
    severity: "critical",
  },
  {
    deviceId: "WS-103",
    activityType: "data-transfer",
    description: "Encrypted file upload to cloud storage",
    sourceIp: "192.168.99.103",
    destinationIp: "185.220.101.45",
    severity: "high",
  },

  // Suspicious Activities
  {
    deviceId: "WS-067",
    activityType: "registry-modification",
    description: "Registry key modified - persistence mechanism",
    severity: "medium",
  },
  {
    deviceId: "SRV-WEB-01",
    activityType: "suspicious-activity",
    description: "Port scanning activity detected",
    sourceIp: "45.142.120.10",
    severity: "high",
  },
  {
    deviceId: "IOT-CAM-12",
    activityType: "network-connection",
    description: "IoT device connecting to unusual external IP",
    sourceIp: "192.168.50.12",
    destinationIp: "185.220.101.45",
    destinationPort: 23,
    protocol: "Telnet",
    severity: "medium",
  },

  // Normal Operations
  {
    deviceId: "SRV-FILE-01",
    activityType: "file-access",
    description: "Weekly backup completed",
    fileName: "backup_2024_11_12.tar.gz",
    severity: "info",
  },
  {
    deviceId: "NET-RTR-01",
    activityType: "other",
    description: "Router configuration updated",
    username: "network.admin",
    severity: "info",
  },
  {
    deviceId: "MOB-023",
    activityType: "login",
    description: "Mobile device authenticated",
    sourceIp: "192.168.10.23",
    username: "manal.muraf",
    severity: "info",
  },
];

async function seedDatabase() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("✅ Connected to MongoDB");

    // Clear existing data (preserve real threat analyses)
    await Asset.deleteMany({});
    await AssetActivity.deleteMany({});
    // Only delete seed-created threat analyses, not real ones
    await ThreatAnalysis.deleteMany({ ioc: "br-icloud.com.br" });
    await User.deleteMany({ email: /@seed-localhost/ });
    console.log("🗑️  Cleared existing data (assets, activities, seed threats)");

    // Ensure a seed user exists for threat analysis ownership
    const seedUser = await User.findOneAndUpdate(
      { email: "seed@seed-localhost" },
      {
        username: "seed-user",
        email: "seed@seed-localhost",
        password: "password123",
      },
      { upsert: true, new: true }
    );

    // Insert sample assets
    const createdAssets = await Asset.insertMany(sampleAssets);
    console.log(`✅ Created ${createdAssets.length} sample assets`);

    // Map deviceIds to asset ObjectIds
    const assetMap = {};
    createdAssets.forEach((asset) => {
      assetMap[asset.deviceId] = asset._id;
    });

    // Insert a sample threat analysis for the known malicious domain
    const sampleThreats = [
      {
        user: seedUser._id,
        ioc: "br-icloud.com.br",
        iocType: "domain",
        verdict: "MALICIOUS",
        confidenceScore: 95,
        reasoning:
          "Branded iCloud phishing domain used in credential harvesting campaigns. Confirmed by multiple sources.",
        sources: [
          { name: "VirusTotal", verdict: "malicious" },
          { name: "Internal honeypot", verdict: "malicious" },
        ],
        rawData: { observedUrls: ["https://br-icloud.com.br/login"] },
      },
    ];

    const createdThreats = await ThreatAnalysis.insertMany(sampleThreats);
    console.log(`✅ Created ${createdThreats.length} sample threat analyses`);

    // Insert sample activities with correct assetId references
    const activitiesWithAssetIds = sampleActivities.map((activity) => ({
      ...activity,
      assetId: assetMap[activity.deviceId],
    }));

    const createdActivities = await AssetActivity.insertMany(
      activitiesWithAssetIds
    );
    console.log(`✅ Created ${createdActivities.length} sample activities`);

    // Simple correlation: link activities that reference the seeded malicious domain
    try {
      const maliciousThreat = createdThreats[0];
      const affectedActivities = await AssetActivity.find({
        domain: "br-icloud.com.br",
      });

      for (const act of affectedActivities) {
        const correlation = {
          ioc: maliciousThreat.ioc,
          iocType: maliciousThreat.iocType,
          threatLevel: (maliciousThreat.verdict || "MALICIOUS")
            .toString()
            .toLowerCase(),
          confidence: maliciousThreat.confidenceScore || 80,
          analysisId: maliciousThreat._id,
          correlatedAt: new Date(),
        };

        act.correlatedThreats = act.correlatedThreats || [];
        act.correlatedThreats.push(correlation);
        act.severity =
          act.severity || (correlation.confidence > 80 ? "critical" : "high");
        await act.save();

        // Update corresponding asset
        const asset = await Asset.findById(act.assetId);
        if (asset) {
          asset.riskScore = Math.min(
            100,
            (asset.riskScore || 0) + (correlation.confidence * 0.5) / 10
          );
          asset.threatIndicators = asset.threatIndicators || [];
          if (!asset.threatIndicators.some((t) => t.ioc === correlation.ioc)) {
            asset.threatIndicators.push({
              ioc: correlation.ioc,
              iocType: correlation.iocType,
              threatLevel: correlation.threatLevel,
              detectedAt: new Date(),
              analysisId: correlation.analysisId,
            });
          }
          if (asset.riskScore > 90) asset.status = "compromised";
          else if (asset.riskScore > 70 && asset.status === "active")
            asset.status = "investigating";
          await asset.save();
        }
      }
      console.log(
        `🔗 Correlated ${affectedActivities.length} activities to ${maliciousThreat.ioc}`
      );
    } catch (err) {
      console.error("Error during inline correlation:", err);
    }

    console.log("\n🎉 Database seeded successfully!");
    console.log("\n📊 Summary:");
    console.log(`   - Assets: ${createdAssets.length}`);
    console.log(`   - Activities: ${createdActivities.length}`);
    console.log("\n💡 You can now:");
    console.log("   1. View assets at /asset-intel");
    console.log(
      "   2. Run threat correlation to link activities with IOC analyses"
    );
    console.log(
      "   3. Analyze IOCs at /dashboard and see automatic asset correlation\n"
    );

    process.exit(0);
  } catch (error) {
    console.error("❌ Error seeding database:", error);
    process.exit(1);
  }
}

seedDatabase();
