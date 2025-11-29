import mongoose from "mongoose";

const assetActivitySchema = new mongoose.Schema(
  {
    assetId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Asset",
      required: true,
    },
    deviceId: {
      type: String,
      required: true,
    },
    activityType: {
      type: String,
      required: true,
      enum: [
        "login",
        "logout",
        "file-access",
        "network-connection",
        "process-execution",
        "registry-modification",
        "dns-query",
        "http-request",
        "email-sent",
        "data-transfer",
        "authentication-failure",
        "privilege-escalation",
        "suspicious-activity",
        "other",
      ],
    },
    description: {
      type: String,
      required: true,
    },
    sourceIp: String,
    destinationIp: String,
    destinationPort: Number,
    protocol: String,
    domain: String,
    url: String,
    fileHash: String,
    fileName: String,
    processName: String,
    username: String,
    severity: {
      type: String,
      enum: ["info", "low", "medium", "high", "critical"],
      default: "info",
    },
    correlatedThreats: [
      {
        ioc: String,
        iocType: String,
        threatLevel: String,
        confidence: Number,
        analysisId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "ThreatAnalysis",
        },
        correlatedAt: Date,
      },
    ],
    metadata: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
    },
    isInvestigated: {
      type: Boolean,
      default: false,
    },
    investigationNotes: String,
    investigatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    investigatedAt: Date,
  },
  {
    timestamps: true,
  }
);

// Indexes for efficient queries
assetActivitySchema.index({ assetId: 1, createdAt: -1 });
assetActivitySchema.index({ deviceId: 1, createdAt: -1 });
assetActivitySchema.index({ activityType: 1 });
assetActivitySchema.index({ severity: 1 });
assetActivitySchema.index({ "correlatedThreats.ioc": 1 });
assetActivitySchema.index({ createdAt: -1 });

export default mongoose.model("AssetActivity", assetActivitySchema);
