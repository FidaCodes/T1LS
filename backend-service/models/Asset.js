import mongoose from "mongoose";

const assetSchema = new mongoose.Schema(
  {
    deviceId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    deviceName: {
      type: String,
      required: true,
      trim: true,
    },
    deviceType: {
      type: String,
      required: true,
      enum: ["workstation", "server", "mobile", "iot", "network-device", "other"],
    },
    owner: {
      type: String,
      required: true,
      trim: true,
    },
    department: {
      type: String,
      trim: true,
    },
    ipAddress: {
      type: String,
      trim: true,
    },
    macAddress: {
      type: String,
      trim: true,
    },
    operatingSystem: {
      type: String,
      trim: true,
    },
    location: {
      type: String,
      trim: true,
    },
    riskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    status: {
      type: String,
      enum: ["active", "inactive", "compromised", "investigating"],
      default: "active",
    },
    lastSeen: {
      type: Date,
      default: Date.now,
    },
    threatIndicators: [
      {
        ioc: String,
        iocType: String,
        threatLevel: String,
        detectedAt: Date,
        analysisId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "ThreatAnalysis",
        },
      },
    ],
    tags: [String],
    notes: String,
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  {
    timestamps: true,
  }
);

// Index for faster queries
assetSchema.index({ deviceId: 1 });
assetSchema.index({ owner: 1 });
assetSchema.index({ ipAddress: 1 });
assetSchema.index({ status: 1 });
assetSchema.index({ riskScore: -1 });

export default mongoose.model("Asset", assetSchema);
