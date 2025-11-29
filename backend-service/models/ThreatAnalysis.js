import mongoose from "mongoose";

const threatAnalysisSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    ioc: {
      type: String,
      required: true,
      trim: true,
    },
    iocType: {
      type: String,
      enum: ["ip", "domain", "url", "hash", "unknown"],
      default: "unknown",
    },
    verdict: {
      type: String,
      enum: [
        "BENIGN",
        "SUSPICIOUS",
        "MALICIOUS",
        "UNKNOWN",
        "SKIPPED",
        "ERROR",
      ],
      required: true,
    },
    confidenceScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    reasoning: {
      type: String,
      default: "",
    },
    sources: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    rawData: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    analystFeedback: {
      type: String,
      default: "",
      trim: true,
    },
    feedbackProvidedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    feedbackProvidedAt: {
      type: Date,
    },
    isScheduled: {
      type: Boolean,
      default: false,
    },
    scheduledAnalysisId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "ScheduledAnalysis",
    },
  },
  {
    timestamps: true,
  }
);

// Index for efficient querying
threatAnalysisSchema.index({ user: 1, createdAt: -1 });
threatAnalysisSchema.index({ ioc: 1, user: 1 });

const ThreatAnalysis = mongoose.model("ThreatAnalysis", threatAnalysisSchema);

export default ThreatAnalysis;
