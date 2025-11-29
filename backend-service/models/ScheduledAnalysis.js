import mongoose from "mongoose";

const scheduledAnalysisSchema = new mongoose.Schema(
  {
    ioc: {
      type: String,
      required: true,
      trim: true,
    },
    scheduledFor: {
      type: Date,
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ["pending", "running", "completed", "failed", "cancelled"],
      default: "pending",
      index: true,
    },
    recurrence: {
      type: String,
      enum: ["once", "hourly", "daily", "weekly"],
      default: "once",
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    analysisResult: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "ThreatAnalysis",
    },
    executedAt: {
      type: Date,
    },
    error: {
      type: String,
    },
    notificationSent: {
      type: Boolean,
      default: false,
    },
    slackChannelId: {
      type: String,
    },
    notes: {
      type: String,
      maxlength: 500,
    },
  },
  {
    timestamps: true,
  }
);

// Index for efficient queries
scheduledAnalysisSchema.index({ status: 1, scheduledFor: 1 });
scheduledAnalysisSchema.index({ user: 1, status: 1 });

// Method to check if analysis should be executed
scheduledAnalysisSchema.methods.isReadyToExecute = function () {
  return this.status === "pending" && this.scheduledFor <= new Date();
};

// Method to mark as running
scheduledAnalysisSchema.methods.markAsRunning = async function () {
  this.status = "running";
  this.executedAt = new Date();
  return this.save();
};

// Method to mark as completed
scheduledAnalysisSchema.methods.markAsCompleted = async function (analysisId) {
  this.status = "completed";
  this.analysisResult = analysisId;
  return this.save();
};

// Method to mark as failed
scheduledAnalysisSchema.methods.markAsFailed = async function (errorMessage) {
  this.status = "failed";
  this.error = errorMessage;
  return this.save();
};

// Static method to get pending analyses that are ready to run
scheduledAnalysisSchema.statics.getReadyAnalyses = function () {
  return this.find({
    status: "pending",
    scheduledFor: { $lte: new Date() },
  }).populate("user", "email username");
};

// Static method to get user's scheduled analyses
scheduledAnalysisSchema.statics.getUserSchedules = function (
  userId,
  includeCompleted = false
) {
  const query = { user: userId };

  if (!includeCompleted) {
    query.status = { $ne: "completed" };
  }

  return this.find(query).populate("analysisResult").sort({ scheduledFor: -1 });
};

const ScheduledAnalysis = mongoose.model(
  "ScheduledAnalysis",
  scheduledAnalysisSchema
);

export default ScheduledAnalysis;
