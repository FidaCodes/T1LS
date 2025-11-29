import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
    },
    userEmail: {
      type: String,
      required: true,
    },
    action: {
      type: String,
      required: true,
      enum: [
        "User Login",
        "Login Failed",
        "User Created",
        "User Updated",
        "User Deleted",
        "Scan Performed",
        "Report Generated",
        "Report Downloaded",
      ],
    },
    details: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      enum: ["SUCCESS", "FAILED"],
      default: "SUCCESS",
    },
    ipAddress: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

// Index for faster queries
auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ userEmail: 1, createdAt: -1 });

const AuditLog = mongoose.model("AuditLog", auditLogSchema);

export default AuditLog;
