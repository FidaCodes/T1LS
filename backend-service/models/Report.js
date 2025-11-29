import mongoose from "mongoose";

const reportSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    title: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      required: true,
      enum: [
        "Custom Report",
        "Weekly Summary",
        "Monthly Report",
        "Quarterly Report",
        "Daily Summary",
      ],
    },
    period: {
      type: String,
      required: true,
    },
    dateRange: {
      start: {
        type: Date,
        required: true,
      },
      end: {
        type: Date,
        required: true,
      },
    },
    fileSize: {
      type: String,
      default: "0 KB",
    },
    stats: {
      totalScans: {
        type: Number,
        default: 0,
      },
      malicious: {
        type: Number,
        default: 0,
      },
      suspicious: {
        type: Number,
        default: 0,
      },
      benign: {
        type: Number,
        default: 0,
      },
      unknown: {
        type: Number,
        default: 0,
      },
    },
    data: {
      type: Array,
      default: [],
    },
  },
  {
    timestamps: true,
  }
);

const Report = mongoose.model("Report", reportSchema);

export default Report;
