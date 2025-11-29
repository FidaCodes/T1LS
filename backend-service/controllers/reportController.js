import ThreatAnalysis from "../models/ThreatAnalysis.js";
import Report from "../models/Report.js";
import AuditLog from "../models/AuditLog.js";
import User from "../models/User.js";

// Generate and save a custom report
export const generateCustomReport = async (req, res) => {
  try {
    const { dateRange } = req.body; // "7days" or "30days"
    const userId = req.user.id;

    // Calculate date range
    const endDate = new Date();
    const startDate = new Date();

    if (dateRange === "7days") {
      startDate.setDate(startDate.getDate() - 7);
    } else if (dateRange === "30days") {
      startDate.setDate(startDate.getDate() - 30);
    } else {
      // Default to 30 days
      startDate.setDate(startDate.getDate() - 30);
    }

    // Fetch analyses within date range
    const analyses = await ThreatAnalysis.find({
      user: userId,
      createdAt: {
        $gte: startDate,
        $lte: endDate,
      },
    }).sort({ createdAt: -1 });

    // Calculate statistics
    const stats = {
      totalScans: analyses.length,
      malicious: analyses.filter((a) => a.verdict === "MALICIOUS").length,
      suspicious: analyses.filter((a) => a.verdict === "SUSPICIOUS").length,
      benign: analyses.filter((a) => a.verdict === "BENIGN").length,
      unknown: analyses.filter((a) => a.verdict === "UNKNOWN").length,
    };

    // Format data for CSV
    const reportData = analyses.map((analysis) => ({
      ioc: analysis.ioc,
      iocType: analysis.iocType,
      verdict: analysis.verdict,
      confidenceScore: analysis.confidenceScore,
      timestamp: analysis.createdAt.toISOString(),
      description: analysis.details?.description || "",
    }));

    // Create period string
    const period = dateRange === "7days" ? "Last 7 Days" : "Last 30 Days";
    const startDateStr = startDate.toISOString().split("T")[0];
    const endDateStr = endDate.toISOString().split("T")[0];

    // Save report to database
    const newReport = new Report({
      userId: userId,
      title: `Custom Report - ${period}`,
      type: "Custom Report",
      period: `${startDateStr} to ${endDateStr}`,
      dateRange: {
        start: startDate,
        end: endDate,
      },
      fileSize: `${Math.round(reportData.length * 0.5)} KB`,
      stats: stats,
      data: reportData,
    });

    await newReport.save();

    // Log report generation
    const user = await User.findById(userId);
    await AuditLog.create({
      userId: userId,
      userEmail: user.email,
      action: "Report Generated",
      details: `Generated custom report for ${period}`,
      status: "SUCCESS",
      ipAddress: req.ip || req.connection.remoteAddress,
    });

    res.json({
      success: true,
      data: {
        report: newReport,
        analyses: reportData,
        stats,
        dateRange: {
          start: startDate.toISOString(),
          end: endDate.toISOString(),
        },
      },
    });
  } catch (error) {
    console.error("Error generating report:", error);
    res.status(500).json({
      success: false,
      message: "Failed to generate report",
      error: error.message,
    });
  }
};

// Get all available reports for the user
export const getAvailableReports = async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch all saved reports for this user, sorted by newest first
    const reports = await Report.find({ userId })
      .sort({ createdAt: -1 })
      .lean();

    // Format reports for frontend
    const formattedReports = reports.map((report) => ({
      _id: report._id,
      title: report.title,
      type: report.type,
      period: report.period,
      date: report.createdAt.toISOString().split("T")[0],
      fileSize: report.fileSize,
      totalScans: report.stats.totalScans,
      malicious: report.stats.malicious,
      suspicious: report.stats.suspicious,
      benign: report.stats.benign,
      data: report.data,
      dateRange: report.dateRange,
    }));

    res.json({
      success: true,
      data: formattedReports,
    });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch reports",
      error: error.message,
    });
  }
};
