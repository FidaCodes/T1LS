import ThreatAnalysis from "../models/ThreatAnalysis.js";
import mongoose from "mongoose";

/**
 * Get analytics data for the dashboard
 */
export const getAnalytics = async (req, res) => {
  const userId = req.user.id;

  try {
    // Log userId for debugging
    console.log("Fetching analytics for user:", userId);

    // Get total analyses count
    const totalAnalyses = await ThreatAnalysis.countDocuments({ user: userId });
    console.log("Total analyses found:", totalAnalyses);

    // Get verdict distribution
    const verdictDistribution = await ThreatAnalysis.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: "$verdict",
          count: { $sum: 1 },
        },
      },
    ]);
    console.log("Verdict distribution:", verdictDistribution);

    // Get IOC type distribution
    const iocTypeDistribution = await ThreatAnalysis.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: "$iocType",
          count: { $sum: 1 },
        },
      },
    ]);
    console.log("IOC type distribution:", iocTypeDistribution);

    // Get analyses over time (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const analysesOverTime = await ThreatAnalysis.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          createdAt: { $gte: thirtyDaysAgo },
        },
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
          },
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    // Get average confidence by verdict
    const confidenceByVerdict = await ThreatAnalysis.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: "$verdict",
          avgConfidence: { $avg: "$confidenceScore" },
          count: { $sum: 1 },
        },
      },
    ]);

    // Get recent high-risk analyses (MALICIOUS or SUSPICIOUS with high confidence)
    const highRiskAnalyses = await ThreatAnalysis.find({
      user: userId,
      verdict: { $in: ["MALICIOUS", "SUSPICIOUS"] },
      confidenceScore: { $gte: 70 },
    })
      .sort({ createdAt: -1 })
      .limit(10)
      .select("ioc iocType verdict confidenceScore createdAt");

    // Get scheduled vs manual analysis count
    const analysisTypeCount = await ThreatAnalysis.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: "$isScheduled",
          count: { $sum: 1 },
        },
      },
    ]);

    // Get top sources with errors
    const sourcesWithErrors = await ThreatAnalysis.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(userId) } },
      { $project: { sources: { $objectToArray: "$sources" } } },
      { $unwind: "$sources" },
      { $match: { "sources.v.error": { $exists: true, $ne: null } } },
      {
        $group: {
          _id: "$sources.k",
          errorCount: { $sum: 1 },
        },
      },
      { $sort: { errorCount: -1 } },
      { $limit: 5 },
    ]);

    res.json({
      success: true,
      data: {
        totalAnalyses,
        verdictDistribution,
        iocTypeDistribution,
        analysesOverTime,
        confidenceByVerdict,
        highRiskAnalyses,
        analysisTypeCount,
        sourcesWithErrors,
      },
    });
  } catch (error) {
    console.error("Analytics error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch analytics data",
    });
  }
};
