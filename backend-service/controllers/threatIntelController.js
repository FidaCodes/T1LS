import axios from "axios";
import ThreatAnalysis from "../models/ThreatAnalysis.js";
import AuditLog from "../models/AuditLog.js";
import User from "../models/User.js";

const AI_THREATINTEL_BASE_URL =
  process.env.AI_THREATINTEL_URL || "http://localhost:8000";

/**
 * Analyze IOC using the AI Threat Intelligence service
 */
const analyzeIOC = async (req, res) => {
  const { ioc } = req.body;
  const userId = req.user.id; // From auth middleware

  if (!ioc || !ioc.trim()) {
    return res.status(400).json({
      success: false,
      message: "IOC is required",
    });
  }

  try {
    // Check for ALL existing feedback for this IOC from this user
    const allFeedback = await ThreatAnalysis.find({
      user: userId,
      ioc: ioc.trim(),
      analystFeedback: { $exists: true, $ne: "" },
    })
      .sort({ feedbackProvidedAt: -1 })
      .select("analystFeedback feedbackProvidedAt createdAt")
      .limit(5); // Limit to last 5 feedback entries to avoid overwhelming the AI

    // Prepare request payload
    const requestPayload = {
      ioc: ioc.trim(),
    };

    // Combine all feedback if any exists
    if (allFeedback && allFeedback.length > 0) {
      // Format feedback with timestamps for context
      const feedbackEntries = allFeedback.map((analysis, index) => {
        const timestamp = analysis.feedbackProvidedAt || analysis.createdAt;
        const timeStr = timestamp.toLocaleString("en-US", {
          month: "short",
          day: "numeric",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        });

        if (allFeedback.length === 1) {
          // Single feedback - no numbering needed
          return `[${timeStr}] ${analysis.analystFeedback}`;
        } else {
          // Multiple feedback - number them
          return `Feedback #${index + 1} [${timeStr}]:\n${
            analysis.analystFeedback
          }`;
        }
      });

      requestPayload.analyst_feedback = feedbackEntries.join("\n\n---\n\n");
      console.log(
        `[FEEDBACK] Found ${allFeedback.length} feedback entr${
          allFeedback.length === 1 ? "y" : "ies"
        } for IOC ${ioc.trim()}`
      );
    } else {
      console.log(
        `[FEEDBACK] No existing feedback found for IOC ${ioc.trim()}`
      );
    }

    // Call the AI ThreatIntel service
    const response = await axios.post(
      `${AI_THREATINTEL_BASE_URL}/api/v1/analyze/all-sources`,
      requestPayload,
      {
        timeout: 60000, // 60 second timeout
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    const analysisData = response.data;

    // Save analysis to database
    const analysis = new ThreatAnalysis({
      user: userId,
      ioc: ioc.trim(),
      iocType: analysisData.ioc_type || "unknown",
      verdict: analysisData.final_verdict?.verdict || "UNKNOWN",
      confidenceScore: analysisData.final_verdict?.confidence_score || 0,
      reasoning: analysisData.final_verdict?.reasoning || "",
      sources: analysisData.sources || {},
      rawData: analysisData,
    });

    await analysis.save();

    // Log the IOC analysis
    const user = await User.findById(userId);
    await AuditLog.create({
      userId: userId,
      userEmail: user.email,
      action: "Scan Performed",
      details: `Analyzed IP address ${ioc.trim()}`,
      status: "SUCCESS",
      ipAddress: req.ip || req.connection.remoteAddress,
    });

    res.json({
      success: true,
      data: {
        analysisId: analysis._id,
        ...analysisData,
      },
    });
  } catch (error) {
    console.error("Analysis error:", error.message);

    // Handle specific error cases
    if (error.response) {
      // AI service returned an error
      return res.status(error.response.status).json({
        success: false,
        message: error.response.data.message || "Analysis failed",
        details: error.response.data,
      });
    } else if (error.code === "ECONNREFUSED") {
      return res.status(503).json({
        success: false,
        message: "AI Threat Intelligence service is unavailable",
      });
    } else if (error.code === "ETIMEDOUT") {
      return res.status(504).json({
        success: false,
        message: "Analysis timed out. Please try again.",
      });
    }

    res.status(500).json({
      success: false,
      message: "Server error during analysis",
    });
  }
};

/**
 * Get analysis history for the current user
 */
const getAnalysisHistory = async (req, res) => {
  const userId = req.user.id;
  const { limit = 50, skip = 0 } = req.query;

  try {
    const analyses = await ThreatAnalysis.find({ user: userId })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .select("-rawData"); // Exclude large rawData field

    const total = await ThreatAnalysis.countDocuments({ user: userId });

    res.json({
      success: true,
      data: {
        analyses,
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
      },
    });
  } catch (error) {
    console.error("Get history error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to retrieve analysis history",
    });
  }
};

/**
 * Get a single analysis by ID
 */
const getAnalysisById = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    const analysis = await ThreatAnalysis.findOne({
      _id: id,
      user: userId,
    });

    if (!analysis) {
      return res.status(404).json({
        success: false,
        message: "Analysis not found",
      });
    }

    res.json({
      success: true,
      data: analysis,
    });
  } catch (error) {
    console.error("Get analysis error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to retrieve analysis",
    });
  }
};

/**
 * Delete an analysis by ID
 */
const deleteAnalysis = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    const analysis = await ThreatAnalysis.findOneAndDelete({
      _id: id,
      user: userId,
    });

    if (!analysis) {
      return res.status(404).json({
        success: false,
        message: "Analysis not found",
      });
    }

    res.json({
      success: true,
      message: "Analysis deleted successfully",
    });
  } catch (error) {
    console.error("Delete analysis error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete analysis",
    });
  }
};

/**
 * Get statistics for the current user
 */
const getStatistics = async (req, res) => {
  const userId = req.user.id;

  try {
    const total = await ThreatAnalysis.countDocuments({ user: userId });

    const verdictStats = await ThreatAnalysis.aggregate([
      { $match: { user: userId } },
      { $group: { _id: "$verdict", count: { $sum: 1 } } },
    ]);

    const recentAnalyses = await ThreatAnalysis.find({ user: userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .select("ioc verdict confidenceScore createdAt");

    res.json({
      success: true,
      data: {
        total,
        verdictStats: verdictStats.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        recentAnalyses,
      },
    });
  } catch (error) {
    console.error("Get statistics error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to retrieve statistics",
    });
  }
};

/**
 * Re-analyze an IOC and compare with previous analysis
 */
const reanalyzeIOC = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    // Fetch the old analysis
    const oldAnalysis = await ThreatAnalysis.findOne({
      _id: id,
      user: userId,
    });

    if (!oldAnalysis) {
      return res.status(404).json({
        success: false,
        message: "Analysis not found",
      });
    }

    const ioc = oldAnalysis.ioc;

    // Perform new analysis
    const newAnalysisResponse = await axios.post(
      `${AI_THREATINTEL_BASE_URL}/api/v1/analyze/all-sources`,
      { ioc: ioc.trim() },
      {
        timeout: 60000,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    const newAnalysisData = newAnalysisResponse.data;

    // Call comparison endpoint
    let comparisonData = null;
    try {
      const comparisonResponse = await axios.post(
        `${AI_THREATINTEL_BASE_URL}/api/v1/compare-analyses`,
        {
          old_analysis: {
            ...oldAnalysis.rawData,
            timestamp: oldAnalysis.createdAt,
          },
          new_analysis: {
            ...newAnalysisData,
            timestamp: new Date().toISOString(),
          },
        },
        {
          timeout: 30000,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      comparisonData = comparisonResponse.data;
    } catch (compError) {
      console.error("Comparison error:", compError.message);
      // Continue even if comparison fails
    }

    // Save new analysis to database
    const newAnalysis = new ThreatAnalysis({
      user: userId,
      ioc: ioc.trim(),
      iocType: newAnalysisData.ioc_type || "unknown",
      verdict: newAnalysisData.final_verdict?.verdict || "UNKNOWN",
      confidenceScore: newAnalysisData.final_verdict?.confidence_score || 0,
      reasoning: newAnalysisData.final_verdict?.reasoning || "",
      sources: newAnalysisData.sources || {},
      rawData: newAnalysisData,
    });

    await newAnalysis.save();

    res.json({
      success: true,
      data: {
        oldAnalysis: {
          _id: oldAnalysis._id,
          verdict: oldAnalysis.verdict,
          confidenceScore: oldAnalysis.confidenceScore,
          createdAt: oldAnalysis.createdAt,
          rawData: oldAnalysis.rawData,
        },
        newAnalysis: {
          _id: newAnalysis._id,
          ...newAnalysisData,
        },
        comparison: comparisonData,
      },
    });
  } catch (error) {
    console.error("Re-analysis error:", error.message);

    if (error.response) {
      return res.status(error.response.status).json({
        success: false,
        message: error.response.data.message || "Re-analysis failed",
        details: error.response.data,
      });
    } else if (error.code === "ECONNREFUSED") {
      return res.status(503).json({
        success: false,
        message: "AI Threat Intelligence service is unavailable",
      });
    } else if (error.code === "ETIMEDOUT") {
      return res.status(504).json({
        success: false,
        message: "Re-analysis timed out. Please try again.",
      });
    }

    res.status(500).json({
      success: false,
      message: "Server error during re-analysis",
    });
  }
};

/**
 * Add analyst feedback to an analysis
 */
const addAnalystFeedback = async (req, res) => {
  const { id } = req.params;
  const { feedback } = req.body;
  const userId = req.user.id;

  if (!feedback || !feedback.trim()) {
    return res.status(400).json({
      success: false,
      message: "Feedback is required",
    });
  }

  try {
    const analysis = await ThreatAnalysis.findOne({
      _id: id,
      user: userId,
    });

    if (!analysis) {
      return res.status(404).json({
        success: false,
        message: "Analysis not found",
      });
    }

    // Update feedback fields
    analysis.analystFeedback = feedback.trim();
    analysis.feedbackProvidedBy = userId;
    analysis.feedbackProvidedAt = new Date();

    await analysis.save();

    res.json({
      success: true,
      message: "Feedback added successfully",
      data: {
        _id: analysis._id,
        analystFeedback: analysis.analystFeedback,
        feedbackProvidedAt: analysis.feedbackProvidedAt,
      },
    });
  } catch (error) {
    console.error("Add feedback error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to add feedback",
    });
  }
};

/**
 * Get feedback for a specific IOC (most recent feedback across all analyses)
 */
const getFeedbackForIOC = async (req, res) => {
  const { ioc } = req.params;
  const userId = req.user.id;

  try {
    // Find the most recent analysis with feedback for this IOC
    const analysisWithFeedback = await ThreatAnalysis.findOne({
      user: userId,
      ioc: ioc.trim(),
      analystFeedback: { $exists: true, $ne: "" },
    })
      .sort({ feedbackProvidedAt: -1 })
      .select("analystFeedback feedbackProvidedAt feedbackProvidedBy");

    if (!analysisWithFeedback) {
      return res.json({
        success: true,
        data: {
          hasFeedback: false,
          feedback: null,
        },
      });
    }

    res.json({
      success: true,
      data: {
        hasFeedback: true,
        feedback: analysisWithFeedback.analystFeedback,
        feedbackProvidedAt: analysisWithFeedback.feedbackProvidedAt,
      },
    });
  } catch (error) {
    console.error("Get feedback error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to retrieve feedback",
    });
  }
};

export {
  analyzeIOC,
  getAnalysisHistory,
  getAnalysisById,
  deleteAnalysis,
  getStatistics,
  reanalyzeIOC,
  addAnalystFeedback,
  getFeedbackForIOC,
};
