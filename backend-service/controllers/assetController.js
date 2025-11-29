import Asset from "../models/Asset.js";
import AssetActivity from "../models/AssetActivity.js";
import ThreatAnalysis from "../models/ThreatAnalysis.js";

// Get all assets with pagination and filtering
export const getAllAssets = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      status,
      deviceType,
      owner,
      sortBy = "riskScore",
      sortOrder = "desc",
    } = req.query;

    const query = {};
    if (status) query.status = status;
    if (deviceType) query.deviceType = deviceType;
    if (owner) query.owner = new RegExp(owner, "i");

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sort = { [sortBy]: sortOrder === "desc" ? -1 : 1 };

    const [assets, total] = await Promise.all([
      Asset.find(query).sort(sort).skip(skip).limit(parseInt(limit)),
      Asset.countDocuments(query),
    ]);

    res.json({
      success: true,
      data: assets,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        totalAssets: total,
        limit: parseInt(limit),
      },
    });
  } catch (error) {
    console.error("Error fetching assets:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Get single asset with activities
export const getAssetById = async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);
    if (!asset) {
      return res
        .status(404)
        .json({ success: false, message: "Asset not found" });
    }

    // Get recent activities
    const activities = await AssetActivity.find({ assetId: asset._id })
      .sort({ createdAt: -1 })
      .limit(100);

    res.json({
      success: true,
      data: {
        asset,
        activities,
      },
    });
  } catch (error) {
    console.error("Error fetching asset:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Create new asset
export const createAsset = async (req, res) => {
  try {
    const asset = new Asset({
      ...req.body,
      createdBy: req.user.userId,
    });
    await asset.save();

    res.status(201).json({
      success: true,
      message: "Asset created successfully",
      data: asset,
    });
  } catch (error) {
    console.error("Error creating asset:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Update asset
export const updateAsset = async (req, res) => {
  try {
    const asset = await Asset.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!asset) {
      return res
        .status(404)
        .json({ success: false, message: "Asset not found" });
    }

    res.json({
      success: true,
      message: "Asset updated successfully",
      data: asset,
    });
  } catch (error) {
    console.error("Error updating asset:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Delete asset
export const deleteAsset = async (req, res) => {
  try {
    const asset = await Asset.findByIdAndDelete(req.params.id);
    if (!asset) {
      return res
        .status(404)
        .json({ success: false, message: "Asset not found" });
    }

    // Also delete associated activities
    await AssetActivity.deleteMany({ assetId: asset._id });

    res.json({
      success: true,
      message: "Asset and associated activities deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting asset:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Log new activity for an asset
export const logActivity = async (req, res) => {
  try {
    const { deviceId } = req.body;

    // Find or create asset
    let asset = await Asset.findOne({ deviceId });
    if (!asset) {
      return res.status(404).json({
        success: false,
        message: "Asset not found. Please create the asset first.",
      });
    }

    const activity = new AssetActivity({
      ...req.body,
      assetId: asset._id,
    });

    // Check for threat correlations
    const correlations = await correlateWithThreats(activity);
    if (correlations.length > 0) {
      activity.correlatedThreats = correlations;
      activity.severity = calculateSeverity(correlations);

      // Update asset risk score and add threat indicators
      await updateAssetRiskScore(asset, correlations);
    }

    await activity.save();

    // Update asset last seen
    asset.lastSeen = new Date();
    await asset.save();

    res.status(201).json({
      success: true,
      message: "Activity logged successfully",
      data: activity,
      correlations: correlations.length,
    });
  } catch (error) {
    console.error("Error logging activity:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Get activities with filtering
export const getActivities = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      deviceId,
      activityType,
      severity,
      hasThreats,
      startDate,
      endDate,
    } = req.query;

    const query = {};
    if (deviceId) query.deviceId = deviceId;
    if (activityType) query.activityType = activityType;
    if (severity) query.severity = severity;
    if (hasThreats === "true") query["correlatedThreats.0"] = { $exists: true };

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [activities, total] = await Promise.all([
      AssetActivity.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .populate("assetId", "deviceId deviceName owner"),
      AssetActivity.countDocuments(query),
    ]);

    res.json({
      success: true,
      data: activities,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        totalActivities: total,
        limit: parseInt(limit),
      },
    });
  } catch (error) {
    console.error("Error fetching activities:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Get threat correlation dashboard
export const getThreatCorrelationDashboard = async (req, res) => {
  try {
    const [
      totalAssets,
      compromisedAssets,
      totalActivities,
      threatenedActivities,
      recentCorrelations,
      topThreatenedAssets,
    ] = await Promise.all([
      Asset.countDocuments(),
      Asset.countDocuments({
        status: { $in: ["compromised", "investigating"] },
      }),
      AssetActivity.countDocuments(),
      AssetActivity.countDocuments({
        "correlatedThreats.0": { $exists: true },
      }),
      AssetActivity.find({ "correlatedThreats.0": { $exists: true } })
        .sort({ createdAt: -1 })
        .limit(10)
        .populate("assetId", "deviceId deviceName owner"),
      Asset.find({ riskScore: { $gt: 0 } })
        .sort({ riskScore: -1 })
        .limit(10),
    ]);

    // Get activity type distribution
    const activityDistribution = await AssetActivity.aggregate([
      { $group: { _id: "$activityType", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    // Get severity distribution
    const severityDistribution = await AssetActivity.aggregate([
      { $match: { "correlatedThreats.0": { $exists: true } } },
      { $group: { _id: "$severity", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    res.json({
      success: true,
      data: {
        summary: {
          totalAssets,
          compromisedAssets,
          totalActivities,
          threatenedActivities,
          threatPercentage:
            totalActivities > 0
              ? ((threatenedActivities / totalActivities) * 100).toFixed(2)
              : 0,
        },
        recentCorrelations,
        topThreatenedAssets,
        activityDistribution,
        severityDistribution,
      },
    });
  } catch (error) {
    console.error("Error fetching threat correlation dashboard:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Helper function to correlate activity with known threats
async function correlateWithThreats(activity) {
  const correlations = [];

  try {
    // Check IPs against threat analyses
    if (activity.destinationIp) {
      const ipThreats = await ThreatAnalysis.find({
        ioc: activity.destinationIp,
        iocType: "ip",
        verdict: { $in: ["MALICIOUS", "SUSPICIOUS"] },
      })
        .sort({ updatedAt: -1 })
        .limit(5);

      for (const threat of ipThreats) {
        correlations.push({
          ioc: threat.ioc,
          iocType: threat.iocType,
          threatLevel: (threat.verdict || "UNKNOWN").toString().toLowerCase(),
          confidence: calculateConfidence(threat),
          analysisId: threat._id,
          correlatedAt: new Date(),
        });
      }
    }

    // Check domains
    if (activity.domain) {
      const domainThreats = await ThreatAnalysis.find({
        ioc: activity.domain,
        iocType: "domain",
        verdict: { $in: ["MALICIOUS", "SUSPICIOUS"] },
      })
        .sort({ updatedAt: -1 })
        .limit(5);

      for (const threat of domainThreats) {
        correlations.push({
          ioc: threat.ioc,
          iocType: threat.iocType,
          threatLevel: (threat.verdict || "UNKNOWN").toString().toLowerCase(),
          confidence: calculateConfidence(threat),
          analysisId: threat._id,
          correlatedAt: new Date(),
        });
      }
    }

    // Check URLs
    if (activity.url) {
      const urlThreats = await ThreatAnalysis.find({
        ioc: activity.url,
        iocType: "url",
        verdict: { $in: ["MALICIOUS", "SUSPICIOUS"] },
      })
        .sort({ updatedAt: -1 })
        .limit(5);

      for (const threat of urlThreats) {
        correlations.push({
          ioc: threat.ioc,
          iocType: threat.iocType,
          threatLevel: (threat.verdict || "UNKNOWN").toString().toLowerCase(),
          confidence: calculateConfidence(threat),
          analysisId: threat._id,
          correlatedAt: new Date(),
        });
      }
    }

    // Check file hashes
    if (activity.fileHash) {
      const hashThreats = await ThreatAnalysis.find({
        ioc: activity.fileHash,
        iocType: "hash",
        verdict: { $in: ["MALICIOUS", "SUSPICIOUS"] },
      })
        .sort({ updatedAt: -1 })
        .limit(5);

      for (const threat of hashThreats) {
        correlations.push({
          ioc: threat.ioc,
          iocType: threat.iocType,
          threatLevel: (threat.verdict || "UNKNOWN").toString().toLowerCase(),
          confidence: calculateConfidence(threat),
          analysisId: threat._id,
          correlatedAt: new Date(),
        });
      }
    }
  } catch (error) {
    console.error("Error correlating with threats:", error);
  }

  return correlations;
}

// Calculate confidence score based on source verdicts
function calculateConfidence(threatAnalysis) {
  const sources = threatAnalysis.sources || [];
  let maliciousCount = 0;
  let totalCount = sources.length;

  sources.forEach((source) => {
    if (
      source.verdict === "malicious" ||
      source.verdict === "suspicious" ||
      source.is_malicious
    ) {
      maliciousCount++;
    }
  });

  return totalCount > 0 ? Math.round((maliciousCount / totalCount) * 100) : 50;
}

// Calculate severity based on correlations
function calculateSeverity(correlations) {
  if (correlations.length === 0) return "info";

  const hasCritical = correlations.some(
    (c) => c.threatLevel === "malicious" && c.confidence > 80
  );
  if (hasCritical) return "critical";

  const hasHigh = correlations.some(
    (c) => c.threatLevel === "malicious" && c.confidence > 50
  );
  if (hasHigh) return "high";

  const hasMedium = correlations.some((c) => c.threatLevel === "suspicious");
  if (hasMedium) return "medium";

  return "low";
}

// Update asset risk score based on threat correlations
async function updateAssetRiskScore(asset, correlations) {
  // Calculate risk score based on correlations
  let riskIncrease = 0;

  correlations.forEach((correlation) => {
    if (correlation.threatLevel === "malicious") {
      riskIncrease += correlation.confidence * 0.5; // Max 50 points per threat
    } else if (correlation.threatLevel === "suspicious") {
      riskIncrease += correlation.confidence * 0.3; // Max 30 points per threat
    }
  });

  asset.riskScore = Math.min(100, asset.riskScore + riskIncrease / 10);

  // Add unique threat indicators
  correlations.forEach((correlation) => {
    const exists = asset.threatIndicators.some(
      (ti) => ti.ioc === correlation.ioc
    );
    if (!exists) {
      asset.threatIndicators.push({
        ioc: correlation.ioc,
        iocType: correlation.iocType,
        threatLevel: correlation.threatLevel,
        detectedAt: new Date(),
        analysisId: correlation.analysisId,
      });
    }
  });

  // Update status if high risk
  if (asset.riskScore > 70 && asset.status === "active") {
    asset.status = "investigating";
  } else if (asset.riskScore > 90 && asset.status !== "compromised") {
    asset.status = "compromised";
  }

  await asset.save();
}

// Manual threat correlation trigger
export const correlateAllAssets = async (req, res) => {
  try {
    const activities = await AssetActivity.find({
      correlatedThreats: { $size: 0 },
    }).limit(1000);

    let correlatedCount = 0;

    for (const activity of activities) {
      const correlations = await correlateWithThreats(activity);
      if (correlations.length > 0) {
        activity.correlatedThreats = correlations;
        activity.severity = calculateSeverity(correlations);
        await activity.save();

        const asset = await Asset.findById(activity.assetId);
        if (asset) {
          await updateAssetRiskScore(asset, correlations);
        }

        correlatedCount++;
      }
    }

    res.json({
      success: true,
      message: `Correlated ${correlatedCount} activities with known threats`,
      correlatedCount,
    });
  } catch (error) {
    console.error("Error correlating assets:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};
