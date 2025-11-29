import ScheduledAnalysis from "../models/ScheduledAnalysis.js";
import ThreatAnalysis from "../models/ThreatAnalysis.js";

// Create a new scheduled analysis
export const createScheduledAnalysis = async (req, res) => {
  try {
    const { ioc, scheduledFor, recurrence, notes, slackChannelId } = req.body;

    // Validate scheduledFor is in the future
    const scheduleDate = new Date(scheduledFor);
    if (scheduleDate <= new Date()) {
      return res.status(400).json({
        message: "Scheduled time must be in the future",
      });
    }

    const scheduledAnalysis = new ScheduledAnalysis({
      ioc,
      scheduledFor: scheduleDate,
      recurrence: recurrence || "once",
      user: req.user.id,
      notes,
      slackChannelId,
    });

    await scheduledAnalysis.save();

    res.status(201).json({
      message: "Analysis scheduled successfully",
      schedule: scheduledAnalysis,
    });
  } catch (error) {
    console.error("Error creating scheduled analysis:", error);
    res.status(500).json({
      message: "Failed to schedule analysis",
      error: error.message,
    });
  }
};

// Get all scheduled analyses for the authenticated user
export const getUserSchedules = async (req, res) => {
  try {
    const { includeCompleted } = req.query;

    const schedules = await ScheduledAnalysis.getUserSchedules(
      req.user.id,
      includeCompleted === "true"
    );

    res.json({
      schedules,
      count: schedules.length,
    });
  } catch (error) {
    console.error("Error fetching scheduled analyses:", error);
    res.status(500).json({
      message: "Failed to fetch scheduled analyses",
      error: error.message,
    });
  }
};

// Get a specific scheduled analysis
export const getScheduleById = async (req, res) => {
  try {
    const { id } = req.params;

    const schedule = await ScheduledAnalysis.findById(id)
      .populate("user", "email username")
      .populate("analysisResult");

    if (!schedule) {
      return res.status(404).json({
        message: "Scheduled analysis not found",
      });
    }

    // Check if user owns this schedule
    if (schedule.user._id.toString() !== req.user.id) {
      return res.status(403).json({
        message: "Access denied",
      });
    }

    res.json({ schedule });
  } catch (error) {
    console.error("Error fetching scheduled analysis:", error);
    res.status(500).json({
      message: "Failed to fetch scheduled analysis",
      error: error.message,
    });
  }
};

// Update a scheduled analysis
export const updateSchedule = async (req, res) => {
  try {
    const { id } = req.params;
    const { scheduledFor, notes, slackChannelId, recurrence } = req.body;

    const schedule = await ScheduledAnalysis.findById(id);

    if (!schedule) {
      return res.status(404).json({
        message: "Scheduled analysis not found",
      });
    }

    // Check if user owns this schedule
    if (schedule.user.toString() !== req.user.id) {
      return res.status(403).json({
        message: "Access denied",
      });
    }

    // Can only update pending schedules
    if (schedule.status !== "pending") {
      return res.status(400).json({
        message: `Cannot update ${schedule.status} schedule`,
      });
    }

    // Update fields
    if (scheduledFor) {
      const newScheduleDate = new Date(scheduledFor);
      if (newScheduleDate <= new Date()) {
        return res.status(400).json({
          message: "Scheduled time must be in the future",
        });
      }
      schedule.scheduledFor = newScheduleDate;
    }

    if (notes !== undefined) schedule.notes = notes;
    if (slackChannelId !== undefined) schedule.slackChannelId = slackChannelId;
    if (recurrence !== undefined) schedule.recurrence = recurrence;

    await schedule.save();

    res.json({
      message: "Schedule updated successfully",
      schedule,
    });
  } catch (error) {
    console.error("Error updating scheduled analysis:", error);
    res.status(500).json({
      message: "Failed to update schedule",
      error: error.message,
    });
  }
};

// Cancel a scheduled analysis
export const cancelSchedule = async (req, res) => {
  try {
    const { id } = req.params;

    const schedule = await ScheduledAnalysis.findById(id);

    if (!schedule) {
      return res.status(404).json({
        message: "Scheduled analysis not found",
      });
    }

    // Check if user owns this schedule
    if (schedule.user.toString() !== req.user.id) {
      return res.status(403).json({
        message: "Access denied",
      });
    }

    // Can only cancel pending schedules
    if (schedule.status !== "pending") {
      return res.status(400).json({
        message: `Cannot cancel ${schedule.status} schedule`,
      });
    }

    schedule.status = "cancelled";
    await schedule.save();

    res.json({
      message: "Schedule cancelled successfully",
      schedule,
    });
  } catch (error) {
    console.error("Error cancelling scheduled analysis:", error);
    res.status(500).json({
      message: "Failed to cancel schedule",
      error: error.message,
    });
  }
};

// Delete a scheduled analysis
export const deleteSchedule = async (req, res) => {
  try {
    const { id } = req.params;

    const schedule = await ScheduledAnalysis.findById(id);

    if (!schedule) {
      return res.status(404).json({
        message: "Scheduled analysis not found",
      });
    }

    // Check if user owns this schedule
    if (schedule.user.toString() !== req.user.id) {
      return res.status(403).json({
        message: "Access denied",
      });
    }

    await schedule.deleteOne();

    res.json({
      message: "Schedule deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting scheduled analysis:", error);
    res.status(500).json({
      message: "Failed to delete schedule",
      error: error.message,
    });
  }
};

// Get statistics about scheduled analyses
export const getScheduleStats = async (req, res) => {
  try {
    const userId = req.user.id;

    const stats = await ScheduledAnalysis.aggregate([
      { $match: { user: userId } },
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 },
        },
      },
    ]);

    const statsObject = {
      pending: 0,
      running: 0,
      completed: 0,
      failed: 0,
      cancelled: 0,
    };

    stats.forEach((stat) => {
      statsObject[stat._id] = stat.count;
    });

    // Get upcoming schedules (next 24 hours)
    const upcoming = await ScheduledAnalysis.countDocuments({
      user: userId,
      status: "pending",
      scheduledFor: {
        $gte: new Date(),
        $lte: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });

    res.json({
      stats: statsObject,
      upcoming,
    });
  } catch (error) {
    console.error("Error fetching schedule stats:", error);
    res.status(500).json({
      message: "Failed to fetch statistics",
      error: error.message,
    });
  }
};
