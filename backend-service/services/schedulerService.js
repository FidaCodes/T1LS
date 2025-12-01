import cron from "node-cron";
import axios from "axios";
import ScheduledAnalysis from "../models/ScheduledAnalysis.js";
import ThreatAnalysis from "../models/ThreatAnalysis.js";

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8000";

class SchedulerService {
  constructor() {
    this.isRunning = false;
  }

  // Start the scheduler - runs every minute to check for pending analyses
  start() {
    if (this.isRunning) {
      console.log("⚠️  Scheduler is already running");
      return;
    }

    console.log("\n📅 Starting Scheduler Service...");
    console.log(`🔧 AI Service URL: ${AI_SERVICE_URL}`);
    console.log("⏰ Cron job will run every minute (* * * * *)");

    // Run every minute
    cron.schedule("* * * * *", async () => {
      await this.processScheduledAnalyses();
    });

    // Also run immediately on startup
    console.log("🚀 Running initial check...\n");
    this.processScheduledAnalyses();

    this.isRunning = true;
    console.log("✅ Scheduler Service started successfully\n");
  }

  // Process all pending scheduled analyses that are ready to run
  async processScheduledAnalyses() {
    try {
      const now = new Date();
      console.log(
        `⏰ Checking for scheduled analyses... (Current time: ${now.toISOString()})`
      );

      // Get all ready-to-run analyses
      const readyAnalyses = await ScheduledAnalysis.getReadyAnalyses();

      if (readyAnalyses.length === 0) {
        // Check if there are any pending schedules at all
        const allPending = await ScheduledAnalysis.find({ status: "pending" });
        if (allPending.length > 0) {
          console.log(
            `⏳ ${allPending.length} pending schedule(s) found, but not ready yet:`
          );
          allPending.forEach((schedule) => {
            console.log(
              `   - IOC: ${
                schedule.ioc
              }, Scheduled for: ${schedule.scheduledFor.toISOString()}`
            );
          });
        }
        return;
      }

      console.log(
        `\n🔄 Processing ${readyAnalyses.length} scheduled analysis(es)...`
      );

      // Process each analysis
      for (const schedule of readyAnalyses) {
        await this.executeScheduledAnalysis(schedule);
      }
    } catch (error) {
      console.error("❌ Error processing scheduled analyses:", error);
    }
  }

  // Execute a single scheduled analysis
  async executeScheduledAnalysis(schedule) {
    try {
      console.log(`\n▶️  Executing scheduled analysis: ${schedule.ioc}`);

      // Mark as running
      await schedule.markAsRunning();

      // Call AI service to analyze the IOC
      const analysisResult = await this.analyzeIOC(schedule.ioc);

      console.log(
        "📊 Analysis result structure:",
        JSON.stringify(
          {
            success: analysisResult.success,
            hasSources: !!analysisResult.sources,
            hasFinalVerdict: !!analysisResult.final_verdict,
            sources: analysisResult.sources
              ? Object.keys(analysisResult.sources)
              : [],
          },
          null,
          2
        )
      );

      // Extract data from the response - SAME as normal analysis
      const iocType = analysisResult.ioc_type || "unknown";
      const verdict = analysisResult.final_verdict?.verdict || "UNKNOWN";
      const confidence = analysisResult.final_verdict?.confidence_score || 0;
      const reasoning = analysisResult.final_verdict?.reasoning || "";
      const sources = analysisResult.sources || {};

      // Check if analysis was successful
      if (!analysisResult.success) {
        throw new Error(analysisResult.message || "Analysis failed");
      }

      // Save the analysis result - SAME FORMAT as normal analysis
      const threatAnalysis = new ThreatAnalysis({
        user: schedule.user._id,
        ioc: schedule.ioc,
        iocType: iocType,
        verdict: verdict,
        confidenceScore: confidence,
        reasoning: reasoning,
        sources: sources, // Top-level sources, just like normal analysis
        rawData: analysisResult,
        isScheduled: true,
        scheduledAnalysisId: schedule._id,
      });

      await threatAnalysis.save();

      console.log(`✅ Analysis completed for: ${schedule.ioc} (${verdict})`);

      // Handle recurrence - update the schedule for next run instead of marking completed
      await this.rescheduleAnalysis(schedule);
    } catch (error) {
      console.error(
        `❌ Error executing analysis for ${schedule.ioc}:`,
        error.message
      );

      // Mark as failed
      await schedule.markAsFailed(error.message);
    }
  }

  // Call AI service to analyze IOC
  async analyzeIOC(ioc) {
    try {
      const response = await axios.post(
        `${AI_SERVICE_URL}/api/v1/analyze/all-sources`,
        { ioc },
        {
          timeout: 60000, // 60 second timeout
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      return response.data;
    } catch (error) {
      if (error.response) {
        throw new Error(
          `AI Service Error: ${
            error.response.data.detail || error.response.statusText
          }`
        );
      } else if (error.request) {
        throw new Error("AI Service is unreachable");
      } else {
        throw new Error(`Analysis failed: ${error.message}`);
      }
    }
  }

  // Reschedule the analysis for next run
  async rescheduleAnalysis(schedule) {
    try {
      let nextScheduledFor = new Date();

      // Calculate next run time based on recurrence (matching UI labels)
      switch (schedule.recurrence) {
        case "hourly": // Every 6 hours
          nextScheduledFor.setHours(nextScheduledFor.getHours() + 6);
          break;
        case "daily": // Every 12 hours
          nextScheduledFor.setHours(nextScheduledFor.getHours() + 12);
          break;
        case "once": // Every 24 hours
          nextScheduledFor.setHours(nextScheduledFor.getHours() + 24);
          break;
        case "weekly": // Every 48 hours
          nextScheduledFor.setHours(nextScheduledFor.getHours() + 48);
          break;
        default:
          nextScheduledFor.setHours(nextScheduledFor.getHours() + 24);
      }

      // Update the same schedule for next run
      schedule.scheduledFor = nextScheduledFor;
      schedule.status = "pending";
      schedule.lastRun = new Date();
      schedule.totalScans = (schedule.totalScans || 0) + 1;
      await schedule.save();

      console.log(
        `🔁 Rescheduled for: ${nextScheduledFor.toLocaleString()} (Recurrence: ${schedule.recurrence})`
      );
    } catch (error) {
      console.error("❌ Error rescheduling analysis:", error);
    }
  }
}

// Create singleton instance
const schedulerService = new SchedulerService();

export default schedulerService;
