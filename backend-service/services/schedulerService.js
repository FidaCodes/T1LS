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

      // Mark schedule as completed
      await schedule.markAsCompleted(threatAnalysis._id);

      console.log(`✅ Analysis completed for: ${schedule.ioc} (${verdict})`);

      // Handle recurrence
      if (schedule.recurrence !== "once") {
        await this.scheduleNextOccurrence(schedule);
      }
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

  // Schedule the next occurrence for recurring analyses
  async scheduleNextOccurrence(originalSchedule) {
    try {
      let nextScheduledFor = new Date(originalSchedule.scheduledFor);

      // Calculate next run time based on recurrence
      switch (originalSchedule.recurrence) {
        case "hourly":
          nextScheduledFor.setHours(nextScheduledFor.getHours() + 1);
          break;
        case "daily":
          nextScheduledFor.setDate(nextScheduledFor.getDate() + 1);
          break;
        case "weekly":
          nextScheduledFor.setDate(nextScheduledFor.getDate() + 7);
          break;
        default:
          return; // No recurrence
      }

      // Create new scheduled analysis
      const newSchedule = new ScheduledAnalysis({
        ioc: originalSchedule.ioc,
        scheduledFor: nextScheduledFor,
        recurrence: originalSchedule.recurrence,
        user: originalSchedule.user,
        notes: originalSchedule.notes,
      });

      await newSchedule.save();

      console.log(
        `🔁 Next occurrence scheduled for: ${nextScheduledFor.toLocaleString()}`
      );
    } catch (error) {
      console.error("❌ Error scheduling next occurrence:", error);
    }
  }
}

// Create singleton instance
const schedulerService = new SchedulerService();

export default schedulerService;
