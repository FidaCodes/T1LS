import mongoose from "mongoose";
import dotenv from "dotenv";
import ScheduledAnalysis from "./models/ScheduledAnalysis.js";
import User from "./models/User.js";

dotenv.config();

const testScheduler = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("✅ Connected to MongoDB");

    // Get current time
    const now = new Date();
    console.log(`\n⏰ Current time: ${now.toISOString()}`);
    console.log(`⏰ Current time (local): ${now.toLocaleString()}`);

    // Find all pending schedules
    const pendingSchedules = await ScheduledAnalysis.find({
      status: "pending",
    }).populate("user", "email username");

    console.log(`\n📊 Found ${pendingSchedules.length} pending schedule(s):\n`);

    pendingSchedules.forEach((schedule, index) => {
      const scheduledTime = new Date(schedule.scheduledFor);
      const isPast = scheduledTime <= now;
      const diffMinutes = Math.round((scheduledTime - now) / 60000);

      console.log(`${index + 1}. IOC: ${schedule.ioc}`);
      console.log(`   Scheduled for: ${scheduledTime.toISOString()}`);
      console.log(
        `   Scheduled for (local): ${scheduledTime.toLocaleString()}`
      );
      console.log(`   Status: ${schedule.status}`);
      console.log(`   User: ${schedule.user?.email || "Unknown"}`);
      console.log(`   Ready to run: ${isPast ? "✅ YES" : "❌ NO"}`);
      console.log(
        `   Time difference: ${
          isPast ? "Past" : `${diffMinutes} minutes in future`
        }`
      );
      console.log("");
    });

    // Test getReadyAnalyses method
    const readyAnalyses = await ScheduledAnalysis.find({
      status: "pending",
      scheduledFor: { $lte: now },
    }).populate("user", "email username");

    console.log(`\n✨ Ready to execute: ${readyAnalyses.length} schedule(s)`);

    if (readyAnalyses.length > 0) {
      console.log("\nSchedules ready for execution:");
      readyAnalyses.forEach((schedule, index) => {
        console.log(
          `${index + 1}. ${
            schedule.ioc
          } (${schedule.scheduledFor.toISOString()})`
        );
      });
    }

    // Show all schedules by status
    const byStatus = await ScheduledAnalysis.aggregate([
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 },
        },
      },
    ]);

    console.log("\n📈 Schedules by status:");
    byStatus.forEach((stat) => {
      console.log(`   ${stat._id}: ${stat.count}`);
    });
  } catch (error) {
    console.error("❌ Error:", error);
  } finally {
    await mongoose.disconnect();
    console.log("\n👋 Disconnected from MongoDB");
    process.exit(0);
  }
};

testScheduler();
