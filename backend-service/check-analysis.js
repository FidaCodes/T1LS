import mongoose from "mongoose";
import dotenv from "dotenv";
import ThreatAnalysis from "./models/ThreatAnalysis.js";

dotenv.config();

const checkAnalysis = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("✅ Connected to MongoDB\n");

    const latest = await ThreatAnalysis.findOne({ ioc: "facebook.com" }).sort({
      createdAt: -1,
    });

    if (!latest) {
      console.log("❌ No analysis found for facebook.com");
      return;
    }

    console.log("📊 Analysis for facebook.com:\n");
    console.log("IOC:", latest.ioc);
    console.log("Verdict:", latest.verdict);
    console.log("Confidence:", latest.confidence);
    console.log("IOC Type:", latest.ioc_type);
    console.log("\n📦 Raw Data Structure:");
    console.log("Has intelligence_data?", !!latest.rawData?.intelligence_data);
    console.log("Has sources?", !!latest.rawData?.intelligence_data?.sources);

    if (latest.rawData?.intelligence_data?.sources) {
      const sources = latest.rawData.intelligence_data.sources;
      console.log("\n🔍 Sources collected:");
      Object.keys(sources).forEach((sourceName) => {
        const source = sources[sourceName];
        const hasError = !!source.error;
        console.log(
          `   ${hasError ? "❌" : "✅"} ${sourceName}:`,
          hasError ? source.error : "Data collected"
        );
      });
    } else {
      console.log("\n❌ No sources data found!");
      console.log("rawData keys:", Object.keys(latest.rawData || {}));
    }

    console.log("\n📝 Classification:");
    if (latest.rawData?.classification) {
      console.log(
        "   Classification:",
        latest.rawData.classification.classification
      );
      console.log(
        "   Confidence:",
        latest.rawData.classification.confidence_score
      );
      console.log(
        "   Reasoning:",
        latest.rawData.classification.reasoning?.substring(0, 100) + "..."
      );
    } else {
      console.log("   ❌ No classification found");
    }
  } catch (error) {
    console.error("❌ Error:", error);
  } finally {
    await mongoose.disconnect();
    console.log("\n👋 Disconnected from MongoDB");
    process.exit(0);
  }
};

checkAnalysis();
