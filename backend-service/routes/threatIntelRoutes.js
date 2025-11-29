import express from "express";
import authMiddleware from "../middlewares/authMiddleware.js";
import {
  analyzeIOC,
  getAnalysisHistory,
  getAnalysisById,
  deleteAnalysis,
  getStatistics,
  reanalyzeIOC,
  addAnalystFeedback,
  getFeedbackForIOC,
} from "../controllers/threatIntelController.js";

const router = express.Router();

// All routes require authentication
router.use(authMiddleware);

// Analyze IOC
router.post("/analyze", analyzeIOC);

// Re-analyze IOC and compare with previous analysis
router.post("/reanalyze/:id", reanalyzeIOC);

// Add analyst feedback to an analysis
router.post("/:id/feedback", addAnalystFeedback);

// Get feedback for a specific IOC
router.get("/feedback/:ioc", getFeedbackForIOC);

// Get analysis history
router.get("/history", getAnalysisHistory);

// Get statistics
router.get("/statistics", getStatistics);

// Get specific analysis
router.get("/:id", getAnalysisById);

// Delete analysis
router.delete("/:id", deleteAnalysis);

export default router;
