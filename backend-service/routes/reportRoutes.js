import express from "express";
import {
  generateCustomReport,
  getAvailableReports,
} from "../controllers/reportController.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = express.Router();

// Get available reports
router.get("/", authMiddleware, getAvailableReports);

// Generate custom report
router.post("/generate", authMiddleware, generateCustomReport);

export default router;
