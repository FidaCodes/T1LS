import express from "express";
import { getAnalytics } from "../controllers/analyticsController.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = express.Router();

// All routes require authentication
router.use(authMiddleware);

// Get analytics data
router.get("/", getAnalytics);

export default router;
