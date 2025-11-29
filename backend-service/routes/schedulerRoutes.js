import express from "express";
import * as schedulerController from "../controllers/schedulerController.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = express.Router();

// All routes require authentication
router.use(authMiddleware);

// Create a new scheduled analysis
router.post("/schedule", schedulerController.createScheduledAnalysis);

// Get all scheduled analyses for the user
router.get("/schedules", schedulerController.getUserSchedules);

// Get schedule statistics
router.get("/stats", schedulerController.getScheduleStats);

// Get a specific scheduled analysis
router.get("/schedule/:id", schedulerController.getScheduleById);

// Update a scheduled analysis
router.put("/schedule/:id", schedulerController.updateSchedule);

// Cancel a scheduled analysis
router.patch("/schedule/:id/cancel", schedulerController.cancelSchedule);

// Delete a scheduled analysis
router.delete("/schedule/:id", schedulerController.deleteSchedule);

export default router;
