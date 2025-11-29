import express from "express";
import * as assetController from "../controllers/assetController.js";
import authMiddleware from "../middlewares/authMiddleware.js";

const router = express.Router();

// All routes require authentication
router.use(authMiddleware);

// Asset management routes
router.get("/assets", assetController.getAllAssets);
router.get("/assets/:id", assetController.getAssetById);
router.post("/assets", assetController.createAsset);
router.put("/assets/:id", assetController.updateAsset);
router.delete("/assets/:id", assetController.deleteAsset);

// Activity logging routes
router.post("/activities", assetController.logActivity);
router.get("/activities", assetController.getActivities);

// Threat correlation routes
router.get("/dashboard", assetController.getThreatCorrelationDashboard);
router.post("/correlate", assetController.correlateAllAssets);

export default router;
