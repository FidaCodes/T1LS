import express from "express";
import {
  registerDeveloper,
  loginDeveloper,
  getDeveloperProfile,
  generateApiKey,
  getApiKeys,
  deleteApiKey,
  addCredits,
  getCredits,
} from "../controllers/developerController.js";
import { protectDeveloper } from "../middlewares/developerMiddleware.js";

const router = express.Router();

// Public routes
router.post("/register", registerDeveloper);
router.post("/login", loginDeveloper);

// Protected routes (require authentication)
router.get("/profile", protectDeveloper, getDeveloperProfile);
router.get("/credits", protectDeveloper, getCredits);
router.post("/credits", protectDeveloper, addCredits);
router.get("/api-keys", protectDeveloper, getApiKeys);
router.post("/api-keys", protectDeveloper, generateApiKey);
router.delete("/api-keys/:keyId", protectDeveloper, deleteApiKey);

export default router;
