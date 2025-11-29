import express from "express";
import {
  getAllUsers,
  createUser,
  updateUser,
  deleteUser,
  getAuditLogs,
} from "../controllers/adminController.js";
import authMiddleware from "../middlewares/authMiddleware.js";
import adminMiddleware from "../middlewares/adminMiddleware.js";

const router = express.Router();

// All routes require authentication and admin privileges
router.use(authMiddleware);
router.use(adminMiddleware);

// User management routes
router.get("/users", getAllUsers);
router.post("/users", createUser);
router.put("/users/:id", updateUser);
router.delete("/users/:id", deleteUser);

// Audit logs route
router.get("/audit-logs", getAuditLogs);

export default router;
