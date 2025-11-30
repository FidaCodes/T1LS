import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import authRoutes from "./routes/authRoutes.js";
import threatIntelRoutes from "./routes/threatIntelRoutes.js";
import schedulerRoutes from "./routes/schedulerRoutes.js";
import analyticsRoutes from "./routes/analyticsRoutes.js";
import reportRoutes from "./routes/reportRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import connectDB from "./configs/mongodb.js";
import schedulerService from "./services/schedulerService.js";

dotenv.config();
connectDB();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/threat-intel", threatIntelRoutes);
app.use("/api/scheduler", schedulerRoutes);
app.use("/api/analytics", analyticsRoutes);
app.use("/api/reports", reportRoutes);
app.use("/api/admin", adminRoutes);

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "Backend service is running" });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);

  // Start the scheduler service
  schedulerService.start();
});
