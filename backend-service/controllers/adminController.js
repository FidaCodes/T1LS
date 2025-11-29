import bcrypt from "bcryptjs";
import User from "../models/User.js";
import AuditLog from "../models/AuditLog.js";
import ThreatAnalysis from "../models/ThreatAnalysis.js";

// Get all users
export const getAllUsers = async (req, res) => {
  try {
    const users = await User.find()
      .select("-password")
      .sort({ createdAt: -1 })
      .lean();

    // Get total scans for each user
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const totalScans = await ThreatAnalysis.countDocuments({
          user: user._id,
        });

        return {
          ...user,
          totalScans,
          lastLogin: user.updatedAt,
          status: "Active", // You can implement a more sophisticated status system
        };
      })
    );

    res.json({
      success: true,
      data: usersWithStats,
    });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch users",
    });
  }
};

// Create a new user (admin function)
export const createUser = async (req, res) => {
  const { username, email, password, role } = req.body;
  const adminId = req.user.id;
  const ipAddress = req.ip || req.connection.remoteAddress;

  try {
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    // Create new user
    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({
      username,
      email,
      password: hashedPassword,
      role: role || "analyst",
    });

    await user.save();

    // Log user creation by admin
    const admin = await User.findById(adminId);
    await AuditLog.create({
      userId: adminId,
      userEmail: admin.email,
      action: "User Created",
      details: `Created new user account for ${email} with role ${
        role || "analyst"
      }`,
      status: "SUCCESS",
      ipAddress,
    });

    res.status(201).json({
      success: true,
      data: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Create user error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create user",
    });
  }
};

// Update user
export const updateUser = async (req, res) => {
  const { id } = req.params;
  const { username, email, role, password } = req.body;
  const adminId = req.user.id;
  const ipAddress = req.ip || req.connection.remoteAddress;

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Update fields
    if (username) user.username = username;
    if (email) user.email = email;
    if (role) user.role = role;
    if (password) {
      user.password = await bcrypt.hash(password, 10);
    }

    await user.save();

    // Log user update
    const admin = await User.findById(adminId);
    await AuditLog.create({
      userId: adminId,
      userEmail: admin.email,
      action: "User Updated",
      details: `Updated user account for ${user.email}`,
      status: "SUCCESS",
      ipAddress,
    });

    res.json({
      success: true,
      data: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Update user error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update user",
    });
  }
};

// Delete user
export const deleteUser = async (req, res) => {
  const { id } = req.params;
  const adminId = req.user.id;
  const ipAddress = req.ip || req.connection.remoteAddress;

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Prevent deleting yourself
    if (id === adminId) {
      return res.status(400).json({
        success: false,
        message: "Cannot delete your own account",
      });
    }

    const userEmail = user.email;
    await User.findByIdAndDelete(id);

    // Log user deletion
    const admin = await User.findById(adminId);
    await AuditLog.create({
      userId: adminId,
      userEmail: admin.email,
      action: "User Deleted",
      details: `Deleted user account for ${userEmail}`,
      status: "SUCCESS",
      ipAddress,
    });

    res.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete user",
    });
  }
};

// Get audit logs
export const getAuditLogs = async (req, res) => {
  try {
    const { limit = 100, skip = 0 } = req.query;

    const logs = await AuditLog.find()
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .populate("userId", "username email")
      .lean();

    const total = await AuditLog.countDocuments();

    res.json({
      success: true,
      data: {
        logs,
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
      },
    });
  } catch (error) {
    console.error("Get audit logs error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch audit logs",
    });
  }
};
