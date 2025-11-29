import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import AuditLog from "../models/AuditLog.js";

const login = async (req, res) => {
  const { email, password } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      // Log failed login attempt
      await AuditLog.create({
        userEmail: email,
        action: "Login Failed",
        details: "User not found",
        status: "FAILED",
        ipAddress,
      });
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Log failed login attempt
      await AuditLog.create({
        userId: user._id,
        userEmail: email,
        action: "Login Failed",
        details: "Invalid credentials",
        status: "FAILED",
        ipAddress,
      });
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    // Log successful login
    await AuditLog.create({
      userId: user._id,
      userEmail: email,
      action: "User Login",
      details: `Successful login from IP ${ipAddress}`,
      status: "SUCCESS",
      ipAddress,
    });

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

const register = async (req, res) => {
  const { username, email, password, role } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({
      username,
      email,
      password: hashedPassword,
      role: role || "analyst", // Default to analyst if not specified
    });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    // Log user creation
    await AuditLog.create({
      userId: user._id,
      userEmail: email,
      action: "User Created",
      details: `New user account created for ${email}`,
      status: "SUCCESS",
      ipAddress,
    });

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export { login, register };
