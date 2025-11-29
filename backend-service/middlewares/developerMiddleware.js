import jwt from "jsonwebtoken";
import Developer from "../models/Developer.js";

const protectDeveloper = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      // Get token from header
      token = req.headers.authorization.split(" ")[1];

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Check if this is a developer token
      if (decoded.type !== "developer") {
        return res.status(401).json({
          success: false,
          message: "Not authorized as developer",
        });
      }

      // Get developer from token
      req.developer = await Developer.findById(decoded.id).select("-password");

      if (!req.developer) {
        return res.status(401).json({
          success: false,
          message: "Developer not found",
        });
      }

      next();
    } catch (error) {
      console.error("Developer auth middleware error:", error);
      return res.status(401).json({
        success: false,
        message: "Not authorized, token failed",
      });
    }
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Not authorized, no token",
    });
  }
};

// Middleware to verify API key
const verifyApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers["x-api-key"];

    if (!apiKey) {
      return res.status(401).json({
        success: false,
        message: "API key is required",
      });
    }

    // Find developer with this API key
    const developer = await Developer.findOne({
      "apiKeys.key": apiKey,
      "apiKeys.isActive": true,
    });

    if (!developer) {
      return res.status(401).json({
        success: false,
        message: "Invalid or inactive API key",
      });
    }

    // Find the specific API key and update last used
    const apiKeyObj = developer.apiKeys.find(
      (key) => key.key === apiKey && key.isActive
    );
    if (apiKeyObj) {
      apiKeyObj.lastUsed = new Date();
      await developer.save();
    }

    // Attach developer to request
    req.developer = developer;
    req.apiKey = apiKey;

    next();
  } catch (error) {
    console.error("API key verification error:", error);
    return res.status(401).json({
      success: false,
      message: "API key verification failed",
    });
  }
};

export { protectDeveloper, verifyApiKey };
