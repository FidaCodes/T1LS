import Developer from "../models/Developer.js";
import jwt from "jsonwebtoken";

// Generate JWT Token
const generateToken = (id) => {
  return jwt.sign({ id, type: "developer" }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};

// Register a new developer
const registerDeveloper = async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Validation
    if (!email || !password || !name) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required fields",
      });
    }

    // Check if developer exists
    const developerExists = await Developer.findOne({ email });
    if (developerExists) {
      return res.status(400).json({
        success: false,
        message: "Developer already exists with this email",
      });
    }

    // Create developer
    const developer = await Developer.create({
      email,
      password,
      name,
      credits: 100, // Initial bonus credits
    });

    // Generate token
    const token = generateToken(developer._id);

    res.status(201).json({
      success: true,
      data: {
        id: developer._id,
        name: developer.name,
        email: developer.email,
        credits: developer.credits,
        token,
      },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during registration",
    });
  }
};

// Login developer
const loginDeveloper = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide email and password",
      });
    }

    // Check for developer
    const developer = await Developer.findOne({ email });
    if (!developer) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check password
    const isMatch = await developer.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Generate token
    const token = generateToken(developer._id);

    res.json({
      success: true,
      data: {
        id: developer._id,
        name: developer.name,
        email: developer.email,
        credits: developer.credits,
        token,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during login",
    });
  }
};

// Get developer profile
const getDeveloperProfile = async (req, res) => {
  try {
    const developer = await Developer.findById(req.developer.id).select(
      "-password"
    );

    if (!developer) {
      return res.status(404).json({
        success: false,
        message: "Developer not found",
      });
    }

    res.json({
      success: true,
      data: developer,
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

// Generate API Key
const generateApiKey = async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Please provide a name for the API key",
      });
    }

    const developer = await Developer.findById(req.developer.id);

    if (!developer) {
      return res.status(404).json({
        success: false,
        message: "Developer not found",
      });
    }

    // Generate the API key
    const apiKey = developer.generateApiKey(name);
    await developer.save();

    res.status(201).json({
      success: true,
      message: "API key generated successfully",
      data: {
        key: apiKey,
        name,
        createdAt: new Date(),
      },
    });
  } catch (error) {
    console.error("Generate API key error:", error);
    res.status(500).json({
      success: false,
      message: "Server error generating API key",
    });
  }
};

// Get all API keys
const getApiKeys = async (req, res) => {
  try {
    const developer = await Developer.findById(req.developer.id).select(
      "apiKeys"
    );

    if (!developer) {
      return res.status(404).json({
        success: false,
        message: "Developer not found",
      });
    }

    res.json({
      success: true,
      data: developer.apiKeys,
    });
  } catch (error) {
    console.error("Get API keys error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

// Delete API Key
const deleteApiKey = async (req, res) => {
  try {
    const { keyId } = req.params;

    const developer = await Developer.findById(req.developer.id);

    if (!developer) {
      return res.status(404).json({
        success: false,
        message: "Developer not found",
      });
    }

    const deleted = developer.deleteApiKey(keyId);

    if (!deleted) {
      return res.status(404).json({
        success: false,
        message: "API key not found",
      });
    }

    await developer.save();

    res.json({
      success: true,
      message: "API key deleted successfully",
    });
  } catch (error) {
    console.error("Delete API key error:", error);
    res.status(500).json({
      success: false,
      message: "Server error deleting API key",
    });
  }
};

// Add credits (static - no payment processing)
const addCredits = async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid amount",
      });
    }

    const developer = await Developer.findById(req.developer.id);

    if (!developer) {
      return res.status(404).json({
        success: false,
        message: "Developer not found",
      });
    }

    developer.addCredits(amount);
    await developer.save();

    res.json({
      success: true,
      message: `${amount} credits added successfully`,
      data: {
        credits: developer.credits,
      },
    });
  } catch (error) {
    console.error("Add credits error:", error);
    res.status(500).json({
      success: false,
      message: "Server error adding credits",
    });
  }
};

// Get credits balance
const getCredits = async (req, res) => {
  try {
    const developer = await Developer.findById(req.developer.id).select(
      "credits"
    );

    if (!developer) {
      return res.status(404).json({
        success: false,
        message: "Developer not found",
      });
    }

    res.json({
      success: true,
      data: {
        credits: developer.credits,
      },
    });
  } catch (error) {
    console.error("Get credits error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

export {
  registerDeveloper,
  loginDeveloper,
  getDeveloperProfile,
  generateApiKey,
  getApiKeys,
  deleteApiKey,
  addCredits,
  getCredits,
};
