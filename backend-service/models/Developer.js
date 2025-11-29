import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const apiKeySchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true,
  },
  name: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  lastUsed: {
    type: Date,
    default: null,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
});

const developerSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  name: {
    type: String,
    required: true,
  },
  credits: {
    type: Number,
    default: 0,
    min: 0,
  },
  apiKeys: [apiKeySchema],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Hash password before saving
developerSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
developerSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Method to generate API key
developerSchema.methods.generateApiKey = function (name) {
  const apiKey = "dev_" + crypto.randomBytes(32).toString("hex");

  this.apiKeys.push({
    key: apiKey,
    name: name || "Unnamed Key",
    createdAt: new Date(),
    isActive: true,
  });

  return apiKey;
};

// Method to deactivate API key
developerSchema.methods.deactivateApiKey = function (keyId) {
  const apiKey = this.apiKeys.id(keyId);
  if (apiKey) {
    apiKey.isActive = false;
    return true;
  }
  return false;
};

// Method to delete API key
developerSchema.methods.deleteApiKey = function (keyId) {
  const apiKey = this.apiKeys.id(keyId);
  if (apiKey) {
    apiKey.remove();
    return true;
  }
  return false;
};

// Method to add credits
developerSchema.methods.addCredits = function (amount) {
  this.credits += amount;
};

// Method to deduct credits
developerSchema.methods.deductCredits = function (amount) {
  if (this.credits >= amount) {
    this.credits -= amount;
    return true;
  }
  return false;
};

const Developer = mongoose.model("Developer", developerSchema);
export default Developer;
