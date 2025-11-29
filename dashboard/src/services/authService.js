import api from "./api";

export const authService = {
  login: async (email, password) => {
    const response = await api.post("/auth/login", { email, password });
    return response.data;
  },

  register: async (username, email, password) => {
    const response = await api.post("/auth/register", {
      username,
      email,
      password,
    });
    return response.data;
  },

  logout: () => {
    localStorage.removeItem("token");
  },

  getToken: () => {
    return localStorage.getItem("token");
  },

  setToken: (token) => {
    localStorage.setItem("token", token);
  },

  isAuthenticated: () => {
    return !!localStorage.getItem("token");
  },
};

export const threatIntelService = {
  analyzeIOC: async (ioc) => {
    const response = await api.post("/threat-intel/analyze", { ioc });
    return response.data;
  },

  reanalyzeIOC: async (analysisId) => {
    const response = await api.post(`/threat-intel/reanalyze/${analysisId}`);
    return response.data;
  },

  getHistory: async (limit = 50, skip = 0) => {
    const response = await api.get("/threat-intel/history", {
      params: { limit, skip },
    });
    return response.data;
  },

  getAnalysisById: async (id) => {
    const response = await api.get(`/threat-intel/${id}`);
    return response.data;
  },

  deleteAnalysis: async (id) => {
    const response = await api.delete(`/threat-intel/${id}`);
    return response.data;
  },

  getStatistics: async () => {
    const response = await api.get("/threat-intel/statistics");
    return response.data;
  },

  // Add analyst feedback to an IOC analysis
  saveFeedback: async (analysisId, feedback) => {
    const response = await api.post(`/threat-intel/${analysisId}/feedback`, {
      feedback,
    });
    return response.data;
  },

  // Get feedback for a specific IOC
  getFeedback: async (ioc) => {
    const response = await api.get(
      `/threat-intel/feedback/${encodeURIComponent(ioc)}`
    );
    return response.data;
  },
};

export const schedulerService = {
  // Create a new scheduled analysis
  createSchedule: async (scheduleData) => {
    const response = await api.post("/scheduler/schedule", scheduleData);
    return response.data;
  },

  // Get all user's scheduled analyses
  getSchedules: async (includeCompleted = false) => {
    const response = await api.get("/scheduler/schedules", {
      params: { includeCompleted },
    });
    return response.data;
  },

  // Get a specific scheduled analysis
  getScheduleById: async (id) => {
    const response = await api.get(`/scheduler/schedule/${id}`);
    return response.data;
  },

  // Update a scheduled analysis
  updateSchedule: async (id, updateData) => {
    const response = await api.put(`/scheduler/schedule/${id}`, updateData);
    return response.data;
  },

  // Cancel a scheduled analysis
  cancelSchedule: async (id) => {
    const response = await api.patch(`/scheduler/schedule/${id}/cancel`);
    return response.data;
  },

  // Delete a scheduled analysis
  deleteSchedule: async (id) => {
    const response = await api.delete(`/scheduler/schedule/${id}`);
    return response.data;
  },

  // Get scheduler statistics
  getStats: async () => {
    const response = await api.get("/scheduler/stats");
    return response.data;
  },
};

export const assetIntelService = {
  // Get asset intelligence dashboard
  getDashboard: async () => {
    const response = await api.get("/asset-intel/dashboard");
    return response.data.data;
  },

  // Get all assets
  getAssets: async (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.status) params.append("status", filters.status);
    if (filters.deviceType) params.append("deviceType", filters.deviceType);
    if (filters.owner) params.append("owner", filters.owner);

    const response = await api.get(`/asset-intel/assets?${params.toString()}`);
    return response.data;
  },

  // Get single asset
  getAsset: async (id) => {
    const response = await api.get(`/asset-intel/assets/${id}`);
    return response.data.data;
  },

  // Create new asset
  createAsset: async (assetData) => {
    const response = await api.post("/asset-intel/assets", assetData);
    return response.data;
  },

  // Update asset
  updateAsset: async (id, assetData) => {
    const response = await api.put(`/asset-intel/assets/${id}`, assetData);
    return response.data;
  },

  // Delete asset
  deleteAsset: async (id) => {
    const response = await api.delete(`/asset-intel/assets/${id}`);
    return response.data;
  },

  // Get activities
  getActivities: async (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.deviceId) params.append("deviceId", filters.deviceId);
    if (filters.activityType)
      params.append("activityType", filters.activityType);
    if (filters.severity) params.append("severity", filters.severity);
    if (filters.hasThreats) params.append("hasThreats", "true");

    const response = await api.get(
      `/asset-intel/activities?${params.toString()}`
    );
    return response.data;
  },

  // Log new activity
  logActivity: async (activityData) => {
    const response = await api.post("/asset-intel/activities", activityData);
    return response.data;
  },

  // Trigger manual correlation
  correlateAll: async () => {
    const response = await api.post("/asset-intel/correlate");
    return response.data;
  },
};

export const reportService = {
  // Get available reports
  getAvailableReports: async () => {
    const response = await api.get("/reports");
    return response.data;
  },

  // Generate custom report
  generateCustomReport: async (dateRange) => {
    const response = await api.post("/reports/generate", { dateRange });
    return response.data;
  },
};

export const adminService = {
  // Get all users
  getAllUsers: async () => {
    const response = await api.get("/admin/users");
    return response.data;
  },

  // Create a new user
  createUser: async (userData) => {
    const response = await api.post("/admin/users", userData);
    return response.data;
  },

  // Update user
  updateUser: async (userId, userData) => {
    const response = await api.put(`/admin/users/${userId}`, userData);
    return response.data;
  },

  // Delete user
  deleteUser: async (userId) => {
    const response = await api.delete(`/admin/users/${userId}`);
    return response.data;
  },

  // Get audit logs
  getAuditLogs: async (limit = 100, skip = 0) => {
    const response = await api.get("/admin/audit-logs", {
      params: { limit, skip },
    });
    return response.data;
  },
};
