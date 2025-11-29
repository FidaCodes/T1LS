import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { assetIntelService } from "../services/authService";
import { Link } from "react-router-dom";
import { Navbar } from "../components/Navbar";

export const AssetIntelPage = () => {
  const [assets, setAssets] = useState([]);
  const [activities, setActivities] = useState([]);
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [filters, setFilters] = useState({
    status: "",
    deviceType: "",
    hasThreats: false,
  });
  const { logout } = useAuth();

  useEffect(() => {
    fetchData();
  }, [filters]);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [dashboardData, assetsData, activitiesData] = await Promise.all([
        assetIntelService.getDashboard(),
        assetIntelService.getAssets(filters),
        assetIntelService.getActivities({ hasThreats: filters.hasThreats }),
      ]);

      setDashboard(dashboardData);
      setAssets(assetsData.data);
      setActivities(activitiesData.data);
    } catch (error) {
      console.error("Error fetching asset intelligence data:", error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
      high: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400",
      medium:
        "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
      low: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
      info: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
    };
    return colors[severity] || colors.info;
  };

  const getStatusColor = (status) => {
    const colors = {
      active:
        "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
      inactive: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
      compromised:
        "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
      investigating:
        "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400",
    };
    return colors[status] || colors.inactive;
  };

  const getRiskScoreColor = (score) => {
    if (score >= 80) return "text-red-600 dark:text-red-400";
    if (score >= 60) return "text-orange-600 dark:text-orange-400";
    if (score >= 40) return "text-yellow-600 dark:text-yellow-400";
    return "text-green-600 dark:text-green-400";
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50 dark:bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-600"></div>
      </div>
    );
  }

  return (
    <>
      <Navbar onLogout={logout} />
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 pt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
              Asset Intelligence & Threat Correlation
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              Real-time monitoring and AI-powered threat correlation for your
              organization's assets
            </p>
          </div>

          {/* Tabs */}
          <div className="mb-6 border-b border-gray-200 dark:border-gray-700">
            <nav className="-mb-px flex space-x-8">
              {["overview", "assets", "activities", "threats"].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`py-4 px-1 border-b-2 font-medium text-sm capitalize transition-colors ${
                    activeTab === tab
                      ? "border-cyan-500 text-cyan-600 dark:text-cyan-400"
                      : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
                  }`}
                >
                  {tab}
                </button>
              ))}
            </nav>
          </div>

          {/* Overview Tab */}
          {activeTab === "overview" && dashboard && (
            <div className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Total Assets
                      </p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {dashboard.summary.totalAssets}
                      </p>
                    </div>
                    <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-full">
                      <svg
                        className="w-6 h-6 text-blue-600 dark:text-blue-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"
                        />
                      </svg>
                    </div>
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Compromised
                      </p>
                      <p className="text-2xl font-bold text-red-600 dark:text-red-400 mt-1">
                        {dashboard.summary.compromisedAssets}
                      </p>
                    </div>
                    <div className="p-3 bg-red-100 dark:bg-red-900/30 rounded-full">
                      <svg
                        className="w-6 h-6 text-red-600 dark:text-red-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                        />
                      </svg>
                    </div>
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Total Activities
                      </p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {dashboard.summary.totalActivities.toLocaleString()}
                      </p>
                    </div>
                    <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-full">
                      <svg
                        className="w-6 h-6 text-purple-600 dark:text-purple-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                        />
                      </svg>
                    </div>
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Threat Detection Rate
                      </p>
                      <p className="text-2xl font-bold text-orange-600 dark:text-orange-400 mt-1">
                        {dashboard.summary.threatPercentage}%
                      </p>
                    </div>
                    <div className="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-full">
                      <svg
                        className="w-6 h-6 text-orange-600 dark:text-orange-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M13 10V3L4 14h7v7l9-11h-7z"
                        />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>

              {/* Top Threatened Assets */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    🎯 High-Risk Assets
                  </h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead className="bg-gray-50 dark:bg-gray-900">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Device
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Owner
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Risk Score
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Threats
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Status
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                      {dashboard.topThreatenedAssets.map((asset) => (
                        <tr
                          key={asset._id}
                          className="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer"
                          onClick={() => setSelectedAsset(asset)}
                        >
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div>
                              <div className="text-sm font-medium text-gray-900 dark:text-white">
                                {asset.deviceName}
                              </div>
                              <div className="text-sm text-gray-500 dark:text-gray-400">
                                {asset.deviceId}
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                            {asset.owner}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              <span
                                className={`text-2xl font-bold ${getRiskScoreColor(
                                  asset.riskScore
                                )}`}
                              >
                                {Math.round(asset.riskScore)}
                              </span>
                              <span className="text-sm text-gray-500 dark:text-gray-400 ml-1">
                                /100
                              </span>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                            {asset.threatIndicators.length} indicators
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span
                              className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getStatusColor(
                                asset.status
                              )}`}
                            >
                              {asset.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Recent Threat Correlations */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    ⚡ Recent Threat Correlations
                  </h2>
                </div>
                <div className="p-6 space-y-4">
                  {dashboard.recentCorrelations.map((activity) => (
                    <div
                      key={activity._id}
                      className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:border-cyan-500 transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span
                              className={`px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(
                                activity.severity
                              )}`}
                            >
                              {activity.severity.toUpperCase()}
                            </span>
                            <span className="text-sm text-gray-600 dark:text-gray-400">
                              {activity.activityType.replace(/-/g, " ")}
                            </span>
                          </div>
                          <p className="text-sm text-gray-900 dark:text-white mb-2">
                            {activity.description}
                          </p>
                          <div className="flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
                            <span>
                              Device:{" "}
                              {activity.assetId?.deviceName || "Unknown"}
                            </span>
                            <span>
                              Owner: {activity.assetId?.owner || "Unknown"}
                            </span>
                            <span>
                              {new Date(activity.createdAt).toLocaleString()}
                            </span>
                          </div>
                          {activity.correlatedThreats.length > 0 && (
                            <div className="mt-3 space-y-2">
                              {activity.correlatedThreats.map((threat, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-center gap-2 text-xs bg-red-50 dark:bg-red-900/20 p-2 rounded"
                                >
                                  <span className="font-semibold text-red-600 dark:text-red-400">
                                    🚨 {threat.iocType.toUpperCase()}:
                                  </span>
                                  <code className="text-red-900 dark:text-red-300">
                                    {threat.ioc}
                                  </code>
                                  <span className="text-gray-600 dark:text-gray-400">
                                    ({threat.confidence}% confidence)
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Assets Tab */}
          {activeTab === "assets" && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  All Assets
                </h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-900">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Device
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Type
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Owner
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        IP Address
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Risk
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    {assets.map((asset) => (
                      <tr
                        key={asset._id}
                        className="hover:bg-gray-50 dark:hover:bg-gray-700"
                      >
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div className="text-sm font-medium text-gray-900 dark:text-white">
                              {asset.deviceName}
                            </div>
                            <div className="text-sm text-gray-500 dark:text-gray-400">
                              {asset.deviceId}
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                          {asset.deviceType}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                          {asset.owner}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                          {asset.ipAddress || "N/A"}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span
                            className={`text-lg font-bold ${getRiskScoreColor(
                              asset.riskScore
                            )}`}
                          >
                            {Math.round(asset.riskScore)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span
                            className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getStatusColor(
                              asset.status
                            )}`}
                          >
                            {asset.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Activities Tab */}
          {activeTab === "activities" && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Activity Timeline
                </h2>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={filters.hasThreats}
                    onChange={(e) =>
                      setFilters({ ...filters, hasThreats: e.target.checked })
                    }
                    className="rounded border-gray-300 text-cyan-600 focus:ring-cyan-500"
                  />
                  <span className="text-gray-700 dark:text-gray-300">
                    Show only threats
                  </span>
                </label>
              </div>
              <div className="p-6 space-y-4">
                {activities.map((activity) => (
                  <div
                    key={activity._id}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg p-4"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <span
                            className={`px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(
                              activity.severity
                            )}`}
                          >
                            {activity.severity}
                          </span>
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {activity.activityType.replace(/-/g, " ")}
                          </span>
                        </div>
                        <p className="text-sm text-gray-700 dark:text-gray-300 mb-2">
                          {activity.description}
                        </p>
                        <div className="flex flex-wrap items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
                          {activity.assetId && (
                            <>
                              <span>Device: {activity.assetId.deviceName}</span>
                              <span>Owner: {activity.assetId.owner}</span>
                            </>
                          )}
                          {activity.sourceIp && (
                            <span>Source: {activity.sourceIp}</span>
                          )}
                          {activity.destinationIp && (
                            <span>Dest: {activity.destinationIp}</span>
                          )}
                          <span>
                            {new Date(activity.createdAt).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Threats Tab */}
          {activeTab === "threats" && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Threat Intelligence Integration
              </h2>
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                This system automatically correlates asset activities with IOC
                analyses from your threat intelligence platform. When suspicious
                activities are detected, they are cross-referenced with known
                malicious indicators.
              </p>
              <div className="grid md:grid-cols-2 gap-6">
                <div className="border border-cyan-200 dark:border-cyan-800 rounded-lg p-4 bg-cyan-50 dark:bg-cyan-900/20">
                  <h3 className="font-semibold text-cyan-900 dark:text-cyan-300 mb-2">
                    ✨ AI-Powered Correlation
                  </h3>
                  <p className="text-sm text-cyan-800 dark:text-cyan-400">
                    Activities are automatically checked against your threat
                    intel database. IP addresses, domains, URLs, and file hashes
                    are correlated in real-time.
                  </p>
                </div>
                <div className="border border-purple-200 dark:border-purple-800 rounded-lg p-4 bg-purple-50 dark:bg-purple-900/20">
                  <h3 className="font-semibold text-purple-900 dark:text-purple-300 mb-2">
                    🎯 Risk Scoring
                  </h3>
                  <p className="text-sm text-purple-800 dark:text-purple-400">
                    Assets receive dynamic risk scores based on threat
                    correlations. High-risk assets are automatically flagged for
                    investigation.
                  </p>
                </div>
              </div>
              <div className="mt-6">
                <Link
                  to="/dashboard"
                  className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors"
                >
                  <svg
                    className="w-5 h-5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                    />
                  </svg>
                  Analyze New IOC
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
};
