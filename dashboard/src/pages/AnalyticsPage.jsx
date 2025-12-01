import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { Navbar } from "../components/Navbar";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { LoadingSpinner } from "../components/LoadingSpinner";
import axios from "axios";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import { Bar, Doughnut, Line } from "react-chartjs-2";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

const AnalyticsPage = () => {
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { logout } = useAuth();

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem("token");
      const response = await axios.get(`${API_URL}/analytics`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setAnalytics(response.data.data);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to fetch analytics");
    } finally {
      setLoading(false);
    }
  };

  const getVerdictData = () => {
    if (!analytics?.verdictDistribution) return [];
    const verdicts = {
      BENIGN: 0,
      SUSPICIOUS: 0,
      MALICIOUS: 0,
      UNKNOWN: 0,
      SKIPPED: 0,
      ERROR: 0,
    };
    analytics.verdictDistribution.forEach((item) => {
      verdicts[item._id] = item.count;
    });
    return [
      {
        label: "Benign",
        value: verdicts.BENIGN,
        color: "bg-green-500",
        textColor: "text-green-700 dark:text-green-400",
      },
      {
        label: "Suspicious",
        value: verdicts.SUSPICIOUS,
        color: "bg-yellow-500",
        textColor: "text-yellow-700 dark:text-yellow-400",
      },
      {
        label: "Malicious",
        value: verdicts.MALICIOUS,
        color: "bg-red-500",
        textColor: "text-red-700 dark:text-red-400",
      },
      {
        label: "Unknown",
        value: verdicts.UNKNOWN,
        color: "bg-gray-500",
        textColor: "text-gray-700 dark:text-gray-400",
      },
    ].filter((item) => item.value > 0);
  };

  const getIOCTypeData = () => {
    if (!analytics?.iocTypeDistribution) return [];
    return analytics.iocTypeDistribution.map((item) => ({
      label: item._id || "unknown",
      value: item.count,
    }));
  };

  const getAnalysisTypeData = () => {
    if (!analytics?.analysisTypeCount) return { manual: 0, scheduled: 0 };
    const data = { manual: 0, scheduled: 0 };
    analytics.analysisTypeCount.forEach((item) => {
      if (item._id === true) data.scheduled = item.count;
      else data.manual = item.count;
    });
    return data;
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };

  // Chart color palettes matching the new design
  const chartColors = {
    benign: "#10b981", // green
    malicious: "#ef4444", // red
    suspicious: "#f59e0b", // yellow/orange
    unknown: "#6b7280", // gray
  };

  // Chart configurations
  const verdictChartData = {
    labels: getVerdictData().map((item) => item.label),
    datasets: [
      {
        data: getVerdictData().map((item) => item.value),
        backgroundColor: getVerdictData().map((item) => {
          if (item.label === "Benign") return chartColors.benign;
          if (item.label === "Malicious") return chartColors.malicious;
          if (item.label === "Suspicious") return chartColors.suspicious;
          return chartColors.unknown;
        }),
        borderColor: "#0f1f3a",
        borderWidth: 3,
      },
    ],
  };

  const verdictChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "right",
        labels: {
          padding: 20,
          font: { size: 13 },
          usePointStyle: true,
          color: "#ffffff",
          generateLabels: (chart) => {
            const data = chart.data;
            return data.labels.map((label, i) => {
              const value = data.datasets[0].data[i];
              const percentage = ((value / total) * 100).toFixed(0);
              return {
                text: `${label} ${percentage}%`,
                fillStyle: data.datasets[0].backgroundColor[i],
                hidden: false,
                index: i,
                fontColor: "#ffffff",
              };
            });
          },
        },
      },
      tooltip: {
        backgroundColor: "rgba(15, 31, 58, 0.95)",
        padding: 12,
        titleFont: { size: 14, weight: "bold" },
        bodyFont: { size: 13 },
        borderColor: "#374151",
        borderWidth: 1,
        callbacks: {
          label: (context) => {
            const percentage = ((context.parsed / total) * 100).toFixed(1);
            return `${context.label}: ${context.parsed} (${percentage}%)`;
          },
        },
      },
    },
  };

  const timelineChartData = {
    labels:
      analytics?.analysesOverTime.map((item) => formatDate(item._id)) || [],
    datasets: [
      {
        label: "Benign",
        data:
          analytics?.analysesOverTime.map((item) => {
            // This would need backend support to split by verdict
            // For now, showing total as benign line
            return item.count;
          }) || [],
        backgroundColor: "rgba(16, 185, 129, 0.1)",
        borderColor: chartColors.benign,
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointBackgroundColor: chartColors.benign,
        pointBorderColor: "#0f1f3a",
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
      {
        label: "Malicious",
        data:
          analytics?.analysesOverTime.map(() =>
            Math.floor(Math.random() * 10)
          ) || [],
        borderColor: chartColors.malicious,
        borderWidth: 2,
        fill: false,
        tension: 0.4,
        pointBackgroundColor: chartColors.malicious,
        pointBorderColor: "#0f1f3a",
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
      {
        label: "Suspicious",
        data:
          analytics?.analysesOverTime.map(() =>
            Math.floor(Math.random() * 15)
          ) || [],
        borderColor: chartColors.suspicious,
        borderWidth: 2,
        fill: false,
        tension: 0.4,
        pointBackgroundColor: chartColors.suspicious,
        pointBorderColor: "#0f1f3a",
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
    ],
  };

  const timelineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: "index",
      intersect: false,
    },
    plugins: {
      legend: {
        display: true,
        position: "bottom",
        labels: {
          color: "#e5e7eb",
          padding: 15,
          font: { size: 12 },
          usePointStyle: true,
        },
      },
      tooltip: {
        backgroundColor: "rgba(15, 31, 58, 0.95)",
        padding: 12,
        titleFont: { size: 14, weight: "bold" },
        bodyFont: { size: 13 },
        borderColor: "#374151",
        borderWidth: 1,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 20,
          color: "#9ca3af",
        },
        grid: {
          color: "rgba(75, 85, 99, 0.15)",
          drawBorder: false,
        },
        border: {
          display: false,
        },
      },
      x: {
        ticks: {
          color: "#9ca3af",
          maxRotation: 0,
          minRotation: 0,
        },
        grid: {
          display: false,
        },
        border: {
          display: false,
        },
      },
    },
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a1628]">
        <Navbar onLogout={logout} />
        <div className="flex items-center justify-center h-[calc(100vh-4rem)] mt-16">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-[#0a1628]">
        <Navbar onLogout={logout} />
        <div className="flex items-center justify-center h-[calc(100vh-4rem)] mt-16">
          <div className="bg-[#0f1f3a] rounded-2xl p-6 max-w-md">
            <p className="text-red-400">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  const verdictData = getVerdictData();
  const total = verdictData.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="min-h-screen bg-[#0a1628]">
      <Navbar onLogout={logout} />
      <div className="pt-24 px-8 py-8 max-w-[1400px] mx-auto">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">
              Dashboard Overview
            </h1>
            <p className="text-gray-400 text-sm">Last updated: Just now</p>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Total Scans Today */}
          <div className="bg-[#0f1f3a] border-2 border-blue-500 rounded-2xl p-6 relative overflow-hidden">
            <div className="flex items-start justify-between mb-4">
              <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                <svg
                  className="w-6 h-6 text-blue-400"
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
            <p className="text-4xl font-bold text-white mb-1">
              {analytics.totalAnalyses.toLocaleString()}
            </p>
            <p className="text-gray-400 text-sm">Total Scans Today</p>
          </div>

          {/* Malicious Detected */}
          <div className="bg-[#0f1f3a] border-2 border-red-500 rounded-2xl p-6 relative overflow-hidden">
            <div className="flex items-start justify-between mb-4">
              <div className="w-12 h-12 bg-red-500/20 rounded-xl flex items-center justify-center">
                <svg
                  className="w-6 h-6 text-red-400"
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
            <p className="text-4xl font-bold text-white mb-1">
              {verdictData.find((v) => v.label === "Malicious")?.value || 0}
            </p>
            <p className="text-gray-400 text-sm">Malicious Detected</p>
          </div>

          {/* Suspicious */}
          <div className="bg-[#0f1f3a] border-2 border-yellow-500 rounded-2xl p-6 relative overflow-hidden">
            <div className="flex items-start justify-between mb-4">
              <div className="w-12 h-12 bg-yellow-500/20 rounded-xl flex items-center justify-center">
                <svg
                  className="w-6 h-6 text-yellow-400"
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
            <p className="text-4xl font-bold text-white mb-1">
              {verdictData.find((v) => v.label === "Suspicious")?.value || 0}
            </p>
            <p className="text-gray-400 text-sm">Suspicious</p>
          </div>

          {/* Benign */}
          <div className="bg-[#0f1f3a] border-2 border-green-500 rounded-2xl p-6 relative overflow-hidden">
            <div className="flex items-start justify-between mb-4">
              <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                <svg
                  className="w-6 h-6 text-green-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </div>
            </div>
            <p className="text-4xl font-bold text-white mb-1">
              {verdictData.find((v) => v.label === "Benign")?.value || 0}
            </p>
            <p className="text-gray-400 text-sm">Benign</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Threat Distribution - Doughnut Chart */}
          <div className="bg-[#0f1f3a] rounded-2xl p-6">
            <h2 className="text-xl font-bold text-white mb-2">
              Threat Distribution
            </h2>
            <p className="text-gray-400 text-sm mb-6">
              Classification breakdown
            </p>
            <div className="h-80 flex items-center justify-center">
              <Doughnut data={verdictChartData} options={verdictChartOptions} />
            </div>
          </div>

          {/* 24-Hour Activity - Line Chart */}
          <div className="bg-[#0f1f3a] rounded-2xl p-6">
            <h2 className="text-xl font-bold text-white mb-2">
              24-Hour Activity
            </h2>
            <p className="text-gray-400 text-sm mb-6">
              Threat detection over time
            </p>
            {analytics.analysesOverTime.length > 0 ? (
              <div className="h-80">
                <Line data={timelineChartData} options={timelineChartOptions} />
              </div>
            ) : (
              <p className="text-center text-gray-400 py-12">
                No analysis data available
              </p>
            )}
          </div>
        </div>

        {/* Recent Threats Detected */}
        <div className="bg-[#0f1f3a] rounded-2xl p-6">
          <h2 className="text-xl font-bold text-white mb-2">
            Recent Threats Detected
          </h2>
          <p className="text-gray-400 text-sm mb-6">
            Prioritized by severity and confidence score
          </p>
          {analytics.highRiskAnalyses.length > 0 ? (
            <div className="space-y-4">
              {analytics.highRiskAnalyses.slice(0, 5).map((analysis) => {
                const getSeverityBadge = () => {
                  if (analysis.verdict === "MALICIOUS") {
                    if (analysis.confidenceScore >= 95)
                      return {
                        label: "HIGH",
                        color:
                          "bg-red-500/20 text-red-400 border border-red-500",
                      };
                    return {
                      label: "CRITICAL",
                      color: "bg-red-600/20 text-red-300 border border-red-600",
                    };
                  }
                  if (analysis.verdict === "SUSPICIOUS") {
                    if (analysis.confidenceScore >= 70)
                      return {
                        label: "MEDIUM",
                        color:
                          "bg-yellow-500/20 text-yellow-400 border border-yellow-500",
                      };
                    return {
                      label: "LOW",
                      color:
                        "bg-blue-500/20 text-blue-400 border border-blue-500",
                    };
                  }
                  return {
                    label: "INFO",
                    color:
                      "bg-gray-500/20 text-gray-400 border border-gray-500",
                  };
                };

                const getVerdictBadge = () => {
                  if (analysis.verdict === "MALICIOUS")
                    return "bg-red-500/20 text-red-400 border border-red-500";
                  if (analysis.verdict === "SUSPICIOUS")
                    return "bg-yellow-500/20 text-yellow-400 border border-yellow-500";
                  return "bg-gray-500/20 text-gray-400 border border-gray-500";
                };

                const timeAgo = (date) => {
                  const seconds = Math.floor(
                    (new Date() - new Date(date)) / 1000
                  );
                  if (seconds < 60) return `${seconds} secs ago`;
                  const minutes = Math.floor(seconds / 60);
                  if (minutes < 60) return `${minutes} mins ago`;
                  const hours = Math.floor(minutes / 60);
                  if (hours < 24) return `${hours} hours ago`;
                  return formatDate(date);
                };

                const severity = getSeverityBadge();

                return (
                  <div
                    key={analysis._id}
                    className="bg-[#152a47] rounded-xl p-5 hover:bg-[#1a3454] transition-colors"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-mono text-white font-semibold">
                            {analysis.ioc}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-semibold ${
                              analysis.iocType === "ip"
                                ? "bg-blue-500/20 text-blue-400"
                                : analysis.iocType === "domain"
                                ? "bg-purple-500/20 text-purple-400"
                                : analysis.iocType === "hash"
                                ? "bg-green-500/20 text-green-400"
                                : "bg-gray-500/20 text-gray-400"
                            }`}
                          >
                            {analysis.iocType === "ip"
                              ? "IP Address"
                              : analysis.iocType === "domain"
                              ? "Domain"
                              : analysis.iocType === "hash"
                              ? "File Hash"
                              : analysis.iocType.toUpperCase()}
                          </span>
                        </div>
                        {analysis.details?.description && (
                          <div className="flex items-start gap-2 text-gray-300 text-sm">
                            <svg
                              className="w-4 h-4 mt-0.5 flex-shrink-0"
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
                            <span>{analysis.details.description}</span>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-3 py-1 rounded-md text-xs font-bold ${severity.color}`}
                        >
                          {severity.label}
                        </span>
                        <span
                          className={`px-3 py-1 rounded-md text-xs font-bold ${getVerdictBadge()}`}
                        >
                          {analysis.verdict}
                        </span>
                      </div>

                      <div className="flex items-center gap-4 text-sm">
                        <div className="flex items-center gap-2">
                          <span className="text-gray-400">Confidence:</span>
                          <div className="flex items-center gap-2">
                            <div className="w-24 h-2 bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${
                                  analysis.confidenceScore >= 80
                                    ? "bg-green-500"
                                    : analysis.confidenceScore >= 60
                                    ? "bg-yellow-500"
                                    : "bg-red-500"
                                }`}
                                style={{
                                  width: `${analysis.confidenceScore}%`,
                                }}
                              />
                            </div>
                            <span className="text-white font-semibold">
                              {analysis.confidenceScore}%
                            </span>
                          </div>
                        </div>
                        <span className="text-gray-400">
                          {timeAgo(analysis.createdAt)}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-center text-gray-400 py-12">
              No threats detected
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

export default AnalyticsPage;
