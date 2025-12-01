import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { threatIntelService } from "../services/authService";
import { Badge } from "../components/Badge";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { Drawer } from "../components/Drawer";
import { Navbar } from "../components/Navbar";

const HistoryDetailsPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { logout } = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerData, setDrawerData] = useState(null);
  const [drawerTitle, setDrawerTitle] = useState("");

  useEffect(() => {
    fetchAnalysisDetails();
  }, [id]);

  const fetchAnalysisDetails = async () => {
    try {
      setLoading(true);
      const response = await threatIntelService.getAnalysisById(id);
      setAnalysis(response.data);
    } catch (err) {
      setError(
        err.response?.data?.message || "Failed to fetch analysis details"
      );
    } finally {
      setLoading(false);
    }
  };

  const handleOpenDrawer = (sourceName, sourceData) => {
    setDrawerTitle(sourceName.replace("_", " ").toUpperCase());
    setDrawerData(sourceData);
    setDrawerOpen(true);
  };

  const handleCloseDrawer = () => {
    setDrawerOpen(false);
    setDrawerData(null);
    setDrawerTitle("");
  };

  const getVerdictIcon = (verdict) => {
    switch (verdict) {
      case "BENIGN":
        return (
          <svg
            className="w-6 h-6 text-green-500"
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
        );
      case "MALICIOUS":
        return (
          <svg
            className="w-6 h-6 text-red-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
        );
      case "SUSPICIOUS":
        return (
          <svg
            className="w-6 h-6 text-yellow-500"
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
        );
      default:
        return (
          <svg
            className="w-6 h-6 text-gray-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
        );
    }
  };

  const formatTimestamp = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString("en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
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

  if (error || !analysis) {
    return (
      <div className="min-h-screen bg-[#0a1628]">
        <Navbar onLogout={logout} />
        <div className="pt-24 px-8 py-8 max-w-[1200px] mx-auto">
          <div className="bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg flex items-start gap-2">
            <svg
              className="w-5 h-5 mt-0.5 flex-shrink-0"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <span>{error || "Analysis not found"}</span>
          </div>
          <button
            onClick={() => navigate("/history")}
            className="mt-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg transition-colors"
          >
            ← Back to History
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a1628]">
      <Navbar onLogout={logout} />

      <div className="pt-24 px-8 py-8 max-w-[1200px] mx-auto">
        {/* Header with Back Button */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <button
              onClick={() => navigate("/history")}
              className="flex items-center gap-2 text-blue-400 hover:text-blue-300 mb-4 transition-colors"
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
                  d="M15 19l-7-7 7-7"
                />
              </svg>
              <span>Back to History</span>
            </button>
            <h1 className="text-3xl font-bold text-white mb-2">
              Analysis Details
            </h1>
            <p className="text-gray-400">
              Detailed threat intelligence for{" "}
              <span className="font-mono text-blue-400">{analysis.ioc}</span>
            </p>
          </div>
        </div>

        {/* Analysis Results */}
        <div className="space-y-6">
          {/* Final Verdict */}
          <div className="bg-[#0f1f3a] rounded-2xl p-6 border-2 border-blue-600/30">
            <div className="flex items-start gap-4">
              {getVerdictIcon(analysis.verdict)}
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2 flex-wrap">
                  <h3 className="text-xl font-bold text-white">
                    Final Verdict
                  </h3>
                  <Badge variant={analysis.verdict}>
                    {analysis.verdict || "UNKNOWN"}
                  </Badge>
                  {analysis.confidenceScore && (
                    <span className="text-sm text-gray-300">
                      {analysis.confidenceScore}% Confidence
                    </span>
                  )}
                </div>
                <p className="text-gray-300 leading-relaxed">
                  {analysis.reasoning || "No reasoning available"}
                </p>
              </div>
            </div>
          </div>

          {/* IOC Details */}
          <div className="bg-[#0f1f3a] rounded-2xl p-6">
            <h3 className="text-lg font-bold text-white mb-4">IOC Details</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-400 mb-1">Indicator</p>
                <p className="font-mono font-semibold text-white break-all">
                  {analysis.ioc}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-400 mb-1">Type</p>
                <p className="font-semibold text-white uppercase">
                  {analysis.iocType || "Unknown"}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-400 mb-1">Analyzed At</p>
                <p className="font-semibold text-white">
                  {formatTimestamp(analysis.createdAt)}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-400 mb-1">Sources Checked</p>
                <p className="font-semibold text-white">
                  {analysis.sources && typeof analysis.sources === "object"
                    ? Object.keys(analysis.sources).length
                    : 0}{" "}
                  sources
                </p>
              </div>
            </div>
          </div>

          {/* Source Analysis */}
          {analysis.sources && Object.keys(analysis.sources).length > 0 && (
            <div className="bg-[#0f1f3a] rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-2">
                Source Analysis
              </h3>
              <p className="text-sm text-gray-400 mb-6">
                Click on a source to view details
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(analysis.sources).map(
                  ([sourceName, sourceData]) => (
                    <button
                      key={sourceName}
                      onClick={() => handleOpenDrawer(sourceName, sourceData)}
                      className="text-left bg-[#152a47] border border-gray-700 rounded-xl p-4 hover:border-blue-500 transition-all duration-200"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="font-bold text-white capitalize text-sm">
                          {sourceName.replace("_", " ")}
                        </h4>
                        <svg
                          className="w-5 h-5 text-gray-400"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M9 5l7 7-7 7"
                          />
                        </svg>
                      </div>
                      <div className="flex items-center justify-center">
                        {sourceData.verdict && (
                          <Badge
                            variant={sourceData.verdict}
                            className="text-xs"
                          >
                            {sourceData.verdict}
                          </Badge>
                        )}
                      </div>
                    </button>
                  )
                )}
              </div>
            </div>
          )}

          {/* Additional Details if available */}
          {analysis.details && (
            <div className="bg-[#0f1f3a] rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-4">
                Additional Information
              </h3>
              {analysis.details.description && (
                <div className="mb-4">
                  <p className="text-sm text-gray-400 mb-1">Description</p>
                  <p className="text-gray-300">
                    {analysis.details.description}
                  </p>
                </div>
              )}
              {analysis.details.tags && analysis.details.tags.length > 0 && (
                <div>
                  <p className="text-sm text-gray-400 mb-2">Tags</p>
                  <div className="flex flex-wrap gap-2">
                    {analysis.details.tags.map((tag, index) => (
                      <span
                        key={index}
                        className="bg-gray-700 text-gray-300 px-3 py-1 rounded-full text-sm"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex gap-4">
            <button
              onClick={() => navigate("/history")}
              className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-colors"
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
                  d="M15 19l-7-7 7-7"
                />
              </svg>
              <span>Back to History</span>
            </button>
            <button
              onClick={() => navigate("/dashboard")}
              className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-colors"
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
                  d="M12 4v16m8-8H4"
                />
              </svg>
              <span>New Analysis</span>
            </button>
          </div>
        </div>
      </div>

      {/* Drawer for Source Details */}
      <Drawer
        isOpen={drawerOpen}
        onClose={handleCloseDrawer}
        data={drawerData}
        title={drawerTitle}
      />
    </div>
  );
};

export default HistoryDetailsPage;
