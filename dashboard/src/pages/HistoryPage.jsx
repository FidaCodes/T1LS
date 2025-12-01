import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { threatIntelService } from "../services/authService";
import { Navbar } from "../components/Navbar";
import { Badge } from "../components/Badge";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { useNavigate } from "react-router-dom";

const HistoryPage = () => {
  const [analyses, setAnalyses] = useState([]);
  const [filteredAnalyses, setFilteredAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [classificationFilter, setClassificationFilter] = useState("all");
  const { logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    fetchAnalysisHistory();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [searchQuery, typeFilter, classificationFilter, analyses]);

  const fetchAnalysisHistory = async () => {
    try {
      setLoading(true);
      const response = await threatIntelService.getHistory();
      setAnalyses(response.data.analyses);
      setFilteredAnalyses(response.data.analyses);
    } catch (err) {
      setError(
        err.response?.data?.message || "Failed to fetch analysis history"
      );
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...analyses];

    // Search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (analysis) =>
          analysis.ioc.toLowerCase().includes(query) ||
          analysis.iocType.toLowerCase().includes(query) ||
          (analysis.details?.description &&
            analysis.details.description.toLowerCase().includes(query))
      );
    }

    // Type filter
    if (typeFilter !== "all") {
      filtered = filtered.filter(
        (analysis) =>
          analysis.iocType.toLowerCase() === typeFilter.toLowerCase()
      );
    }

    // Classification filter
    if (classificationFilter !== "all") {
      filtered = filtered.filter(
        (analysis) => analysis.verdict === classificationFilter
      );
    }

    setFilteredAnalyses(filtered);
  };

  const handleDelete = async (id) => {
    if (window.confirm("Are you sure you want to delete this analysis?")) {
      try {
        await threatIntelService.deleteAnalysis(id);
        setAnalyses(analyses.filter((a) => a._id !== id));
      } catch (err) {
        console.error("Failed to delete analysis:", err);
      }
    }
  };

  const handleCopyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
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

  const getSeverityBadge = (verdict, confidence) => {
    if (verdict === "MALICIOUS") {
      if (confidence >= 95)
        return {
          label: "HIGH",
          color: "bg-red-500/20 text-red-400 border border-red-500",
        };
      return {
        label: "CRITICAL",
        color: "bg-red-600/20 text-red-300 border border-red-600",
      };
    }
    if (verdict === "SUSPICIOUS") {
      if (confidence >= 70)
        return {
          label: "MEDIUM",
          color: "bg-yellow-500/20 text-yellow-400 border border-yellow-500",
        };
      return {
        label: "MEDIUM",
        color: "bg-yellow-500/20 text-yellow-400 border border-yellow-500",
      };
    }
    if (verdict === "BENIGN") {
      return {
        label: "LOW",
        color: "bg-green-500/20 text-green-400 border border-green-500",
      };
    }
    return {
      label: "LOW",
      color: "bg-gray-500/20 text-gray-400 border border-gray-500",
    };
  };

  const exportHistory = () => {
    const csvContent = [
      [
        "Observable",
        "Type",
        "Classification",
        "Confidence",
        "Severity",
        "Sources",
        "Timestamp",
        "Description",
      ],
      ...filteredAnalyses.map((analysis) => {
        const severity = getSeverityBadge(
          analysis.verdict,
          analysis.confidenceScore
        );
        const sourcesCount =
          analysis.sources && typeof analysis.sources === "object"
            ? Object.keys(analysis.sources).length
            : 0;
        return [
          analysis.ioc,
          analysis.iocType,
          analysis.verdict,
          `${analysis.confidenceScore}%`,
          severity.label,
          sourcesCount,
          formatTimestamp(analysis.createdAt),
          analysis.details?.description || "",
        ];
      }),
    ]
      .map((row) => row.map((cell) => `"${cell}"`).join(","))
      .join("\n");

    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `analysis-history-${
      new Date().toISOString().split("T")[0]
    }.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
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

  return (
    <div className="min-h-screen bg-[#0a1628]">
      <Navbar onLogout={logout} />

      <div className="pt-24 px-8 py-8 max-w-[1600px] mx-auto">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">
              Analysis History
            </h1>
            <p className="text-gray-400">
              Complete record of all past scans and searches
            </p>
          </div>
          <button
            onClick={exportHistory}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2.5 px-5 rounded-lg transition-colors"
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
                d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
            Export History
          </button>
        </div>

        {/* Search and Filters */}
        <div className="mb-6 flex gap-4 items-center">
          <div className="flex-1 relative">
            <svg
              className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500"
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
            <input
              type="text"
              placeholder="Search by observable, reason, or any keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#0f1f3a] border border-gray-700 text-white rounded-lg pl-12 pr-4 py-3 placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>

          <div className="flex items-center gap-2">
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
                d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"
              />
            </svg>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-[#0f1f3a] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 transition-colors min-w-[150px]"
            >
              <option value="all">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="email">Email</option>
              <option value="hash">Hash</option>
            </select>

            <select
              value={classificationFilter}
              onChange={(e) => setClassificationFilter(e.target.value)}
              className="bg-[#0f1f3a] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 transition-colors min-w-[200px]"
            >
              <option value="all">All Classifications</option>
              <option value="MALICIOUS">Malicious</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="BENIGN">Benign</option>
              <option value="UNKNOWN">Unknown</option>
            </select>
          </div>
        </div>

        {/* Stats */}
        <div className="mb-6 bg-[#0f1f3a] rounded-xl p-6 flex gap-8">
          <div>
            <p className="text-sm text-gray-400 mb-1">Total Scans</p>
            <p className="text-2xl font-bold text-blue-400">
              {analyses.length}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">Filtered Results</p>
            <p className="text-2xl font-bold text-blue-400">
              {filteredAnalyses.length}
            </p>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="mb-6 bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg flex items-start gap-2">
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
            <span>{error}</span>
          </div>
        )}

        {/* Table */}
        <div className="bg-[#0f1f3a] rounded-xl overflow-hidden">
          {filteredAnalyses.length === 0 ? (
            <div className="text-center py-16">
              <svg
                className="w-16 h-16 text-gray-600 mx-auto mb-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                />
              </svg>
              <p className="text-gray-400 text-lg">No analysis records found</p>
              <p className="text-gray-500 text-sm mt-2">
                Try adjusting your search or filters
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-4 px-6 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Observable
                    </th>
                    <th className="text-left py-4 px-6 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="text-left py-4 px-6 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Classification
                    </th>
                    <th className="text-left py-4 px-6 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Confidence
                    </th>
                    <th className="text-left py-4 px-6 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="text-left py-4 px-6 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Sources
                    </th>
                    <th className="text-left py-4 px-6 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Timestamp
                    </th>
                    <th className="text-left py-4 px-6 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredAnalyses.map((analysis) => {
                    const severity = getSeverityBadge(
                      analysis.verdict,
                      analysis.confidenceScore
                    );
                    return (
                      <tr
                        key={analysis._id}
                        className="hover:bg-[#152a47] transition-colors"
                      >
                        <td className="py-4 px-6">
                          <div>
                            <p className="font-mono text-white font-medium">
                              {analysis.ioc}
                            </p>
                            {analysis.details?.description && (
                              <p className="text-sm text-gray-400 mt-1">
                                {analysis.details.description}
                              </p>
                            )}
                          </div>
                        </td>
                        <td className="py-4 px-6">
                          <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-gray-700 text-gray-300">
                            {analysis.iocType}
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <Badge variant={analysis.verdict} className="text-xs">
                            {analysis.verdict}
                          </Badge>
                        </td>
                        <td className="py-4 px-6">
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
                            <span className="text-sm text-white font-medium">
                              {analysis.confidenceScore}%
                            </span>
                          </div>
                        </td>
                        <td className="py-4 px-6">
                          <span
                            className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-bold ${severity.color}`}
                          >
                            {severity.label}
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <span className="text-sm text-gray-300">
                            {analysis.sources &&
                            typeof analysis.sources === "object"
                              ? Object.keys(analysis.sources).length
                              : 0}{" "}
                            sources
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <div className="flex items-center gap-1 text-sm text-gray-400">
                            <svg
                              className="w-4 h-4"
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                              />
                            </svg>
                            <span>{formatTimestamp(analysis.createdAt)}</span>
                          </div>
                        </td>
                        <td className="py-4 px-6">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() =>
                                navigate(`/history/${analysis._id}`)
                              }
                              className="p-2 hover:bg-blue-900/30 rounded-lg transition-colors"
                              title="View details"
                            >
                              <svg
                                className="w-4 h-4 text-gray-400 hover:text-blue-400"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                                />
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                                />
                              </svg>
                            </button>
                            <button
                              onClick={() =>
                                handleCopyToClipboard(analysis.ioc)
                              }
                              className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
                              title="Copy to clipboard"
                            >
                              <svg
                                className="w-4 h-4 text-gray-400 hover:text-white"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                />
                              </svg>
                            </button>
                            <button
                              onClick={() => handleDelete(analysis._id)}
                              className="p-2 hover:bg-red-900/30 rounded-lg transition-colors"
                              title="Delete"
                            >
                              <svg
                                className="w-4 h-4 text-gray-400 hover:text-red-400"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                                />
                              </svg>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default HistoryPage;
