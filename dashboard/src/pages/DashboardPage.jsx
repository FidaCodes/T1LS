import { useState, useRef } from "react";
import { useAuth } from "../context/AuthContext";
import { threatIntelService } from "../services/authService";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { Drawer } from "../components/Drawer";
import { Navbar } from "../components/Navbar";

const DashboardPage = () => {
  const [activeTab, setActiveTab] = useState("single"); // 'single' or 'bulk'
  const [ioc, setIoc] = useState("");
  const [iocType, setIocType] = useState("auto-detect");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerData, setDrawerData] = useState(null);
  const [drawerTitle, setDrawerTitle] = useState("");

  // Bulk upload states
  const [file, setFile] = useState(null);
  const [bulkResults, setBulkResults] = useState([]);
  const [bulkProgress, setBulkProgress] = useState({ current: 0, total: 0 });
  const [bulkLoading, setBulkLoading] = useState(false);
  const fileInputRef = useRef(null);

  const { logout } = useAuth();

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!ioc.trim()) {
      setError("Please enter an IOC to analyze");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await threatIntelService.analyzeIOC(ioc.trim());
      setResult(response.data);
    } catch (err) {
      setError(
        err.response?.data?.message ||
          "Failed to analyze IOC. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const parseTxtFile = (content) => {
    return content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  };

  const parseCsvFile = (content) => {
    const lines = content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    if (lines.length < 2) {
      throw new Error(
        "CSV file must have a header row and at least one data row"
      );
    }

    const iocs = [];
    // Skip header row
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(",").map((p) => p.trim());
      if (parts.length >= 2) {
        iocs.push(parts[1]); // IOC is in the second column
      }
    }
    return iocs;
  };

  const handleFileUpload = async (e) => {
    const uploadedFile = e.target.files?.[0];
    if (!uploadedFile) return;

    const fileExtension = uploadedFile.name.split(".").pop()?.toLowerCase();
    if (!["txt", "csv"].includes(fileExtension)) {
      setError("Only TXT and CSV files are supported");
      return;
    }

    setFile(uploadedFile);
    setError("");
  };

  const handleBulkAnalysis = async () => {
    if (!file) {
      setError("Please select a file to upload");
      return;
    }

    setBulkLoading(true);
    setError("");
    setBulkResults([]);
    setBulkProgress({ current: 0, total: 0 });

    try {
      const fileContent = await file.text();
      const fileExtension = file.name.split(".").pop()?.toLowerCase();

      let iocs = [];
      if (fileExtension === "txt") {
        iocs = parseTxtFile(fileContent);
      } else if (fileExtension === "csv") {
        iocs = parseCsvFile(fileContent);
      }

      if (iocs.length === 0) {
        setError("No valid IOCs found in the file");
        setBulkLoading(false);
        return;
      }

      if (iocs.length > 10000) {
        setError("Maximum 10,000 observables per file");
        setBulkLoading(false);
        return;
      }

      setBulkProgress({ current: 0, total: iocs.length });

      const results = [];
      for (let i = 0; i < iocs.length; i++) {
        const currentIoc = iocs[i];
        setBulkProgress({ current: i + 1, total: iocs.length });

        try {
          const response = await threatIntelService.analyzeIOC(currentIoc);
          results.push({
            ioc: currentIoc,
            success: true,
            data: response.data,
          });
        } catch (err) {
          results.push({
            ioc: currentIoc,
            success: false,
            error: err.response?.data?.message || "Analysis failed",
          });
        }
      }

      setBulkResults(results);
    } catch (err) {
      setError(
        err.message || "Failed to process file. Please check the format."
      );
    } finally {
      setBulkLoading(false);
    }
  };

  const handleNewAnalysis = () => {
    setIoc("");
    setResult(null);
    setError("");
    setFile(null);
    setBulkResults([]);
    setBulkProgress({ current: 0, total: 0 });
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
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

  return (
    <div className="min-h-screen bg-[#0a1628]">
      <Navbar onLogout={logout} />

      <div className="pt-24 px-8 py-8 max-w-[1200px] mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">
            Threat Analysis
          </h1>
          <p className="text-gray-400">
            AI-powered observable analysis with multi-source intelligence
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-3 mb-8">
          <button
            onClick={() => setActiveTab("single")}
            className={`flex items-center gap-2 px-6 py-2.5 rounded-lg font-medium transition-all ${
              activeTab === "single"
                ? "bg-blue-600 text-white"
                : "bg-[#1a2942] text-gray-400 hover:bg-[#1f3149]"
            }`}
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
            Single Observable
          </button>
          <button
            onClick={() => setActiveTab("bulk")}
            className={`flex items-center gap-2 px-6 py-2.5 rounded-lg font-medium transition-all ${
              activeTab === "bulk"
                ? "bg-blue-600 text-white"
                : "bg-[#1a2942] text-gray-400 hover:bg-[#1f3149]"
            }`}
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
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
              />
            </svg>
            Bulk Upload
          </button>
        </div>

        {/* Single Observable Tab */}
        {activeTab === "single" && (
          <div className="bg-[#0f1f3a] rounded-2xl p-8">
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-300 mb-3">
                Observable Type
              </label>
              <select
                value={iocType}
                onChange={(e) => setIocType(e.target.value)}
                className="w-full bg-[#1a2942] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 transition-colors"
              >
                <option value="auto-detect">Auto-detect</option>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">File Hash</option>
              </select>
            </div>

            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-300 mb-3">
                Enter Observable
              </label>
              <input
                type="text"
                value={ioc}
                onChange={(e) => setIoc(e.target.value)}
                placeholder="e.g., 192.168.1.100, example.com, hash@email.com..."
                className="w-full bg-[#152a47] border border-gray-700 text-white rounded-lg px-4 py-3 placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
                disabled={loading}
                onKeyDown={(e) => e.key === "Enter" && handleAnalyze(e)}
              />
              <p className="mt-2 text-sm text-gray-400">
                Supported: IP addresses, Domains, URLs, Email addresses, File
                hashes (MD5, SHA1, SHA256)
              </p>
            </div>

            <button
              onClick={handleAnalyze}
              disabled={loading || !ioc.trim()}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-colors"
            >
              {loading ? (
                <>
                  <LoadingSpinner size="sm" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
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
                      d="M13 10V3L4 14h7v7l9-11h-7z"
                    />
                  </svg>
                  <span>Analyze with AI</span>
                </>
              )}
            </button>
          </div>
        )}

        {/* Bulk Upload Tab */}
        {activeTab === "bulk" && (
          <div className="bg-[#0f1f3a] rounded-2xl p-8">
            <div
              className="border-2 border-dashed border-gray-600 rounded-xl p-12 text-center hover:border-blue-500 transition-colors cursor-pointer"
              onClick={() => fileInputRef.current?.click()}
            >
              <div className="flex flex-col items-center">
                <div className="w-16 h-16 bg-blue-600/20 rounded-full flex items-center justify-center mb-4">
                  <svg
                    className="w-8 h-8 text-blue-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                    />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold text-white mb-2">
                  Upload TXT/CSV File
                </h3>
                <p className="text-gray-400 mb-4">
                  Drag and drop your file here or click to browse
                </p>
                <button className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors">
                  Choose File
                </button>
                {file && (
                  <div className="mt-4 text-sm text-green-400">
                    Selected: {file.name}
                  </div>
                )}
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.csv"
                onChange={handleFileUpload}
                className="hidden"
              />
            </div>

            <div className="mt-8 bg-[#152a47] rounded-xl p-6">
              <h4 className="text-white font-semibold mb-3">
                File Format Requirements:
              </h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-start gap-2">
                  <span className="text-blue-400 mt-1">•</span>
                  <span>Supported formats: TXT, CSV</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-400 mt-1">•</span>
                  <span>One observable per line</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-400 mt-1">•</span>
                  <span>Maximum 10,000 observables per file</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-400 mt-1">•</span>
                  <span>Supported types: IP, Domain, URL, Email, Hash</span>
                </li>
              </ul>
            </div>

            {file && (
              <button
                onClick={handleBulkAnalysis}
                disabled={bulkLoading}
                className="w-full mt-6 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-colors"
              >
                {bulkLoading ? (
                  <>
                    <LoadingSpinner size="sm" />
                    <span>
                      Processing {bulkProgress.current} of {bulkProgress.total}
                      ...
                    </span>
                  </>
                ) : (
                  <>
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
                        d="M13 10V3L4 14h7v7l9-11h-7z"
                      />
                    </svg>
                    <span>Analyze with AI</span>
                  </>
                )}
              </button>
            )}
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="mt-6 bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg flex items-start gap-2">
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

        {/* Single Analysis Results */}
        {result && activeTab === "single" && !loading && (
          <div className="mt-8 space-y-6">
            {/* Final Verdict */}
            <div className="bg-[#0f1f3a] rounded-2xl p-6 border-2 border-blue-600/30">
              <div className="flex items-start gap-4">
                {getVerdictIcon(result.final_verdict?.verdict)}
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2 flex-wrap">
                    <h3 className="text-xl font-bold text-white">
                      Final Verdict
                    </h3>
                    <Badge variant={result.final_verdict?.verdict}>
                      {result.final_verdict?.verdict || "UNKNOWN"}
                    </Badge>
                    {result.final_verdict?.confidence_score && (
                      <span className="text-sm text-gray-300">
                        {result.final_verdict.confidence_score}% Confidence
                      </span>
                    )}
                  </div>
                  <p className="text-gray-300 leading-relaxed">
                    {result.final_verdict?.reasoning ||
                      "No reasoning available"}
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
                    {result.ioc}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400 mb-1">Type</p>
                  <p className="font-semibold text-white uppercase">
                    {result.ioc_type || "Unknown"}
                  </p>
                </div>
              </div>
            </div>

            {/* Source Analysis */}
            {result.sources && Object.keys(result.sources).length > 0 && (
              <div className="bg-[#0f1f3a] rounded-2xl p-6">
                <h3 className="text-lg font-bold text-white mb-2">
                  Source Analysis
                </h3>
                <p className="text-sm text-gray-400 mb-6">
                  Click on a source to view details
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {Object.entries(result.sources).map(([source, data]) => (
                    <button
                      key={source}
                      onClick={() => handleOpenDrawer(source, data)}
                      className="text-left bg-[#152a47] border border-gray-700 rounded-xl p-4 hover:border-blue-500 transition-all duration-200"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="font-bold text-white capitalize text-sm">
                          {source.replace("_", " ")}
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
                        {data.verdict && (
                          <Badge variant={data.verdict} className="text-xs">
                            {data.verdict}
                          </Badge>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* New Analysis Button */}
            <button
              onClick={handleNewAnalysis}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-colors"
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
        )}

        {/* Bulk Analysis Results */}
        {bulkResults.length > 0 && activeTab === "bulk" && !bulkLoading && (
          <div className="mt-8 space-y-6">
            <div className="bg-[#0f1f3a] rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-xl font-bold text-white">
                    Bulk Analysis Results
                  </h3>
                  <p className="text-gray-400 text-sm mt-1">
                    Analyzed {bulkResults.length} observables
                  </p>
                </div>
                <button
                  onClick={handleNewAnalysis}
                  className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg flex items-center gap-2 transition-colors"
                >
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
                      d="M12 4v16m8-8H4"
                    />
                  </svg>
                  <span>New Analysis</span>
                </button>
              </div>

              <div className="space-y-3 max-h-[600px] overflow-y-auto">
                {bulkResults.map((item, index) => (
                  <div
                    key={index}
                    className="bg-[#152a47] rounded-xl p-4 border border-gray-700"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <p className="font-mono text-white font-semibold mb-2">
                          {item.ioc}
                        </p>
                        {item.success ? (
                          <div className="flex items-center gap-2">
                            <Badge variant={item.data.final_verdict?.verdict}>
                              {item.data.final_verdict?.verdict || "UNKNOWN"}
                            </Badge>
                            {item.data.final_verdict?.confidence_score && (
                              <span className="text-sm text-gray-400">
                                {item.data.final_verdict.confidence_score}%
                                Confidence
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-red-400 text-sm">
                            {item.error}
                          </span>
                        )}
                      </div>
                      {item.success && (
                        <button
                          onClick={() => {
                            setResult(item.data);
                            setActiveTab("single");
                            setIoc(item.ioc);
                          }}
                          className="text-blue-400 hover:text-blue-300 text-sm font-medium"
                        >
                          View Details →
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
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

export default DashboardPage;
