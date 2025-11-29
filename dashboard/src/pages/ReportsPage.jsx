import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { reportService } from "../services/authService";
import { Navbar } from "../components/Navbar";
import { LoadingSpinner } from "../components/LoadingSpinner";

const ReportsPage = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reportTypeFilter, setReportTypeFilter] = useState("all");
  const [dateFilter, setDateFilter] = useState("30days");
  const [generatingCustom, setGeneratingCustom] = useState(false);
  const { logout } = useAuth();

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      setLoading(true);
      const response = await reportService.getAvailableReports();
      setReports(response.data);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to fetch reports");
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateCustomReport = async () => {
    try {
      setGeneratingCustom(true);
      setError("");

      const response = await reportService.generateCustomReport(dateFilter);
      const { report } = response.data;

      // Refresh the reports list to include the new report
      await fetchReports();

      // Show success message
      alert(
        `Custom report generated successfully!\n\nTotal Scans: ${report.stats.totalScans}\nMalicious: ${report.stats.malicious}\nSuspicious: ${report.stats.suspicious}\nBenign: ${report.stats.benign}\nUnknown: ${report.stats.unknown}`
      );
    } catch (err) {
      setError(
        err.response?.data?.message || "Failed to generate custom report"
      );
    } finally {
      setGeneratingCustom(false);
    }
  };

  const handleDownloadReport = async (report) => {
    try {
      let analyses;

      // If report has data (custom generated report), use it
      if (report.data) {
        analyses = report.data;
      } else {
        // Otherwise, fetch data for predefined reports
        const response = await reportService.generateCustomReport("30days");
        analyses = response.data.analyses;
      }

      // Create CSV content
      const csvContent = [
        [
          "IOC",
          "Type",
          "Verdict",
          "Confidence Score",
          "Timestamp",
          "Description",
        ],
        ...analyses.map((analysis) => [
          analysis.ioc,
          analysis.iocType,
          analysis.verdict,
          `${analysis.confidenceScore}%`,
          new Date(analysis.timestamp).toLocaleString(),
          analysis.description,
        ]),
      ]
        .map((row) => row.map((cell) => `"${cell}"`).join(","))
        .join("\n");

      // Download CSV
      const blob = new Blob([csvContent], { type: "text/csv" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${report.type.toLowerCase().replace(/\s+/g, "-")}-${
        report.date
      }.csv`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to download report");
    }
  };

  const filteredReports = reports.filter((report) => {
    if (reportTypeFilter === "all") return true;
    return report.type.toLowerCase().includes(reportTypeFilter.toLowerCase());
  });

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

      <div className="pt-24 px-8 py-8 max-w-[1400px] mx-auto">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">
              Reports & Analytics
            </h1>
            <p className="text-gray-400">
              Download comprehensive analysis reports
            </p>
          </div>
          <button
            onClick={handleGenerateCustomReport}
            disabled={generatingCustom}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-semibold py-2.5 px-5 rounded-lg transition-colors"
          >
            {generatingCustom ? (
              <>
                <LoadingSpinner size="sm" />
                <span>Generating...</span>
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
                    d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                  />
                </svg>
                Generate Custom Report
              </>
            )}
          </button>
        </div>

        {/* Filters */}
        <div className="mb-6 flex gap-4 items-center">
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
              value={reportTypeFilter}
              onChange={(e) => setReportTypeFilter(e.target.value)}
              className="bg-[#0f1f3a] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 transition-colors min-w-[180px]"
            >
              <option value="all">All Report Types</option>
              <option value="weekly">Weekly Summary</option>
              <option value="monthly">Monthly Report</option>
              <option value="quarterly">Quarterly Report</option>
              <option value="daily">Daily Summary</option>
            </select>

            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="bg-[#0f1f3a] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 transition-colors min-w-[150px]"
            >
              <option value="7days">Last 7 Days</option>
              <option value="30days">Last 30 Days</option>
            </select>
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

        {/* Reports List */}
        <div className="space-y-4">
          {filteredReports.length === 0 ? (
            <div className="bg-[#0f1f3a] rounded-xl p-16 text-center">
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
              <p className="text-gray-400 text-lg">No reports available</p>
              <p className="text-gray-500 text-sm mt-2">
                Generate a custom report to get started
              </p>
            </div>
          ) : (
            filteredReports.map((report, index) => (
              <div
                key={index}
                className="bg-[#0f1f3a] rounded-xl p-6 hover:bg-[#152a47] transition-colors"
              >
                <div className="flex items-center gap-6">
                  {/* Icon */}
                  <div className="w-16 h-16 bg-blue-600/20 rounded-xl flex items-center justify-center flex-shrink-0">
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
                        d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                      />
                    </svg>
                  </div>

                  {/* Content */}
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-white mb-2">
                      {report.title}
                    </h3>
                    <div className="flex items-center gap-6 text-sm text-gray-400">
                      <div className="flex items-center gap-1">
                        <span className="font-medium">{report.type}</span>
                      </div>
                      <div className="flex items-center gap-1">
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
                            d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"
                          />
                        </svg>
                        <span>{report.period}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <span>{report.fileSize}</span>
                      </div>
                    </div>

                    {/* Stats */}
                    <div className="mt-4 flex items-center gap-6">
                      <div>
                        <p className="text-xs text-gray-500 uppercase">
                          Total Scans
                        </p>
                        <p className="text-lg font-bold text-blue-400">
                          {report.totalScans.toLocaleString()}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500 uppercase">
                          Malicious
                        </p>
                        <p className="text-lg font-bold text-red-400">
                          {report.malicious.toLocaleString()}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500 uppercase">
                          Suspicious
                        </p>
                        <p className="text-lg font-bold text-yellow-400">
                          {report.suspicious.toLocaleString()}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500 uppercase">
                          Benign
                        </p>
                        <p className="text-lg font-bold text-green-400">
                          {report.benign.toLocaleString()}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Download Button */}
                  <button
                    onClick={() => handleDownloadReport(report)}
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
                    Download CSV
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default ReportsPage;
