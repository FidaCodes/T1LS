import { useState } from "react";
import { Badge } from "./Badge";

export const Sidebar = ({
  analyses = [],
  onSelectAnalysis,
  selectedAnalysisId,
  isOpen,
  onToggle,
}) => {
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const truncateIOC = (ioc) => {
    if (ioc.length > 25) return ioc.substring(0, 25) + "...";
    return ioc;
  };

  return (
    <>
      {/* Mobile Overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={onToggle}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed lg:sticky top-16 left-0 h-[calc(100vh-4rem)]
          bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700
          transition-transform duration-300 ease-in-out z-20
          ${isOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
          w-80 flex flex-col
        `}
      >
        {/* Header */}
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              History
            </h2>
            <button
              onClick={onToggle}
              className="lg:hidden p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
            >
              <svg
                className="w-5 h-5 text-gray-500"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {analyses.length} {analyses.length === 1 ? "analysis" : "analyses"}
          </p>
        </div>

        {/* Analysis List */}
        <div className="flex-1 overflow-y-auto">
          {analyses.length === 0 ? (
            <div className="p-6 text-center">
              <svg
                className="w-12 h-12 text-gray-400 dark:text-gray-600 mx-auto mb-3"
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
              <p className="text-sm text-gray-500 dark:text-gray-400">
                No analyses yet
              </p>
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                Start by analyzing an IOC
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {analyses.map((analysis) => (
                <button
                  key={analysis._id}
                  onClick={() => onSelectAnalysis(analysis)}
                  className={`
                    w-full p-4 text-left transition-colors
                    hover:bg-gray-50 dark:hover:bg-gray-700/50
                    ${
                      selectedAnalysisId === analysis._id
                        ? "bg-cyan-50 dark:bg-cyan-900/20 border-l-4 border-cyan-600"
                        : ""
                    }
                  `}
                >
                  {/* IOC Type Badge */}
                  <div className="flex items-center gap-2 mb-2">
                    <Badge variant="info" className="text-xs">
                      {analysis.iocType}
                    </Badge>
                    <span className="text-xs text-gray-400 dark:text-gray-500">
                      {formatDate(analysis.createdAt)}
                    </span>
                  </div>

                  {/* IOC Value */}
                  <p className="font-mono text-sm text-gray-900 dark:text-white mb-2 truncate">
                    {truncateIOC(analysis.ioc)}
                  </p>

                  {/* Verdict */}
                  <div className="flex items-center gap-2">
                    <Badge variant={analysis.verdict} className="text-xs">
                      {analysis.verdict}
                    </Badge>
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {analysis.confidenceScore}% confidence
                    </span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <button
            onClick={onToggle}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition-colors"
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
                d="M11 19l-7-7 7-7m8 14l-7-7 7-7"
              />
            </svg>
            Hide Sidebar
          </button>
        </div>
      </aside>
    </>
  );
};
