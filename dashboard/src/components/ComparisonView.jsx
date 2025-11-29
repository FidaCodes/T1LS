import { Badge } from "./Badge";
import { Card } from "./Card";

export const ComparisonView = ({ comparison, oldAnalysis, newAnalysis }) => {
  if (!comparison) {
    return null;
  }

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const getRiskBadgeVariant = (risk) => {
    switch (risk) {
      case "INCREASED":
        return "MALICIOUS";
      case "DECREASED":
        return "BENIGN";
      default:
        return "info";
    }
  };

  const getVerdictChangeIcon = () => {
    const { verdict_changed, risk_assessment } = comparison.comparison;

    if (!verdict_changed && risk_assessment === "UNCHANGED") {
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
            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
          />
        </svg>
      );
    }

    if (risk_assessment === "INCREASED") {
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
            d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"
          />
        </svg>
      );
    }

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
          d="M13 17h8m0 0V9m0 8l-8-8-4 4-6-6"
        />
      </svg>
    );
  };

  return (
    <div className="space-y-6">
      {/* Comparison Header */}
      <Card className="border-2 border-blue-200 dark:border-blue-900/30">
        <div className="flex items-start gap-4">
          {getVerdictChangeIcon()}
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-3">
              <h3 className="text-xl font-bold text-gray-900 dark:text-white">
                Analysis Comparison
              </h3>
              <Badge
                variant={getRiskBadgeVariant(
                  comparison.comparison.risk_assessment
                )}
              >
                {comparison.comparison.risk_assessment}
              </Badge>
            </div>

            {/* Verdict Comparison */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div className="bg-gray-50 dark:bg-gray-700/30 rounded-lg p-4">
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                  Previous Analysis (
                  {formatDate(comparison.old_analysis_timestamp)})
                </p>
                <div className="flex items-center gap-2">
                  <Badge variant={comparison.comparison.old_verdict}>
                    {comparison.comparison.old_verdict}
                  </Badge>
                  <span className="text-sm text-gray-600 dark:text-gray-300">
                    {comparison.comparison.old_confidence}% confidence
                  </span>
                </div>
              </div>

              <div className="bg-gray-50 dark:bg-gray-700/30 rounded-lg p-4">
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                  New Analysis ({formatDate(comparison.new_analysis_timestamp)})
                </p>
                <div className="flex items-center gap-2">
                  <Badge variant={comparison.comparison.new_verdict}>
                    {comparison.comparison.new_verdict}
                  </Badge>
                  <span className="text-sm text-gray-600 dark:text-gray-300">
                    {comparison.comparison.new_confidence}% confidence
                  </span>
                  {comparison.comparison.confidence_change !== 0 && (
                    <span
                      className={`text-xs font-semibold ${
                        comparison.comparison.confidence_change > 0
                          ? "text-red-600 dark:text-red-400"
                          : "text-green-600 dark:text-green-400"
                      }`}
                    >
                      {comparison.comparison.confidence_change > 0 ? "+" : ""}
                      {comparison.comparison.confidence_change}%
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Change Summary */}
            <div className="flex flex-wrap gap-4 text-sm">
              <div>
                <span className="text-gray-500 dark:text-gray-400">
                  Sources Analyzed:
                </span>
                <span className="ml-2 font-semibold text-gray-900 dark:text-white">
                  {comparison.comparison.sources_analyzed}
                </span>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">
                  Sources Changed:
                </span>
                <span className="ml-2 font-semibold text-gray-900 dark:text-white">
                  {comparison.comparison.sources_changed}
                </span>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* AI Insights */}
      <Card>
        <h4 className="text-lg font-bold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
          <svg
            className="w-5 h-5 text-cyan-600 dark:text-cyan-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
            />
          </svg>
          AI-Powered Insights
        </h4>
        <div className="prose prose-sm dark:prose-invert max-w-none">
          <p className="text-gray-700 dark:text-gray-300 whitespace-pre-line leading-relaxed">
            {comparison.ai_insights}
          </p>
        </div>
      </Card>

      {/* Source-Level Changes */}
      {comparison.comparison.source_changes &&
        Object.keys(comparison.comparison.source_changes).length > 0 && (
          <Card>
            <h4 className="text-lg font-bold text-gray-900 dark:text-white mb-4">
              Source-Level Changes
            </h4>
            <div className="space-y-3">
              {Object.entries(comparison.comparison.source_changes).map(
                ([source, change]) => (
                  <div
                    key={source}
                    className={`flex items-center justify-between p-3 rounded-lg ${
                      change.changed
                        ? "bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800"
                        : "bg-gray-50 dark:bg-gray-700/30"
                    }`}
                  >
                    <span className="font-semibold text-gray-900 dark:text-white capitalize">
                      {source.replace("_", " ")}
                    </span>
                    <div className="flex items-center gap-2">
                      {change.changed ? (
                        <>
                          <Badge
                            variant={change.old_verdict}
                            className="text-xs"
                          >
                            {change.old_verdict}
                          </Badge>
                          <svg
                            className="w-4 h-4 text-gray-400"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M13 7l5 5m0 0l-5 5m5-5H6"
                            />
                          </svg>
                          <Badge
                            variant={change.new_verdict}
                            className="text-xs"
                          >
                            {change.new_verdict}
                          </Badge>
                        </>
                      ) : (
                        <Badge variant={change.verdict} className="text-xs">
                          {change.verdict} (unchanged)
                        </Badge>
                      )}
                    </div>
                  </div>
                )
              )}
            </div>
          </Card>
        )}
    </div>
  );
};
