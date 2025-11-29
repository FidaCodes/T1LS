import { useEffect } from "react";
import JsonView from "@uiw/react-json-view";
import { Badge } from "./Badge";

export const Drawer = ({ isOpen, onClose, data, title }) => {
  // Close on ESC key
  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      document.addEventListener("keydown", handleEsc);
      document.body.style.overflow = "hidden";
    }
    return () => {
      document.removeEventListener("keydown", handleEsc);
      document.body.style.overflow = "unset";
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 bg-black/50 z-50 transition-opacity"
        onClick={onClose}
      />

      {/* Drawer */}
      <div
        className={`
          fixed right-0 top-0 h-full w-full sm:w-[600px] lg:w-[700px]
          bg-white dark:bg-gray-800 shadow-2xl z-50
          transform transition-transform duration-300 ease-in-out
          ${isOpen ? "translate-x-0" : "translate-x-full"}
          flex flex-col
        `}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-6 shrink-0">
          <div className="flex-1 min-w-0">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white truncate">
              {title}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="ml-4 p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors shrink-0"
          >
            <svg
              className="w-6 h-6 text-gray-500 dark:text-gray-400"
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

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {data && (
            <div className="space-y-6">
              {/* Summary Section */}
              <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                  Summary
                </h3>

                {/* Verdict */}
                {data.verdict && (
                  <div className="mb-4">
                    <label className="text-sm font-medium text-gray-500 dark:text-gray-400 block mb-2">
                      Verdict
                    </label>
                    <Badge variant={data.verdict} className="text-sm">
                      {data.verdict}
                    </Badge>
                  </div>
                )}

                {/* Confidence Score */}
                {data.confidence_score !== undefined && (
                  <div className="mb-4">
                    <label className="text-sm font-medium text-gray-500 dark:text-gray-400 block mb-2">
                      Confidence Score
                    </label>
                    <div className="flex items-center gap-3">
                      <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-3 overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            data.confidence_score >= 80
                              ? "bg-green-500"
                              : data.confidence_score >= 50
                              ? "bg-yellow-500"
                              : "bg-red-500"
                          }`}
                          style={{ width: `${data.confidence_score}%` }}
                        />
                      </div>
                      <span className="text-sm font-semibold text-gray-900 dark:text-white min-w-[3rem]">
                        {data.confidence_score}%
                      </span>
                    </div>
                  </div>
                )}

                {/* Reasoning */}
                {data.reasoning && (
                  <div>
                    <label className="text-sm font-medium text-gray-500 dark:text-gray-400 block mb-2">
                      Reasoning
                    </label>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                      {data.reasoning}
                    </p>
                  </div>
                )}

                {/* Success status if available */}
                {data.success !== undefined && (
                  <div className="mt-4">
                    <label className="text-sm font-medium text-gray-500 dark:text-gray-400 block mb-2">
                      Status
                    </label>
                    <Badge variant={data.success ? "success" : "danger"}>
                      {data.success ? "Success" : "Failed"}
                    </Badge>
                  </div>
                )}
              </div>

              {/* VirusTotal Specific Details */}
              {title.includes("VIRUSTOTAL") && (
                <>
                  {/* Detection Stats */}
                  {(data?.data?.malicious_count > 0 ||
                    data?.data?.suspicious_count > 0) && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                        Detection Statistics
                      </h3>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Malicious
                          </p>
                          <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                            {data?.data?.malicious_count}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Suspicious
                          </p>
                          <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                            {data?.data?.suspicious_count}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Harmless
                          </p>
                          <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                            {data?.data?.harmless_count}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Undetected
                          </p>
                          <p className="text-2xl font-bold text-gray-600 dark:text-gray-400">
                            {data?.data?.undetected_count}
                          </p>
                        </div>
                      </div>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-3">
                        Total Engines: {data?.data?.total_engines}
                      </p>
                    </div>
                  )}

                  {/* Malicious Vendors */}
                  {data?.data?.malicious_vendors &&
                    data?.data?.malicious_vendors.length > 0 && (
                      <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                          <span className="text-red-600 dark:text-red-400">
                            ⚠️
                          </span>
                          Malicious Detections (
                          {data?.data?.malicious_vendors.length})
                        </h3>
                        <div className="space-y-2 max-h-64 overflow-y-auto">
                          {data?.data?.malicious_vendors.map((vendor, idx) => (
                            <div
                              key={idx}
                              className="bg-white dark:bg-gray-800 p-3 rounded border border-red-200 dark:border-red-800"
                            >
                              <div className="flex items-start justify-between">
                                <div className="flex-1">
                                  <p className="font-semibold text-gray-900 dark:text-white">
                                    {vendor.engine}
                                  </p>
                                  <p className="text-sm text-red-600 dark:text-red-400">
                                    {vendor.result}
                                  </p>
                                </div>
                                <Badge variant="danger" className="text-xs">
                                  {vendor.category}
                                </Badge>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* Phishing Vendors */}
                  {data?.data?.phishing_vendors &&
                    data?.data?.phishing_vendors.length > 0 && (
                      <div className="bg-orange-50 dark:bg-orange-900/20 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                          <span className="text-orange-600 dark:text-orange-400">
                            🎣
                          </span>
                          Phishing Detections (
                          {data?.data?.phishing_vendors.length})
                        </h3>
                        <div className="space-y-2 max-h-64 overflow-y-auto">
                          {data?.data?.phishing_vendors.map((vendor, idx) => (
                            <div
                              key={idx}
                              className="bg-white dark:bg-gray-800 p-3 rounded border border-orange-200 dark:border-orange-800"
                            >
                              <div className="flex items-start justify-between">
                                <div className="flex-1">
                                  <p className="font-semibold text-gray-900 dark:text-white">
                                    {vendor.engine}
                                  </p>
                                  <p className="text-sm text-orange-600 dark:text-orange-400">
                                    {vendor.result}
                                  </p>
                                </div>
                                <Badge variant="warning" className="text-xs">
                                  phishing
                                </Badge>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* Tags */}
                  {data?.data?.tags && data?.data?.tags.length > 0 && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        Tags
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {data?.data?.tags.map((tag, idx) => (
                          <span
                            key={idx}
                            className="px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300 rounded-full text-xs font-medium"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* AbuseIPDB Specific Details */}
              {title.includes("ABUSEIPDB") && (
                <>
                  {/* Abuse Confidence */}
                  {data?.data?.abuse_confidence !== undefined && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        Abuse Confidence
                      </h3>
                      <div className="flex items-center gap-3">
                        <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-4 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              data?.data?.abuse_confidence >= 75
                                ? "bg-red-500"
                                : data?.data?.abuse_confidence >= 50
                                ? "bg-orange-500"
                                : data?.data?.abuse_confidence >= 25
                                ? "bg-yellow-500"
                                : "bg-green-500"
                            }`}
                            style={{
                              width: `${data?.data?.abuse_confidence}%`,
                            }}
                          />
                        </div>
                        <span className="text-xl font-bold text-gray-900 dark:text-white min-w-[4rem]">
                          {data?.data?.abuse_confidence}%
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-4 mt-4">
                        <div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Total Reports
                          </p>
                          <p className="text-lg font-semibold text-gray-900 dark:text-white">
                            {data?.data?.total_reports}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Distinct Users
                          </p>
                          <p className="text-lg font-semibold text-gray-900 dark:text-white">
                            {data?.data?.num_distinct_users}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Top Abuse Categories */}
                  {data?.data?.top_abuse_categories &&
                    data?.data?.top_abuse_categories.length > 0 && (
                      <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          Top Abuse Categories
                        </h3>
                        <div className="space-y-2">
                          {data?.data?.top_abuse_categories.map((cat, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between"
                            >
                              <span className="text-sm text-gray-700 dark:text-gray-300">
                                {cat.category}
                              </span>
                              <Badge variant="danger" className="text-xs">
                                {cat.count} reports
                              </Badge>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* Recent Reports */}
                  {data?.data?.recent_reports &&
                    data?.data?.recent_reports.length > 0 && (
                      <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          Recent Abuse Reports
                        </h3>
                        <div className="space-y-3 max-h-96 overflow-y-auto">
                          {data?.data?.recent_reports.map((report, idx) => (
                            <div
                              key={idx}
                              className="bg-white dark:bg-gray-800 p-3 rounded border border-gray-200 dark:border-gray-700"
                            >
                              <div className="flex items-start justify-between mb-2">
                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                  {new Date(report.date).toLocaleDateString()}
                                </p>
                                {report.reporter_country && (
                                  <span className="text-xs text-gray-500 dark:text-gray-400">
                                    {report.reporter_country}
                                  </span>
                                )}
                              </div>
                              {report.comment && (
                                <p className="text-sm text-gray-700 dark:text-gray-300 mb-2">
                                  {report.comment}
                                </p>
                              )}
                              {report.categories &&
                                report.categories.length > 0 && (
                                  <div className="flex flex-wrap gap-1">
                                    {report.categories.map((cat, catIdx) => (
                                      <span
                                        key={catIdx}
                                        className="px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded text-xs"
                                      >
                                        Cat {cat}
                                      </span>
                                    ))}
                                  </div>
                                )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                </>
              )}

              {/* Shodan Specific Details */}
              {title.includes("SHODAN") && (
                <>
                  {/* Open Ports */}
                  {data?.data?.ports && data?.data?.ports.length > 0 && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        Open Ports ({data?.data?.open_ports_count})
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {data?.data?.ports.map((port, idx) => (
                          <span
                            key={idx}
                            className="px-3 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded font-mono text-sm font-semibold"
                          >
                            {port}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Services */}
                  {data?.data?.services && data?.data?.services.length > 0 && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        Services Detected
                      </h3>
                      <div className="space-y-3 max-h-96 overflow-y-auto">
                        {data?.data?.services.map((service, idx) => (
                          <div
                            key={idx}
                            className="bg-white dark:bg-gray-800 p-3 rounded border border-gray-200 dark:border-gray-700"
                          >
                            <div className="flex items-start justify-between mb-2">
                              <div>
                                <p className="font-semibold text-gray-900 dark:text-white">
                                  Port {service.port}
                                  {service.transport && `/${service.transport}`}
                                </p>
                                {service.product && (
                                  <p className="text-sm text-gray-600 dark:text-gray-400">
                                    {service.product}
                                    {service.version && ` ${service.version}`}
                                  </p>
                                )}
                              </div>
                            </div>
                            {service.banner && (
                              <p className="text-xs text-gray-500 dark:text-gray-400 font-mono bg-gray-100 dark:bg-gray-900 p-2 rounded mt-2 overflow-x-auto">
                                {service.banner}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Vulnerabilities */}
                  {data?.data?.vulnerabilities &&
                    data?.data?.vulnerabilities.length > 0 && (
                      <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                          <span className="text-red-600 dark:text-red-400">
                            🔓
                          </span>
                          Vulnerabilities ({data?.data?.vulnerability_count})
                        </h3>
                        <div className="space-y-1">
                          {data?.data?.vulnerabilities.map((cve, idx) => (
                            <div
                              key={idx}
                              className="font-mono text-sm text-red-700 dark:text-red-400 bg-white dark:bg-gray-800 px-3 py-2 rounded border border-red-200 dark:border-red-800"
                            >
                              {cve}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                </>
              )}

              {/* URLScan Specific Details */}
              {title.includes("URLSCAN") && (
                <>
                  {/* Verdict Breakdown */}
                  {(data?.data?.urlscan_malicious !== undefined ||
                    data?.data?.community_malicious !== undefined) && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        Verdict Breakdown
                      </h3>
                      <div className="space-y-2">
                        {data?.data?.urlscan_malicious !== undefined && (
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-700 dark:text-gray-300">
                              URLScan.io
                            </span>
                            <Badge
                              variant={
                                data?.data?.urlscan_malicious
                                  ? "danger"
                                  : "success"
                              }
                              className="text-xs"
                            >
                              {data?.data?.urlscan_malicious
                                ? "Malicious"
                                : "Clean"}
                            </Badge>
                          </div>
                        )}
                        {data?.data?.community_malicious !== undefined && (
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-700 dark:text-gray-300">
                              Community
                            </span>
                            <Badge
                              variant={
                                data?.data?.community_malicious
                                  ? "danger"
                                  : "success"
                              }
                              className="text-xs"
                            >
                              {data?.data?.community_malicious
                                ? "Malicious"
                                : "Clean"}
                            </Badge>
                          </div>
                        )}
                        {data?.data?.phishing_detected !== undefined &&
                          data?.data?.phishing_detected && (
                            <div className="flex items-center justify-between">
                              <span className="text-sm text-gray-700 dark:text-gray-300">
                                Phishing
                              </span>
                              <Badge variant="warning" className="text-xs">
                                Detected
                              </Badge>
                            </div>
                          )}
                      </div>
                    </div>
                  )}

                  {/* Contacted Domains */}
                  {data?.data?.contacted_domains &&
                    data?.data?.contacted_domains.length > 0 && (
                      <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          Contacted Domains
                        </h3>
                        <div className="space-y-1 max-h-48 overflow-y-auto">
                          {data?.data?.contacted_domains.map((domain, idx) => (
                            <div
                              key={idx}
                              className="text-sm font-mono text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 px-3 py-2 rounded border border-gray-200 dark:border-gray-700"
                            >
                              {domain}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* Certificates */}
                  {data?.data?.certificates &&
                    data?.data?.certificates.length > 0 && (
                      <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          SSL Certificates
                        </h3>
                        <div className="space-y-3">
                          {data?.data?.certificates.map((cert, idx) => (
                            <div
                              key={idx}
                              className="bg-white dark:bg-gray-800 p-3 rounded border border-gray-200 dark:border-gray-700"
                            >
                              <p className="text-sm font-semibold text-gray-900 dark:text-white">
                                {cert.subject}
                              </p>
                              <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                                Issuer: {cert.issuer}
                              </p>
                              {cert.valid_to && (
                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                  Valid until:{" "}
                                  {new Date(cert.valid_to).toLocaleDateString()}
                                </p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                </>
              )}

              {/* MISP Specific Details */}
              {title.includes("MISP") && (
                <>
                  {/* Threat Level Distribution */}
                  {data?.data?.threat_level_distribution && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        Threat Level Distribution
                      </h3>
                      <div className="space-y-2">
                        {Object.entries(
                          data?.data?.threat_level_distribution
                        ).map(([level, count]) => (
                          <div
                            key={level}
                            className="flex items-center justify-between"
                          >
                            <span className="text-sm text-gray-700 dark:text-gray-300">
                              {level}
                            </span>
                            <Badge
                              variant={
                                level === "High"
                                  ? "danger"
                                  : level === "Medium"
                                  ? "warning"
                                  : "default"
                              }
                              className="text-xs"
                            >
                              {count} events
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Top Tags */}
                  {data?.data?.top_tags && data?.data?.top_tags.length > 0 && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        Most Common Tags
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {data?.data?.top_tags.map((tagObj, idx) => (
                          <span
                            key={idx}
                            className="px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300 rounded-full text-xs font-medium"
                          >
                            {tagObj.tag} ({tagObj.count})
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Threat Actors & Malware */}
                  {data?.data?.threat_actors_malware &&
                    data?.data?.threat_actors_malware.length > 0 && (
                      <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          Threat Intelligence
                        </h3>
                        <div className="space-y-2">
                          {data?.data?.threat_actors_malware.map(
                            (item, idx) => (
                              <div
                                key={idx}
                                className="bg-white dark:bg-gray-800 px-3 py-2 rounded border border-red-200 dark:border-red-800"
                              >
                                <p className="text-sm font-medium text-gray-900 dark:text-white">
                                  {item}
                                </p>
                              </div>
                            )
                          )}
                        </div>
                      </div>
                    )}
                </>
              )}

              {/* AlienVault OTX Specific Details */}
              {title.includes("ALIENVAULT") && (
                <>
                  {/* Pulse Count & Reputation */}
                  {(data?.data?.pulse_count !== undefined ||
                    data?.data?.reputation !== undefined) && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                        Threat Intelligence Overview
                      </h3>
                      <div className="grid grid-cols-2 gap-4">
                        {data?.data?.pulse_count !== undefined && (
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              Threat Pulses
                            </p>
                            <p className="text-2xl font-bold text-gray-900 dark:text-white">
                              {data?.data?.pulse_count}
                            </p>
                          </div>
                        )}
                        {data?.data?.reputation !== undefined && (
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              Reputation Score
                            </p>
                            <p
                              className={`text-2xl font-bold ${
                                data?.data?.reputation < -50
                                  ? "text-red-600"
                                  : data?.data?.reputation < 0
                                  ? "text-orange-600"
                                  : "text-green-600"
                              }`}
                            >
                              {data?.data?.reputation}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Malware Families */}
                  {data?.data?.malware_families &&
                    data?.data?.malware_families.length > 0 && (
                      <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          🦠 Malware Families
                        </h3>
                        <div className="flex flex-wrap gap-2">
                          {data?.data?.malware_families.map((family, idx) => (
                            <span
                              key={idx}
                              className="px-3 py-1 bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-300 rounded-full text-sm font-medium"
                            >
                              {family}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* Threat Actors */}
                  {data?.data?.adversaries &&
                    data?.data?.adversaries.length > 0 && (
                      <div className="bg-orange-50 dark:bg-orange-900/20 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          👤 Known Threat Actors
                        </h3>
                        <div className="space-y-2">
                          {data?.data?.adversaries.map((adversary, idx) => (
                            <div
                              key={idx}
                              className="bg-white dark:bg-gray-800 px-3 py-2 rounded border border-orange-200 dark:border-orange-800"
                            >
                              <p className="text-sm font-medium text-gray-900 dark:text-white">
                                {adversary}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* MITRE ATT&CK IDs */}
                  {data?.data?.attack_ids &&
                    data?.data?.attack_ids.length > 0 && (
                      <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          🎯 MITRE ATT&CK Techniques
                        </h3>
                        <div className="flex flex-wrap gap-2">
                          {data?.data?.attack_ids.map((attackId, idx) => (
                            <span
                              key={idx}
                              className="px-3 py-1 bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-300 rounded text-sm font-mono"
                            >
                              {attackId}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* Threat Tags */}
                  {data?.data?.threat_tags &&
                    data?.data?.threat_tags.length > 0 && (
                      <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                          🏷️ Threat Tags
                        </h3>
                        <div className="flex flex-wrap gap-2">
                          {data?.data?.threat_tags.map((tag, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 bg-cyan-100 dark:bg-cyan-900/30 text-cyan-800 dark:text-cyan-300 rounded text-xs"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* Recent Pulses */}
                  {data?.data?.pulses && data?.data?.pulses.length > 0 && (
                    <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        📡 Recent Threat Pulses
                      </h3>
                      <div className="space-y-3 max-h-96 overflow-y-auto">
                        {data?.data?.pulses.map((pulse, idx) => (
                          <div
                            key={idx}
                            className="bg-white dark:bg-gray-800 p-3 rounded border border-gray-200 dark:border-gray-700"
                          >
                            <div className="flex items-start justify-between mb-2">
                              <p className="text-sm font-semibold text-gray-900 dark:text-white flex-1">
                                {pulse.name}
                              </p>
                              {pulse.tlp && (
                                <span className="ml-2 px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 rounded text-xs shrink-0">
                                  TLP:{pulse.tlp}
                                </span>
                              )}
                            </div>
                            {pulse.description && (
                              <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">
                                {pulse.description}
                              </p>
                            )}
                            <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 mb-2">
                              <span>
                                Author: {pulse.author_name || "Unknown"}
                              </span>
                              <span>
                                {new Date(pulse.created).toLocaleDateString()}
                              </span>
                            </div>
                            {pulse.tags && pulse.tags.length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                {pulse.tags.map((tag, tagIdx) => (
                                  <span
                                    key={tagIdx}
                                    className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded text-xs"
                                  >
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* Raw JSON Data */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                  Raw Data (JSON)
                </h3>
                <div className="bg-gray-50 dark:bg-gray-100 rounded-lg p-4 overflow-x-auto">
                  <JsonView
                    value={data}
                    collapsed={1}
                    displayDataTypes={false}
                    style={{
                      backgroundColor: "transparent",
                      fontSize: "13px",
                    }}
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 dark:border-gray-700 p-4 shrink-0">
          <button
            onClick={onClose}
            className="w-full px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </>
  );
};
