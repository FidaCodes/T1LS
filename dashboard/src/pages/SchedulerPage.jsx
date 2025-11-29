import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { schedulerService } from "../services/authService";
import { Button } from "../components/Button";
import { Input } from "../components/Input";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { Navbar } from "../components/Navbar";

const SchedulerPage = () => {
  const [schedules, setSchedules] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [formData, setFormData] = useState({
    ioc: "",
    scheduledFor: "",
    recurrence: "once",
    notes: "",
    slackChannelId: "#threat-intel",
  });
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [includeCompleted, setIncludeCompleted] = useState(false);
  const { logout } = useAuth();

  useEffect(() => {
    fetchData();
  }, [includeCompleted]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [schedulesRes, statsRes] = await Promise.all([
        schedulerService.getSchedules(includeCompleted),
        schedulerService.getStats(),
      ]);
      setSchedules(schedulesRes.schedules);
      setStats(statsRes);
    } catch (error) {
      console.error("Error fetching scheduler data:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSchedule = async (e) => {
    e.preventDefault();
    setFormError("");

    if (!formData.ioc.trim()) {
      setFormError("Please enter an IOC");
      return;
    }

    if (!formData.scheduledFor) {
      setFormError("Please select a date and time");
      return;
    }

    // Validate date is in the future
    const scheduleDate = new Date(formData.scheduledFor);
    if (scheduleDate <= new Date()) {
      setFormError("Scheduled time must be in the future");
      return;
    }

    setSubmitting(true);
    try {
      await schedulerService.createSchedule(formData);

      // Reset form
      setFormData({
        ioc: "",
        scheduledFor: "",
        recurrence: "once",
        notes: "",
        slackChannelId: "#threat-intel",
      });
      setShowCreateForm(false);

      // Refresh data
      await fetchData();
    } catch (error) {
      setFormError(
        error.response?.data?.message || "Failed to create schedule"
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancelSchedule = async (id) => {
    if (!confirm("Are you sure you want to cancel this scheduled analysis?")) {
      return;
    }

    try {
      await schedulerService.cancelSchedule(id);
      await fetchData();
    } catch (error) {
      alert("Failed to cancel schedule");
    }
  };

  const handleDeleteSchedule = async (id) => {
    if (!confirm("Are you sure you want to delete this schedule?")) {
      return;
    }

    try {
      await schedulerService.deleteSchedule(id);
      await fetchData();
    } catch (error) {
      alert("Failed to delete schedule");
    }
  };

  const getStatusBadgeVariant = (status) => {
    switch (status) {
      case "pending":
        return "default";
      case "running":
        return "default";
      case "completed":
        return "BENIGN";
      case "failed":
        return "MALICIOUS";
      case "cancelled":
        return "SUSPICIOUS";
      default:
        return "default";
    }
  };

  const getRecurrenceLabel = (recurrence) => {
    switch (recurrence) {
      case "once":
        return "Every 24 hours";
      case "hourly":
        return "Every 6 hours";
      case "daily":
        return "Every 12 hours";
      case "weekly":
        return "Every 48 hours";
      default:
        return recurrence;
    }
  };

  const formatDateTime = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const getMinDateTime = () => {
    const now = new Date();
    now.setMinutes(now.getMinutes() + 5); // Minimum 5 minutes from now
    return now.toISOString().slice(0, 16);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a1628]">
        <Navbar onLogout={logout} />
        <div className="flex items-center justify-center h-[calc(100vh-4rem)] pt-16">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a1628]">
      <Navbar onLogout={logout} />
      <div className="pt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h1 className="text-3xl font-bold text-white">
                  Scheduled Monitoring
                </h1>
                <p className="text-gray-400 mt-1">
                  Periodic automatic scans for continuous threat monitoring
                </p>
              </div>
              <Button
                variant="primary"
                onClick={() => setShowCreateForm(!showCreateForm)}
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
                Add Monitor
              </Button>
            </div>
          </div>

          {/* Create Form */}
          {showCreateForm && (
            <div className="mb-8 bg-[#0f1f3a] rounded-xl p-6 border border-gray-700">
              <h2 className="text-xl font-bold text-white mb-4">
                Add New Monitor
              </h2>
              <form onSubmit={handleCreateSchedule} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">
                      IOC / Observable *
                    </label>
                    <Input
                      placeholder="e.g., 8.8.8.8, example.com, or file hash"
                      value={formData.ioc}
                      onChange={(e) =>
                        setFormData({ ...formData, ioc: e.target.value })
                      }
                      disabled={submitting}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">
                      Scan Interval *
                    </label>
                    <select
                      value={formData.recurrence}
                      onChange={(e) =>
                        setFormData({ ...formData, recurrence: e.target.value })
                      }
                      disabled={submitting}
                      className="w-full px-4 py-2 border border-gray-700 bg-[#152a47] rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
                    >
                      <option value="hourly">
                        Every 6 hours - Critical assets
                      </option>
                      <option value="daily">
                        Every 12 hours - Important observables
                      </option>
                      <option value="once">
                        Every 24 hours - Standard monitoring
                      </option>
                      <option value="weekly">
                        Every 48 hours - Low priority
                      </option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">
                      First Scan *
                    </label>
                    <Input
                      type="datetime-local"
                      value={formData.scheduledFor}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          scheduledFor: e.target.value,
                        })
                      }
                      min={getMinDateTime()}
                      disabled={submitting}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">
                      Slack Channel
                    </label>
                    <Input
                      placeholder="#threat-intel"
                      value={formData.slackChannelId}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          slackChannelId: e.target.value,
                        })
                      }
                      disabled={submitting}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">
                    Notes (Optional)
                  </label>
                  <textarea
                    value={formData.notes}
                    onChange={(e) =>
                      setFormData({ ...formData, notes: e.target.value })
                    }
                    disabled={submitting}
                    rows={3}
                    maxLength={500}
                    placeholder="Add notes about this monitored observable..."
                    className="w-full px-4 py-2 border border-gray-700 bg-[#152a47] rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white resize-none"
                  />
                </div>

                {formError && (
                  <div className="bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg">
                    {formError}
                  </div>
                )}

                <div className="flex gap-3">
                  <Button
                    type="submit"
                    variant="primary"
                    loading={submitting}
                    disabled={submitting}
                  >
                    Create Monitor
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setShowCreateForm(false)}
                    disabled={submitting}
                  >
                    Cancel
                  </Button>
                </div>
              </form>
            </div>
          )}

          {/* Monitors Grid */}
          {schedules.length === 0 ? (
            <div className="bg-[#0f1f3a] rounded-xl p-12 text-center border border-gray-700">
              <div className="w-20 h-20 bg-blue-600/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg
                  className="w-10 h-10 text-[#3b82f6]"
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
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">
                No Scheduled Monitors
              </h3>
              <p className="text-gray-400 mb-4">
                Create your first monitor to get started with continuous threat
                monitoring
              </p>
              <Button variant="primary" onClick={() => setShowCreateForm(true)}>
                Add Monitor
              </Button>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                {schedules.map((schedule) => (
                  <div
                    key={schedule._id}
                    className="bg-[#0f1f3a] rounded-xl p-5 border border-gray-700 hover:border-gray-600 transition-colors"
                  >
                    {/* Header with IOC and Status */}
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1 min-w-0">
                        <h3 className="text-lg font-bold text-white font-mono truncate mb-1">
                          {schedule.ioc}
                        </h3>
                        <p className="text-xs text-gray-500">
                          {schedule.ioc.includes(".") &&
                          !schedule.ioc.match(/^\d+\.\d+\.\d+\.\d+$/)
                            ? "Domain"
                            : schedule.ioc.match(/^\d+\.\d+\.\d+\.\d+$/)
                            ? "IP Address"
                            : schedule.ioc.includes("@")
                            ? "Email"
                            : schedule.ioc.length > 32
                            ? "Hash"
                            : "URL"}
                        </p>
                      </div>
                      <Badge
                        variant={
                          schedule.status === "pending" ||
                          schedule.status === "running"
                            ? "default"
                            : schedule.status === "cancelled"
                            ? "SUSPICIOUS"
                            : "BENIGN"
                        }
                      >
                        {schedule.status === "pending"
                          ? "ACTIVE"
                          : schedule.status === "cancelled"
                          ? "PAUSED"
                          : schedule.status.toUpperCase()}
                      </Badge>
                    </div>

                    {/* Scan Details */}
                    <div className="space-y-3 mb-4">
                      <div>
                        <p className="text-xs text-gray-500 mb-1">
                          Scan Interval:
                        </p>
                        <p className="text-sm text-white font-medium">
                          {getRecurrenceLabel(schedule.recurrence)}
                        </p>
                      </div>

                      <div>
                        <p className="text-xs text-gray-500 mb-1">Last Scan:</p>
                        <p className="text-sm text-white">
                          {schedule.executedAt
                            ? new Date(schedule.executedAt).toLocaleString(
                                "en-US",
                                {
                                  month: "short",
                                  day: "numeric",
                                  hour: "2-digit",
                                  minute: "2-digit",
                                }
                              )
                            : "Never"}
                        </p>
                      </div>

                      <div>
                        <p className="text-xs text-gray-500 mb-1">Next Scan:</p>
                        <p className="text-sm text-white">
                          {schedule.status === "cancelled"
                            ? "Paused"
                            : schedule.scheduledFor
                            ? new Date(schedule.scheduledFor).toLocaleString(
                                "en-US",
                                {
                                  month: "short",
                                  day: "numeric",
                                  hour: "2-digit",
                                  minute: "2-digit",
                                }
                              )
                            : "Not scheduled"}
                        </p>
                      </div>

                      <div>
                        <p className="text-xs text-gray-500 mb-1">
                          Total Scans:
                        </p>
                        <p className="text-sm text-white font-bold">
                          {schedule.executionCount || 0}
                        </p>
                      </div>
                    </div>

                    {/* Last Result Badge */}
                    {schedule.lastResult && (
                      <div className="mb-4">
                        <p className="text-xs text-gray-500 mb-1">
                          Last Result:
                        </p>
                        <Badge variant={schedule.lastResult}>
                          {schedule.lastResult}
                        </Badge>
                      </div>
                    )}

                    {/* Action Buttons */}
                    <div className="flex gap-2 pt-3 border-t border-gray-700">
                      {schedule.status === "pending" ? (
                        <button
                          onClick={() => handleCancelSchedule(schedule._id)}
                          className="flex-1 px-3 py-2 text-xs font-medium text-gray-300 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors flex items-center justify-center gap-1"
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
                              d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"
                            />
                          </svg>
                          Pause
                        </button>
                      ) : schedule.status === "cancelled" ? (
                        <button className="flex-1 px-3 py-2 text-xs font-medium text-green-400 bg-green-900/30 hover:bg-green-900/50 rounded-lg transition-colors flex items-center justify-center gap-1">
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
                              d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"
                            />
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                            />
                          </svg>
                          Resume
                        </button>
                      ) : null}

                      <button className="flex-1 px-3 py-2 text-xs font-medium text-gray-300 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors flex items-center justify-center gap-1">
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
                            d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                          />
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                          />
                        </svg>
                        Configure
                      </button>

                      <button
                        onClick={() => handleDeleteSchedule(schedule._id)}
                        className="px-3 py-2 text-xs font-medium text-red-400 bg-red-900/30 hover:bg-red-900/50 rounded-lg transition-colors"
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
                            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                          />
                        </svg>
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {/* Info Sections */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* How Monitoring Works */}
                <div className="bg-[#0f1f3a] rounded-xl p-6 border border-gray-700">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-blue-600/20 rounded-lg flex items-center justify-center">
                      <svg
                        className="w-6 h-6 text-[#3b82f6]"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                    </div>
                    <h3 className="text-lg font-bold text-white">
                      How Monitoring Works
                    </h3>
                  </div>
                  <p className="text-sm text-gray-400 leading-relaxed">
                    Set up periodic scans for specific observables. The system
                    will automatically analyze them at your chosen intervals and
                    alert you if the classification changes.
                  </p>
                </div>

                {/* Available Intervals */}
                <div className="bg-[#0f1f3a] rounded-xl p-6 border border-gray-700">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-blue-600/20 rounded-lg flex items-center justify-center">
                      <svg
                        className="w-6 h-6 text-[#3b82f6]"
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
                    </div>
                    <h3 className="text-lg font-bold text-white">
                      Available Intervals
                    </h3>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-sm">
                      <span className="text-[#3b82f6]">→</span>
                      <span className="text-gray-300">
                        Every 6 hours - Critical assets
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="text-[#3b82f6]">→</span>
                      <span className="text-gray-300">
                        Every 12 hours - Important observables
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="text-[#3b82f6]">→</span>
                      <span className="text-gray-300">
                        Every 24 hours - Standard monitoring
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="text-[#3b82f6]">→</span>
                      <span className="text-gray-300">
                        Every 48 hours - Low priority
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default SchedulerPage;
