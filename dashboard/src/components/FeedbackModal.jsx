import { useState } from "react";
import { X } from "lucide-react";

export default function FeedbackModal({
  isOpen,
  onClose,
  onSubmit,
  ioc,
  loading,
}) {
  const [feedback, setFeedback] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();

    if (!feedback.trim()) {
      setError("Please enter feedback before submitting");
      return;
    }

    onSubmit(feedback);
  };

  const handleClose = () => {
    setFeedback("");
    setError("");
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            Provide Analyst Feedback
          </h2>
          <button
            onClick={handleClose}
            className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
            disabled={loading}
          >
            <X size={24} />
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} className="p-6">
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              IOC:{" "}
              <span className="font-mono text-blue-600 dark:text-blue-400">
                {ioc}
              </span>
            </label>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              Your feedback will be used as context for future analyses of this
              IOC. Include your expert assessment, additional context, or any
              relevant information that should be considered in subsequent
              threat evaluations.
            </p>

            <textarea
              value={feedback}
              onChange={(e) => {
                setFeedback(e.target.value);
                setError("");
              }}
              placeholder="Enter your expert analysis and feedback here..."
              className="w-full h-40 px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none bg-white dark:bg-gray-900 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              disabled={loading}
            />

            {error && (
              <p className="mt-2 text-sm text-red-600 dark:text-red-400">
                {error}
              </p>
            )}
          </div>

          <div className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            <p className="font-medium mb-1">Tips for effective feedback:</p>
            <ul className="list-disc list-inside space-y-1 ml-2">
              <li>Be specific about the threat assessment</li>
              <li>Include any false positive/negative information</li>
              <li>Mention relevant contextual factors</li>
              <li>Reference specific evidence or indicators</li>
            </ul>
          </div>

          {/* Footer */}
          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={handleClose}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={loading}
            >
              {loading ? "Submitting..." : "Submit Feedback"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
