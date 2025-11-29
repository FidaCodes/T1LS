export const Badge = ({ children, variant = "default", className = "" }) => {
  const variants = {
    default: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200",
    success:
      "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400",
    warning:
      "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400",
    danger: "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400",
    info: "bg-cyan-100 dark:bg-cyan-900/30 text-cyan-800 dark:text-cyan-400",
    BENIGN:
      "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400",
    SUSPICIOUS:
      "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400",
    MALICIOUS: "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400",
    UNKNOWN: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200",
    SKIPPED: "bg-cyan-100 dark:bg-cyan-900/30 text-cyan-800 dark:text-cyan-400",
  };

  return (
    <span
      className={`px-3 py-1 rounded-full text-xs font-semibold ${
        variants[variant] || variants.default
      } ${className}`}
    >
      {children}
    </span>
  );
};
