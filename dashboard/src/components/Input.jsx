import { forwardRef } from "react";

export const Input = forwardRef(
  (
    {
      label,
      error,
      helperText,
      icon: Icon,
      className = "",
      containerClassName = "",
      ...props
    },
    ref
  ) => {
    return (
      <div className={`w-full ${containerClassName}`}>
        {label && (
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            {label}
          </label>
        )}
        <div className="relative">
          {Icon && (
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Icon className="h-5 w-5 text-gray-400 dark:text-gray-500" />
            </div>
          )}
          <input
            ref={ref}
            className={`
              w-full rounded-lg border transition-all duration-200
              bg-white dark:bg-gray-700 text-gray-900 dark:text-white
              ${Icon ? "pl-10" : "pl-4"} pr-4 py-2.5
              ${
                error
                  ? "border-red-500 focus:ring-red-500 focus:border-red-500"
                  : "border-gray-300 dark:border-gray-600 focus:ring-cyan-500 focus:border-cyan-500"
              }
              focus:outline-none focus:ring-2
              disabled:bg-gray-100 dark:disabled:bg-gray-800 disabled:cursor-not-allowed
              placeholder:text-gray-400 dark:placeholder:text-gray-500
              ${className}
            `}
            {...props}
          />
        </div>
        {error && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{error}</p>
        )}
        {helperText && !error && (
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {helperText}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = "Input";
