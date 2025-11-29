export const Card = ({
  children,
  className = "",
  hover = false,
  padding = "md",
  ...props
}) => {
  const paddings = {
    sm: "p-4",
    md: "p-6",
    lg: "p-8",
    none: "",
  };

  return (
    <div
      className={`
        bg-white dark:bg-gray-800 rounded-xl shadow-md border border-gray-100 dark:border-gray-700
        ${hover ? "hover:shadow-xl transition-shadow duration-300" : ""}
        ${paddings[padding]}
        ${className}
      `}
      {...props}
    >
      {children}
    </div>
  );
};
