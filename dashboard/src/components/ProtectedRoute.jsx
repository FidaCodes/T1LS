import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { FullPageLoader } from "./LoadingSpinner";

export const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <FullPageLoader />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
};
