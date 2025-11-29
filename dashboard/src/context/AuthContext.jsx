import { createContext, useContext, useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { authService } from "../services/authService";

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    // Check if user is already logged in
    const token = authService.getToken();
    const storedUser = localStorage.getItem("user");
    if (token && storedUser) {
      setIsAuthenticated(true);
      setUser(JSON.parse(storedUser));
    }
    setIsLoading(false);
  }, []);

  const login = async (email, password) => {
    const data = await authService.login(email, password);
    authService.setToken(data.token);
    setIsAuthenticated(true);
    setUser(data.user);
    localStorage.setItem("user", JSON.stringify(data.user));
    return data;
  };

  const register = async (username, email, password) => {
    const data = await authService.register(username, email, password);
    authService.setToken(data.token);
    setIsAuthenticated(true);
    setUser(data.user);
    localStorage.setItem("user", JSON.stringify(data.user));
    return data;
  };

  const logout = () => {
    authService.logout();
    setIsAuthenticated(false);
    setUser(null);
    localStorage.removeItem("user");
    navigate("/login");
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        isLoading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
