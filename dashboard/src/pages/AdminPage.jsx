import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { adminService } from "../services/authService";
import { Navbar } from "../components/Navbar";
import { LoadingSpinner } from "../components/LoadingSpinner";

const AdminPage = () => {
  const [activeTab, setActiveTab] = useState("users");
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [newUser, setNewUser] = useState({
    username: "",
    email: "",
    password: "",
    role: "analyst",
  });
  const { logout } = useAuth();

  useEffect(() => {
    if (activeTab === "users") {
      fetchUsers();
    } else if (activeTab === "audit") {
      fetchAuditLogs();
    }
  }, [activeTab]);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await adminService.getAllUsers();
      setUsers(response.data);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to fetch users");
    } finally {
      setLoading(false);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      setLoading(true);
      const response = await adminService.getAuditLogs();
      setAuditLogs(response.data.logs);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to fetch audit logs");
    } finally {
      setLoading(false);
    }
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    try {
      await adminService.createUser(newUser);
      setShowAddUserModal(false);
      setNewUser({ username: "", email: "", password: "", role: "analyst" });
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.message || "Failed to create user");
    }
  };

  const handleDeleteUser = async (userId) => {
    if (window.confirm("Are you sure you want to delete this user?")) {
      try {
        await adminService.deleteUser(userId);
        fetchUsers();
      } catch (err) {
        setError(err.response?.data?.message || "Failed to delete user");
      }
    }
  };

  const getRoleBadgeColor = (role) => {
    switch (role) {
      case "admin":
        return "bg-purple-500/20 text-purple-400 border-purple-500/30";
      case "analyst":
        return "bg-green-500/20 text-green-400 border-green-500/30";
      case "viewer":
        return "bg-gray-500/20 text-gray-400 border-gray-500/30";
      default:
        return "bg-gray-500/20 text-gray-400 border-gray-500/30";
    }
  };

  const getStatusBadgeColor = (status) => {
    return status === "SUCCESS" ? "text-green-400" : "text-red-400";
  };

  if (loading && activeTab === "users" && users.length === 0) {
    return (
      <div className="min-h-screen bg-[#0a1628]">
        <Navbar onLogout={logout} />
        <div className="flex items-center justify-center h-[calc(100vh-4rem)] mt-16">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a1628]">
      <Navbar onLogout={logout} />

      <div className="pt-24 px-8 py-8 max-w-[1400px] mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Administration</h1>
          <p className="text-gray-400">
            Role-based access control and system management
          </p>
        </div>

        {/* Tabs */}
        <div className="flex gap-4 mb-6">
          <button
            onClick={() => setActiveTab("users")}
            className={`flex items-center gap-2 px-6 py-3 rounded-lg font-medium transition-colors ${
              activeTab === "users"
                ? "bg-blue-600 text-white"
                : "bg-[#0f1f3a] text-gray-400 hover:bg-[#152a47]"
            }`}
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
                d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
              />
            </svg>
            User Management
          </button>
          <button
            onClick={() => setActiveTab("audit")}
            className={`flex items-center gap-2 px-6 py-3 rounded-lg font-medium transition-colors ${
              activeTab === "audit"
                ? "bg-blue-600 text-white"
                : "bg-[#0f1f3a] text-gray-400 hover:bg-[#152a47]"
            }`}
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
                d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
              />
            </svg>
            Audit Trail
          </button>
        </div>

        {/* Error Message */}
        {error && (
          <div className="mb-6 bg-red-900/30 border border-red-800 text-red-400 px-4 py-3 rounded-lg flex items-start gap-2">
            <svg
              className="w-5 h-5 mt-0.5 flex-shrink-0"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <span>{error}</span>
          </div>
        )}

        {/* User Management Tab */}
        {activeTab === "users" && (
          <div>
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold text-white">Manage Users</h2>
              <button
                onClick={() => setShowAddUserModal(true)}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2.5 px-5 rounded-lg transition-colors"
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
                    d="M12 6v6m0 0v6m0-6h6m-6 0H6"
                  />
                </svg>
                Add User
              </button>
            </div>

            {/* Users Table */}
            <div className="bg-[#0f1f3a] rounded-xl overflow-hidden">
              <table className="w-full">
                <thead className="bg-[#152a47]">
                  <tr>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      User
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Role
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Status
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Last Login
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Total Scans
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {users.map((user) => (
                    <tr
                      key={user._id}
                      className="hover:bg-[#152a47] transition-colors"
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold">
                            {user.username?.charAt(0).toUpperCase() || "U"}
                          </div>
                          <div>
                            <p className="text-white font-medium">
                              {user.username || "Unknown"}
                            </p>
                            <p className="text-gray-400 text-sm">
                              {user.email || "No email"}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium border ${getRoleBadgeColor(
                            user.role
                          )}`}
                        >
                          {user.role === "admin" && (
                            <svg
                              className="w-3 h-3"
                              fill="currentColor"
                              viewBox="0 0 20 20"
                            >
                              <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                            </svg>
                          )}
                          {user.role
                            ? user.role.charAt(0).toUpperCase() +
                              user.role.slice(1)
                            : "Analyst"}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium bg-green-500/20 text-green-400 border border-green-500/30">
                          <span className="w-2 h-2 bg-green-400 rounded-full"></span>
                          {user.status || "Active"}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-gray-400">
                        {user.lastLogin || user.updatedAt
                          ? new Date(
                              user.lastLogin || user.updatedAt
                            ).toLocaleDateString()
                          : "Never"}
                      </td>
                      <td className="px-6 py-4 text-white font-medium">
                        {(user.totalScans || 0).toLocaleString()}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <button
                            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
                            title="Edit User"
                          >
                            <svg
                              className="w-5 h-5 text-blue-400"
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                              />
                            </svg>
                          </button>
                          <button
                            onClick={() => handleDeleteUser(user._id)}
                            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
                            title="Delete User"
                          >
                            <svg
                              className="w-5 h-5 text-red-400"
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
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Audit Trail Tab */}
        {activeTab === "audit" && (
          <div>
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold text-white">Audit Trail</h2>
              <p className="text-gray-400">
                Complete log of user activities and system events
              </p>
            </div>

            {/* Audit Logs Table */}
            <div className="bg-[#0f1f3a] rounded-xl overflow-hidden">
              <table className="w-full">
                <thead className="bg-[#152a47]">
                  <tr>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Timestamp
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      User
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Action
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Details
                    </th>
                    <th className="text-left px-6 py-4 text-gray-400 font-semibold uppercase text-xs">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {auditLogs.map((log) => (
                    <tr
                      key={log._id}
                      className="hover:bg-[#152a47] transition-colors"
                    >
                      <td className="px-6 py-4 text-gray-400 text-sm">
                        {new Date(log.createdAt).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-white">{log.userEmail}</td>
                      <td className="px-6 py-4 text-white font-medium">
                        {log.action}
                      </td>
                      <td className="px-6 py-4 text-gray-400">{log.details}</td>
                      <td className="px-6 py-4">
                        <span
                          className={`font-semibold uppercase text-xs ${getStatusBadgeColor(
                            log.status
                          )}`}
                        >
                          {log.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Add User Modal */}
        {showAddUserModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-[#0f1f3a] rounded-xl p-8 max-w-md w-full mx-4">
              <h3 className="text-2xl font-bold text-white mb-6">
                Add New User
              </h3>
              <form onSubmit={handleAddUser} className="space-y-4">
                <div>
                  <label className="block text-gray-400 mb-2">Username</label>
                  <input
                    type="text"
                    required
                    value={newUser.username}
                    onChange={(e) =>
                      setNewUser({ ...newUser, username: e.target.value })
                    }
                    className="w-full bg-[#152a47] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-gray-400 mb-2">Email</label>
                  <input
                    type="email"
                    required
                    value={newUser.email}
                    onChange={(e) =>
                      setNewUser({ ...newUser, email: e.target.value })
                    }
                    className="w-full bg-[#152a47] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-gray-400 mb-2">Password</label>
                  <input
                    type="password"
                    required
                    value={newUser.password}
                    onChange={(e) =>
                      setNewUser({ ...newUser, password: e.target.value })
                    }
                    className="w-full bg-[#152a47] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-gray-400 mb-2">Role</label>
                  <select
                    value={newUser.role}
                    onChange={(e) =>
                      setNewUser({ ...newUser, role: e.target.value })
                    }
                    className="w-full bg-[#152a47] border border-gray-700 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500"
                  >
                    <option value="analyst">Analyst</option>
                    <option value="admin">Administrator</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </div>
                <div className="flex gap-4 mt-6">
                  <button
                    type="button"
                    onClick={() => setShowAddUserModal(false)}
                    className="flex-1 px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-lg transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="flex-1 px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
                  >
                    Create User
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminPage;
