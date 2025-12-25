import React, { useEffect } from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import { useAuth } from './AuthContext';
import Login from './Login';
import ChangePassword from './ChangePassword';
import ProtectedRoute from './ProtectedRoute';
import App from './App';

function AppRouter() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/change-password" element={<ChangePasswordWithLogout />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <DashboardWithFirstLoginCheck />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

function DashboardWithFirstLoginCheck() {
  const { user } = useAuth();
  const navigate = useNavigate();

  // Redirect to change password if first login
  useEffect(() => {
    if (user && user.first_login === true) {
      navigate('/change-password');
    }
  }, [user, navigate]);

  return <App />;
}

function ChangePasswordWithLogout() {
  return <ChangePassword />;
}

export default AppRouter;
