import React from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { AppLayout } from "./components/AppLayout";
import LoginPage from "./pages/auth/LoginPage";
import SignupPage from "./pages/auth/SignupPage";
import VerifyPage from "./pages/auth/VerifyPage";
import ForgotPasswordPage from "./pages/auth/ForgotPasswordPage";
import DashboardPage from "./pages/DashboardPage";
import AssessmentsPage from "./pages/AssessmentsPage";
import AssessmentWizardPage from "./pages/AssessmentWizardPage";
import AssessmentDetailPage from "./pages/AssessmentDetailPage";
import AssetsPage from "./pages/AssetsPage";
import FindingsPage from "./pages/FindingsPage";
import FindingDetailPage from "./pages/FindingDetailPage";
import AttackPathsPage from "./pages/AttackPathsPage";
import RemediationPage from "./pages/RemediationPage";
import ReportsPage from "./pages/ReportsPage";
import AuditPage from "./pages/AuditPage";
import SettingsPage from "./pages/SettingsPage";
import { PageSpinner } from "./components/badges";

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <PageSpinner />;
  if (!user) return <Navigate to="/login" state={{ from: location }} replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />
        <Route path="/verify" element={<VerifyPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <AppLayout />
            </RequireAuth>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="assessments" element={<AssessmentsPage />} />
          <Route path="assessments/new" element={<AssessmentWizardPage />} />
          <Route path="assessments/:id" element={<AssessmentDetailPage />} />
          <Route path="assessments/:id/assets" element={<AssetsPage />} />
          <Route path="assessments/:id/findings" element={<FindingsPage />} />
          <Route path="assessments/:id/findings/:findingId" element={<FindingDetailPage />} />
          <Route path="assessments/:id/attack-paths" element={<AttackPathsPage />} />
          <Route path="assessments/:id/remediation" element={<RemediationPage />} />
          <Route path="assessments/:id/reports" element={<ReportsPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}