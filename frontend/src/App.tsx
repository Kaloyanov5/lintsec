import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { ThemeProvider } from '@/contexts/ThemeContext'
import { AuthProvider } from '@/contexts/AuthContext'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { GuestRoute } from '@/components/GuestRoute'
import { ThemedToaster } from '@/components/ui/ThemedToaster'
import LandingPage from '@/pages/LandingPage'
import LoginPage from '@/pages/LoginPage'
import RegisterPage from '@/pages/RegisterPage'
import VerifyEmailPage from '@/pages/VerifyEmailPage'
import OAuthCallbackPage from '@/pages/OAuthCallbackPage'
import DashboardPage from '@/pages/DashboardPage'
import NewScanPage from '@/pages/NewScanPage'
import ScanResultsPage from '@/pages/ScanResultsPage'
import ScanHistoryPage from '@/pages/ScanHistoryPage'
import NotFoundPage from '@/pages/NotFoundPage'

function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <AuthProvider>
          <div className="min-h-screen">
            <ThemedToaster />
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route element={<GuestRoute />}>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />
              </Route>
              <Route path="/verify-email" element={<VerifyEmailPage />} />
              <Route path="/auth/callback" element={<OAuthCallbackPage />} />
              <Route element={<ProtectedRoute />}>
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/scans/new" element={<NewScanPage />} />
                <Route path="/scans/history" element={<ScanHistoryPage />} />
                <Route path="/scans/:id" element={<ScanResultsPage />} />
              </Route>
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </div>
        </AuthProvider>
      </BrowserRouter>
    </ThemeProvider>
  )
}

export default App
