import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { ThemeProvider } from '@/contexts/ThemeContext'
import { AuthProvider } from '@/contexts/AuthContext'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import LandingPage from '@/pages/LandingPage'
import LoginPage from '@/pages/LoginPage'
import RegisterPage from '@/pages/RegisterPage'
import VerifyEmailPage from '@/pages/VerifyEmailPage'
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
          <div className="min-h-screen bg-background text-slate-900 dark:text-slate-100">
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />
              <Route path="/verify-email" element={<VerifyEmailPage />} />
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
