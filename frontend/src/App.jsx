import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import EmailAnalysis from './pages/EmailAnalysis'
import ThreatReports from './pages/ThreatReports'
import UserManagement from './pages/UserManagement'
import Settings from './pages/Settings'
import Layout from './components/Layout'
import LoadingSpinner from './components/LoadingSpinner'

function PrivateRoute({ children }) {
  const { user, loading } = useAuth()

  if (loading) {
    return <LoadingSpinner />
  }

  return user ? children : <Navigate to="/login" />
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route path="/" element={
        <PrivateRoute>
          <Layout />
        </PrivateRoute>
      }>
        <Route index element={<Dashboard />} />
        <Route path="emails" element={<EmailAnalysis />} />
        <Route path="threats" element={<ThreatReports />} />
        <Route path="users" element={<UserManagement />} />
        <Route path="settings" element={<Settings />} />
      </Route>

      <Route path="*" element={<Navigate to="/" />} />
    </Routes>
  )
}

export default App
