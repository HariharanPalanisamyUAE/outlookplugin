import { createContext, useContext, useState, useEffect } from 'react'
import { authAPI } from '../services/api'
import toast from 'react-hot-toast'

const AuthContext = createContext(null)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    const token = localStorage.getItem('access_token')
    if (token) {
      try {
        const userData = await authAPI.verify()
        setUser(userData)
      } catch (error) {
        console.error('Auth verification failed:', error)
        localStorage.removeItem('access_token')
      }
    }
    setLoading(false)
  }

  const login = async (username, password) => {
    try {
      const response = await authAPI.login(username, password)
      localStorage.setItem('access_token', response.access_token)
      const userData = await authAPI.verify()
      setUser(userData)
      toast.success('Welcome back!')
      return true
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed')
      return false
    }
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    setUser(null)
    toast.success('Logged out successfully')
  }

  const value = {
    user,
    login,
    logout,
    loading,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
