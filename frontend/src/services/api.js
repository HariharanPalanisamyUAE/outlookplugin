import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Authentication API
export const authAPI = {
  login: async (username, password) => {
    const formData = new URLSearchParams()
    formData.append('username', username)
    formData.append('password', password)

    const response = await axios.post(`${API_URL}/api/admin/login`, formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })
    return response.data
  },

  verify: async () => {
    const response = await api.get('/api/admin/verify')
    return response.data
  },

  createUser: async (userData) => {
    const response = await api.post('/api/admin/create-user', userData)
    return response.data
  },
}

// Dashboard API
export const dashboardAPI = {
  getData: async () => {
    const response = await api.get('/api/dashboard-data')
    return response.data
  },

  getStatistics: async () => {
    const response = await api.get('/api/threat-statistics')
    return response.data
  },
}

// Email Analysis API
export const emailAPI = {
  getEmails: async (params = {}) => {
    const response = await api.get('/api/email-data', { params })
    return response.data
  },

  analyzeEmail: async (emailData) => {
    const response = await api.post('/api/analyze-email', emailData)
    return response.data
  },

  reportThreat: async (threatData) => {
    const response = await api.post('/api/report-threat', threatData)
    return response.data
  },

  logAction: async (action) => {
    const response = await api.post('/api/log-action', { action })
    return response.data
  },

  addToDatabase: async (emailId, databaseType, emailData) => {
    const response = await api.post('/api/add-to-database', {
      emailId,
      databaseType,
      emailData,
    })
    return response.data
  },
}

// User Reports API
export const userAPI = {
  getReports: async (userEmail = null) => {
    const params = userEmail ? { user_email: userEmail } : {}
    const response = await api.get('/api/user-reports', { params })
    return response.data
  },
}

// Threat Reports API
export const threatAPI = {
  getReports: async () => {
    const response = await api.get('/api/threat-reports')
    return response.data
  },
}

// Database Stats API
export const databaseAPI = {
  getStats: async () => {
    const response = await api.get('/api/database-stats')
    return response.data
  },
}

// Health Check API
export const healthAPI = {
  check: async () => {
    const response = await api.get('/health')
    return response.data
  },
}

export default api
