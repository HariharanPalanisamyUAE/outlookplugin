import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'
import { AuthProvider } from './context/AuthContext'
import { Toaster } from 'react-hot-toast'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#1a1f36',
              color: '#fff',
              border: '1px solid #00f0ff',
            },
            success: {
              iconTheme: {
                primary: '#00ff94',
                secondary: '#0a0e27',
              },
            },
            error: {
              iconTheme: {
                primary: '#ff006e',
                secondary: '#0a0e27',
              },
            },
          }}
        />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
