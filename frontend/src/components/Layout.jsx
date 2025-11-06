import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import {
  HomeIcon,
  EnvelopeIcon,
  ShieldExclamationIcon,
  UsersIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
  BellAlertIcon,
} from '@heroicons/react/24/outline'
import { useState } from 'react'

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [notifications] = useState(3)

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const navigation = [
    { name: 'Dashboard', href: '/', icon: HomeIcon },
    { name: 'Email Analysis', href: '/emails', icon: EnvelopeIcon },
    { name: 'Threat Reports', href: '/threats', icon: ShieldExclamationIcon },
    { name: 'User Management', href: '/users', icon: UsersIcon },
    { name: 'Settings', href: '/settings', icon: Cog6ToothIcon },
  ]

  return (
    <div className="min-h-screen bg-cyber-darker">
      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-800 shadow-xl sticky top-0 z-50 backdrop-blur-sm bg-opacity-90">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo & Title */}
            <div className="flex items-center space-x-4">
              <div className="flex items-center">
                <div className="w-10 h-10 bg-gradient-to-br from-cyber-primary to-cyber-secondary rounded-lg flex items-center justify-center">
                  <ShieldExclamationIcon className="w-6 h-6 text-white" />
                </div>
                <div className="ml-3">
                  <h1 className="text-xl font-bold text-white">Email Security Monitor</h1>
                  <p className="text-xs text-gray-400">Enterprise SOC Platform</p>
                </div>
              </div>
            </div>

            {/* Status & Controls */}
            <div className="flex items-center space-x-4">
              {/* Connection Status */}
              <div className="flex items-center space-x-2 px-3 py-1 bg-green-900/30 border border-green-700 rounded-full">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-xs font-medium text-green-300">System Online</span>
              </div>

              {/* Notifications */}
              <button className="relative p-2 text-gray-400 hover:text-white transition-colors duration-200">
                <BellAlertIcon className="w-6 h-6" />
                {notifications > 0 && (
                  <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center animate-pulse">
                    {notifications}
                  </span>
                )}
              </button>

              {/* User Menu */}
              <div className="flex items-center space-x-3">
                <div className="text-right">
                  <p className="text-sm font-medium text-white">{user?.username}</p>
                  <p className="text-xs text-gray-400">Administrator</p>
                </div>
                <button
                  onClick={handleLogout}
                  className="p-2 text-gray-400 hover:text-red-400 transition-colors duration-200"
                  title="Logout"
                >
                  <ArrowRightOnRectangleIcon className="w-6 h-6" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 bg-slate-900 border-r border-slate-800 min-h-[calc(100vh-4rem)] sticky top-16">
          <nav className="p-4 space-y-2">
            {navigation.map((item) => (
              <NavLink
                key={item.name}
                to={item.href}
                end={item.href === '/'}
                className={({ isActive }) =>
                  `flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                    isActive
                      ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/50'
                      : 'text-gray-400 hover:bg-slate-800 hover:text-white'
                  }`
                }
              >
                <item.icon className="w-5 h-5" />
                <span className="font-medium">{item.name}</span>
              </NavLink>
            ))}
          </nav>

          {/* Sidebar Footer */}
          <div className="absolute bottom-4 left-4 right-4">
            <div className="card p-4">
              <p className="text-xs text-gray-400 mb-2">System Health</p>
              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-gray-400">API</span>
                  <span className="text-green-400">Online</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-gray-400">Database</span>
                  <span className="text-green-400">Connected</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-gray-400">AI Model</span>
                  <span className="text-green-400">Active</span>
                </div>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-8 cyber-grid">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
