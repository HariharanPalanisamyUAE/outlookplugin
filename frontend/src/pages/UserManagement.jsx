import { useState } from 'react'
import { authAPI } from '../services/api'
import { UserPlusIcon, ShieldCheckIcon } from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

export default function UserManagement() {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    full_name: '',
  })
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)

    try {
      await authAPI.createUser(formData)
      toast.success('User created successfully')
      setFormData({ username: '', email: '', password: '', full_name: '' })
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create user')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">User Management</h1>
        <p className="text-gray-400 mt-1">Create and manage admin users</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="card-hover">
          <h2 className="text-xl font-bold text-white mb-6 flex items-center">
            <UserPlusIcon className="w-6 h-6 mr-2 text-cyber-primary" />
            Create New Admin
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="label">Username</label>
              <input
                type="text"
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                required
                className="input-field"
                placeholder="Enter username"
              />
            </div>

            <div>
              <label className="label">Email</label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                required
                className="input-field"
                placeholder="Enter email"
              />
            </div>

            <div>
              <label className="label">Full Name</label>
              <input
                type="text"
                value={formData.full_name}
                onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                className="input-field"
                placeholder="Enter full name"
              />
            </div>

            <div>
              <label className="label">Password</label>
              <input
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                required
                className="input-field"
                placeholder="Enter strong password"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary disabled:opacity-50"
            >
              {loading ? 'Creating...' : 'Create Admin User'}
            </button>
          </form>
        </div>

        <div className="card bg-gradient-to-br from-blue-900/20 to-purple-900/20 border-blue-700/50">
          <h2 className="text-xl font-bold text-white mb-4 flex items-center">
            <ShieldCheckIcon className="w-6 h-6 mr-2 text-cyber-primary" />
            Security Guidelines
          </h2>

          <div className="space-y-4 text-sm text-gray-300">
            <div className="p-3 bg-slate-800/50 rounded-lg">
              <p className="font-semibold text-white mb-1">Strong Passwords</p>
              <p>Use at least 12 characters with uppercase, lowercase, numbers, and symbols</p>
            </div>

            <div className="p-3 bg-slate-800/50 rounded-lg">
              <p className="font-semibold text-white mb-1">Unique Usernames</p>
              <p>Each admin must have a unique username and email address</p>
            </div>

            <div className="p-3 bg-slate-800/50 rounded-lg">
              <p className="font-semibold text-white mb-1">Role Management</p>
              <p>Admin users have full access to the SOC platform and all features</p>
            </div>

            <div className="p-3 bg-slate-800/50 rounded-lg">
              <p className="font-semibold text-white mb-1">Account Security</p>
              <p>All passwords are hashed using bcrypt with cost factor 12</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
