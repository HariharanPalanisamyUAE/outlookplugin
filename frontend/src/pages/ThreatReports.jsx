import { useState, useEffect } from 'react'
import { userAPI } from '../services/api'
import { UsersIcon, ShieldExclamationIcon, FireIcon } from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

export default function ThreatReports() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchReports()
  }, [])

  const fetchReports = async () => {
    try {
      const result = await userAPI.getReports()
      setReports(result.users || [])
    } catch (error) {
      toast.error('Failed to fetch user reports')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">User Threat Reports</h1>
        <p className="text-gray-400 mt-1">Monitor spam and phishing detections per user</p>
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="w-12 h-12 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {reports.map((report, index) => (
            <div key={index} className="card-hover">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className="w-12 h-12 bg-gradient-to-br from-cyber-primary to-cyber-secondary rounded-full flex items-center justify-center">
                    <UsersIcon className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <p className="text-white font-medium">{report.user_email}</p>
                    <p className="text-xs text-gray-400">User Account</p>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex justify-between items-center p-2 bg-slate-800/50 rounded">
                  <span className="text-sm text-gray-300">Total Emails</span>
                  <span className="text-white font-bold">{report.total_emails}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-yellow-900/20 rounded border border-yellow-700/50">
                  <span className="text-sm text-gray-300">Spam</span>
                  <span className="text-yellow-400 font-bold">{report.spam_count}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-red-900/20 rounded border border-red-700/50">
                  <span className="text-sm text-gray-300">Phishing</span>
                  <span className="text-red-400 font-bold">{report.phishing_count}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-purple-900/20 rounded border border-purple-700/50">
                  <span className="text-sm text-gray-300">Threats Blocked</span>
                  <span className="text-purple-400 font-bold">{report.threats_blocked}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-blue-900/20 rounded border border-blue-700/50">
                  <span className="text-sm text-gray-300">Avg Confidence</span>
                  <span className="text-blue-400 font-bold">{report.avg_confidence}%</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
