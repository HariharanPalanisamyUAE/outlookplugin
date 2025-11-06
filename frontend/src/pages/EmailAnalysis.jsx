import { useState, useEffect } from 'react'
import { emailAPI } from '../services/api'
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  ArrowDownTrayIcon,
  EyeIcon,
  ShieldExclamationIcon,
  CheckCircleIcon,
  XCircleIcon,
} from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

export default function EmailAnalysis() {
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [filterPrediction, setFilterPrediction] = useState('all')
  const [filterDate, setFilterDate] = useState('today')
  const [selectedEmail, setSelectedEmail] = useState(null)
  const [showDetails, setShowDetails] = useState(false)

  useEffect(() => {
    fetchEmails()
  }, [filterPrediction, filterDate])

  const fetchEmails = async () => {
    setLoading(true)
    try {
      const result = await emailAPI.getEmails({
        prediction_filter: filterPrediction,
        date_filter: filterDate,
        limit: 100,
      })
      setEmails(result.emails || [])
    } catch (error) {
      toast.error('Failed to fetch emails')
    } finally {
      setLoading(false)
    }
  }

  const handleViewDetails = (email) => {
    setSelectedEmail(email)
    setShowDetails(true)
  }

  const handleAddToDatabase = async (email, type) => {
    try {
      await emailAPI.addToDatabase(email.id, type, email)
      toast.success(`Email added to ${type} database`)
      fetchEmails()
    } catch (error) {
      toast.error('Failed to add to database')
    }
  }

  const handleExport = () => {
    const csvContent = [
      ['Time', 'Date', 'Title', 'Prediction', 'Accuracy', 'User Email', 'Sender'],
      ...filteredEmails.map(email => [
        email.time,
        email.date,
        email.title,
        email.prediction,
        email.accuracy,
        email.userEmail,
        email.sender,
      ])
    ].map(row => row.join(',')).join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `email-analysis-${new Date().toISOString()}.csv`
    a.click()
    toast.success('Export completed')
  }

  const filteredEmails = emails.filter(email => {
    const matchesSearch =
      email.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      email.sender?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      email.userEmail?.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesSearch
  })

  const getPredictionBadge = (prediction) => {
    const badges = {
      'Safe': 'badge-success',
      'Spam': 'badge-warning',
      'Phishing': 'badge-danger',
    }
    return badges[prediction] || 'badge-info'
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Email Analysis</h1>
          <p className="text-gray-400 mt-1">Comprehensive email security analysis and monitoring</p>
        </div>
        <button
          onClick={handleExport}
          className="btn-primary flex items-center space-x-2"
        >
          <ArrowDownTrayIcon className="w-5 h-5" />
          <span>Export CSV</span>
        </button>
      </div>

      {/* Filters & Search */}
      <div className="card">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Search */}
          <div className="md:col-span-2">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search emails by subject, sender, or recipient..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input-field pl-10"
              />
            </div>
          </div>

          {/* Prediction Filter */}
          <div>
            <div className="relative">
              <FunnelIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <select
                value={filterPrediction}
                onChange={(e) => setFilterPrediction(e.target.value)}
                className="input-field pl-10 appearance-none"
              >
                <option value="all">All Types</option>
                <option value="safe">Safe</option>
                <option value="spam">Spam</option>
                <option value="phishing">Phishing</option>
              </select>
            </div>
          </div>

          {/* Date Filter */}
          <div>
            <select
              value={filterDate}
              onChange={(e) => setFilterDate(e.target.value)}
              className="input-field appearance-none"
            >
              <option value="today">Today</option>
              <option value="week">This Week</option>
              <option value="month">This Month</option>
              <option value="all">All Time</option>
            </select>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card bg-gradient-to-br from-blue-900/20 to-blue-700/20 border-blue-700/50">
          <p className="text-sm text-gray-300">Total Emails</p>
          <p className="text-2xl font-bold text-white mt-1">{filteredEmails.length}</p>
        </div>
        <div className="card bg-gradient-to-br from-green-900/20 to-green-700/20 border-green-700/50">
          <p className="text-sm text-gray-300">Safe</p>
          <p className="text-2xl font-bold text-white mt-1">
            {filteredEmails.filter(e => e.prediction === 'Safe').length}
          </p>
        </div>
        <div className="card bg-gradient-to-br from-yellow-900/20 to-yellow-700/20 border-yellow-700/50">
          <p className="text-sm text-gray-300">Spam</p>
          <p className="text-2xl font-bold text-white mt-1">
            {filteredEmails.filter(e => e.prediction === 'Spam').length}
          </p>
        </div>
        <div className="card bg-gradient-to-br from-red-900/20 to-red-700/20 border-red-700/50">
          <p className="text-sm text-gray-300">Phishing</p>
          <p className="text-2xl font-bold text-white mt-1">
            {filteredEmails.filter(e => e.prediction === 'Phishing').length}
          </p>
        </div>
      </div>

      {/* Email Table */}
      <div className="card">
        <div className="overflow-x-auto scrollbar-thin">
          {loading ? (
            <div className="flex justify-center py-12">
              <div className="w-12 h-12 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
            </div>
          ) : filteredEmails.length === 0 ? (
            <div className="text-center py-12">
              <ShieldExclamationIcon className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">No emails found</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-slate-800 sticky top-0">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Subject
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Sender
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Prediction
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Confidence
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredEmails.map((email, index) => (
                  <tr key={index} className="table-row">
                    <td className="px-4 py-3 text-sm text-gray-300 whitespace-nowrap">
                      <div>
                        <div className="font-medium">{email.time}</div>
                        <div className="text-xs text-gray-500">{email.date}</div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-white max-w-xs truncate">
                      {email.title}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {email.sender}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {email.userEmail}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`badge ${getPredictionBadge(email.prediction)}`}>
                        {email.prediction}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <div className="flex items-center">
                        <div className="w-full bg-slate-700 rounded-full h-2 mr-2">
                          <div
                            className={`h-2 rounded-full ${
                              parseFloat(email.accuracy) >= 70 ? 'bg-green-500' :
                              parseFloat(email.accuracy) >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                            }`}
                            style={{ width: email.accuracy }}
                          ></div>
                        </div>
                        <span className="text-gray-300 font-mono text-xs">{email.accuracy}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => handleViewDetails(email)}
                          className="p-1 text-blue-400 hover:text-blue-300 transition-colors"
                          title="View Details"
                        >
                          <EyeIcon className="w-5 h-5" />
                        </button>
                        {(email.prediction === 'Spam' || email.prediction === 'Phishing') && (
                          <button
                            onClick={() => handleAddToDatabase(email, email.prediction.toLowerCase())}
                            className="p-1 text-red-400 hover:text-red-300 transition-colors"
                            title="Add to Database"
                          >
                            <ShieldExclamationIcon className="w-5 h-5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Email Details Modal */}
      {showDetails && selectedEmail && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="card max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white">Email Details</h2>
              <button
                onClick={() => setShowDetails(false)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <XCircleIcon className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="label">Subject</label>
                <p className="text-white">{selectedEmail.title}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">From</label>
                  <p className="text-white">{selectedEmail.sender}</p>
                </div>
                <div>
                  <label className="label">To</label>
                  <p className="text-white">{selectedEmail.userEmail}</p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">Prediction</label>
                  <span className={`badge ${getPredictionBadge(selectedEmail.prediction)}`}>
                    {selectedEmail.prediction}
                  </span>
                </div>
                <div>
                  <label className="label">Confidence</label>
                  <p className="text-white font-mono">{selectedEmail.accuracy}</p>
                </div>
              </div>
              {selectedEmail.cc && (
                <div>
                  <label className="label">CC</label>
                  <p className="text-white">{selectedEmail.cc}</p>
                </div>
              )}
              <div>
                <label className="label">Email Content</label>
                <div className="bg-slate-900 p-4 rounded-lg border border-slate-700 max-h-96 overflow-y-auto">
                  <p className="text-gray-300 whitespace-pre-wrap">{selectedEmail.emailText || 'No content available'}</p>
                </div>
              </div>
              <div>
                <label className="label">Timestamp</label>
                <p className="text-white font-mono">{selectedEmail.date} {selectedEmail.time}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
