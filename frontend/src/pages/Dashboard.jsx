import { useState, useEffect } from 'react'
import { dashboardAPI } from '../services/api'
import { Line, Doughnut } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import {
  EnvelopeIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  FireIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
} from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
)

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdate, setLastUpdate] = useState(new Date())

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 30000) // Update every 30 seconds
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      const result = await dashboardAPI.getData()
      setData(result)
      setLastUpdate(new Date())
    } catch (error) {
      toast.error('Failed to fetch dashboard data')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto"></div>
          <p className="mt-4 text-gray-400">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  const metrics = [
    {
      name: 'Total Processed',
      value: data?.total_processed || 0,
      change: '+12%',
      trend: 'up',
      icon: EnvelopeIcon,
      color: 'blue',
      bgGradient: 'from-blue-500/20 to-blue-700/20',
    },
    {
      name: 'Threats Blocked',
      value: data?.threats_blocked || 0,
      change: '+8%',
      trend: 'up',
      icon: ShieldCheckIcon,
      color: 'red',
      bgGradient: 'from-red-500/20 to-red-700/20',
    },
    {
      name: 'Spam Detected',
      value: data?.email_stats?.spam || 0,
      change: '-5%',
      trend: 'down',
      icon: ExclamationTriangleIcon,
      color: 'yellow',
      bgGradient: 'from-yellow-500/20 to-yellow-700/20',
    },
    {
      name: 'Phishing Blocked',
      value: data?.email_stats?.phishing || 0,
      change: '+15%',
      trend: 'up',
      icon: FireIcon,
      color: 'purple',
      bgGradient: 'from-purple-500/20 to-purple-700/20',
    },
  ]

  // Doughnut Chart Data
  const doughnutData = {
    labels: ['Safe Emails', 'Spam', 'Phishing'],
    datasets: [
      {
        data: [
          data?.email_stats?.ham || 0,
          data?.email_stats?.spam || 0,
          data?.email_stats?.phishing || 0,
        ],
        backgroundColor: [
          'rgba(34, 197, 94, 0.8)',
          'rgba(251, 191, 36, 0.8)',
          'rgba(239, 68, 68, 0.8)',
        ],
        borderColor: [
          'rgb(34, 197, 94)',
          'rgb(251, 191, 36)',
          'rgb(239, 68, 68)',
        ],
        borderWidth: 2,
      },
    ],
  }

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#9ca3af',
          padding: 20,
          usePointStyle: true,
        },
      },
      tooltip: {
        backgroundColor: 'rgba(15, 18, 25, 0.9)',
        titleColor: '#fff',
        bodyColor: '#9ca3af',
        borderColor: '#00f0ff',
        borderWidth: 1,
      },
    },
    cutout: '65%',
  }

  // Line Chart Data
  const hours = Array.from({ length: 24 }, (_, i) => `${i.toString().padStart(2, '0')}:00`)
  const activityData = hours.map((hour) => data?.hourly_activity?.[hour.split(':')[0]] || 0)
  const threatsData = hours.map((hour) => data?.hourly_threats?.[hour.split(':')[0]] || 0)

  const lineData = {
    labels: hours,
    datasets: [
      {
        label: 'Email Processing',
        data: activityData,
        borderColor: 'rgb(0, 240, 255)',
        backgroundColor: 'rgba(0, 240, 255, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Threats Detected',
        data: threatsData,
        borderColor: 'rgb(239, 68, 68)',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        fill: true,
        tension: 0.4,
      },
    ],
  }

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: '#9ca3af',
          usePointStyle: true,
        },
      },
      tooltip: {
        backgroundColor: 'rgba(15, 18, 25, 0.9)',
        titleColor: '#fff',
        bodyColor: '#9ca3af',
        borderColor: '#00f0ff',
        borderWidth: 1,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: 'rgba(75, 85, 99, 0.2)',
        },
        ticks: {
          color: '#9ca3af',
        },
      },
      x: {
        grid: {
          color: 'rgba(75, 85, 99, 0.2)',
        },
        ticks: {
          color: '#9ca3af',
          maxRotation: 45,
          minRotation: 45,
        },
      },
    },
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Operations Center</h1>
          <p className="text-gray-400 mt-1">Real-time email threat monitoring and analytics</p>
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-400">Last Updated</p>
          <p className="text-cyber-primary font-mono">{lastUpdate.toLocaleTimeString()}</p>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {metrics.map((metric, index) => (
          <div
            key={metric.name}
            className="card-hover group"
            style={{ animationDelay: `${index * 100}ms` }}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm font-medium uppercase tracking-wide">
                  {metric.name}
                </p>
                <p className="text-3xl font-bold text-white mt-2">{metric.value.toLocaleString()}</p>
                <div className="flex items-center mt-2 text-sm">
                  {metric.trend === 'up' ? (
                    <ArrowTrendingUpIcon className="w-4 h-4 text-green-400 mr-1" />
                  ) : (
                    <ArrowTrendingDownIcon className="w-4 h-4 text-red-400 mr-1" />
                  )}
                  <span className={metric.trend === 'up' ? 'text-green-400' : 'text-red-400'}>
                    {metric.change}
                  </span>
                  <span className="text-gray-500 ml-1">vs yesterday</span>
                </div>
              </div>
              <div className={`p-4 rounded-xl bg-gradient-to-br ${metric.bgGradient} group-hover:scale-110 transition-transform`}>
                <metric.icon className={`w-8 h-8 text-${metric.color}-400`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Threat Distribution Chart */}
        <div className="card-hover">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-blue-500 to-purple-600 p-2 rounded-lg">
                <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M2 10a8 8 0 018-8v8h8a8 8 0 11-16 0z" />
                  <path d="M12 2.252A8.014 8.014 0 0117.748 8H12V2.252z" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white">Threat Distribution</h3>
                <p className="text-gray-400 text-sm">Real-time email classification</p>
              </div>
            </div>
          </div>
          <div className="h-80">
            <Doughnut data={doughnutData} options={doughnutOptions} />
          </div>
        </div>

        {/* Activity Timeline */}
        <div className="card-hover">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-green-500 to-blue-600 p-2 rounded-lg">
                <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white">24-Hour Activity</h3>
                <p className="text-gray-400 text-sm">Email processing timeline</p>
              </div>
            </div>
          </div>
          <div className="h-80">
            <Line data={lineData} options={lineOptions} />
          </div>
        </div>
      </div>

      {/* Recent Threats & System Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Recent Threats */}
        <div className="lg:col-span-2 card-hover">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <FireIcon className="w-5 h-5 text-red-400 mr-2" />
            Recent Threats
          </h3>
          <div className="space-y-3 max-h-96 overflow-y-auto scrollbar-thin">
            {data?.recent_threats?.slice(0, 10).map((threat, index) => (
              <div
                key={index}
                className="p-4 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-red-500/50 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className={`badge ${
                        threat.threat_type === 'phishing' ? 'badge-danger' : 'badge-warning'
                      }`}>
                        {threat.threat_type?.toUpperCase()}
                      </span>
                      <span className="text-xs text-gray-500">
                        {new Date(threat.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-white font-medium mb-1">{threat.subject}</p>
                    <p className="text-sm text-gray-400">From: {threat.sender}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-400">Confidence</p>
                    <p className="text-lg font-bold text-cyber-primary">
                      {(threat.confidence * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* System Health */}
        <div className="card-hover">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <ShieldCheckIcon className="w-5 h-5 text-green-400 mr-2" />
            System Health
          </h3>
          <div className="space-y-4">
            <div className="p-3 bg-green-900/20 rounded-lg border border-green-700/50">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-300">API Server</span>
                <span className="badge-success">Online</span>
              </div>
            </div>
            <div className="p-3 bg-green-900/20 rounded-lg border border-green-700/50">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-300">Database</span>
                <span className="badge-success">Connected</span>
              </div>
            </div>
            <div className="p-3 bg-green-900/20 rounded-lg border border-green-700/50">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-300">AI Model</span>
                <span className="badge-success">Active</span>
              </div>
            </div>
            <div className="p-3 bg-blue-900/20 rounded-lg border border-blue-700/50">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-300">OpenAI</span>
                <span className="badge-info">Integrated</span>
              </div>
            </div>

            {/* Performance Metrics */}
            <div className="mt-6">
              <h4 className="text-sm font-medium text-white mb-3">Performance</h4>
              <div className="space-y-3">
                <div>
                  <div className="flex justify-between text-xs text-gray-400 mb-1">
                    <span>CPU Usage</span>
                    <span>23%</span>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-2">
                    <div className="bg-green-500 h-2 rounded-full" style={{ width: '23%' }}></div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs text-gray-400 mb-1">
                    <span>Memory</span>
                    <span>67%</span>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-2">
                    <div className="bg-yellow-500 h-2 rounded-full" style={{ width: '67%' }}></div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs text-gray-400 mb-1">
                    <span>Network</span>
                    <span>45%</span>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-2">
                    <div className="bg-blue-500 h-2 rounded-full" style={{ width: '45%' }}></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
