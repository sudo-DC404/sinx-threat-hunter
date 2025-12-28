import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

interface Stats {
  total_logs: number
  total_alerts: number
  total_iocs: number
  critical_alerts: number
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    total_logs: 0,
    total_alerts: 0,
    total_iocs: 0,
    critical_alerts: 0,
  })

  const [ws, setWs] = useState<WebSocket | null>(null)

  useEffect(() => {
    // Connect to WebSocket for real-time updates
    const websocket = new WebSocket('ws://localhost:8000/ws')

    websocket.onopen = () => {
      console.log('WebSocket connected')
    }

    websocket.onmessage = (event) => {
      const data = JSON.parse(event.data)
      console.log('WebSocket message:', data)
      // Handle real-time updates
    }

    websocket.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    setWs(websocket)

    return () => {
      websocket.close()
    }
  }, [])

  return (
    <div className="min-h-screen bg-gradient-to-br from-sinx-darker via-sinx-dark to-sinx-darker">
      {/* Header */}
      <header className="border-b border-gray-800 bg-sinx-darker/80 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-br from-sinx-primary to-sinx-secondary rounded-lg flex items-center justify-center">
                <span className="text-2xl font-bold">S</span>
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gradient">sinX Threat Hunter</h1>
                <p className="text-xs text-gray-400">Enterprise Threat Hunting Platform</p>
              </div>
            </div>
            <nav className="flex space-x-6">
              <Link to="/" className="text-white hover:text-sinx-primary transition">Dashboard</Link>
              <Link to="/siem" className="text-gray-400 hover:text-white transition">SIEM</Link>
              <Link to="/intel" className="text-gray-400 hover:text-white transition">Threat Intel</Link>
              <Link to="/alerts" className="text-gray-400 hover:text-white transition">Alerts</Link>
              <Link to="/hunts" className="text-gray-400 hover:text-white transition">Hunts</Link>
              <Link to="/soar" className="text-gray-400 hover:text-white transition">SOAR</Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatsCard
            title="Total Logs"
            value={stats.total_logs.toLocaleString()}
            icon="📊"
            color="blue"
          />
          <StatsCard
            title="Active Alerts"
            value={stats.total_alerts.toLocaleString()}
            icon="🚨"
            color="red"
          />
          <StatsCard
            title="IOCs"
            value={stats.total_iocs.toLocaleString()}
            icon="🎯"
            color="yellow"
          />
          <StatsCard
            title="Critical"
            value={stats.critical_alerts.toLocaleString()}
            icon="⚠️"
            color="red"
          />
        </div>

        {/* Welcome Message */}
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-8 mb-8">
          <h2 className="text-3xl font-bold mb-4">Welcome to sinX Threat Hunter</h2>
          <p className="text-gray-300 mb-4">
            Enterprise-grade threat hunting platform built from the ground up to compete with
            CrowdStrike Falcon, SentinelOne, and Splunk ES.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
            <Feature
              title="Real-time SIEM"
              description="Ingest, parse, and analyze logs from any source in real-time"
            />
            <Feature
              title="Threat Intelligence"
              description="Automated IOC management with multiple threat feed integrations"
            />
            <Feature
              title="SOAR Automation"
              description="Build and execute automated response playbooks"
            />
          </div>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <ActionCard
            title="Start Threat Hunt"
            description="Begin a new threat hunting session"
            link="/hunts"
            icon="🔍"
          />
          <ActionCard
            title="View Alerts"
            description="Review and investigate active alerts"
            link="/alerts"
            icon="🚨"
          />
          <ActionCard
            title="Manage IOCs"
            description="Add and manage threat indicators"
            link="/intel"
            icon="🎯"
          />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-12">
        <div className="container mx-auto px-6 py-4 text-center text-gray-500 text-sm">
          sinX Threat Hunter v1.0.0 | Enterprise Threat Hunting Platform
        </div>
      </footer>
    </div>
  )
}

function StatsCard({ title, value, icon, color }: { title: string; value: string; icon: string; color: string }) {
  const colorClasses = {
    blue: 'from-blue-500/20 to-blue-600/20 border-blue-500/30',
    red: 'from-red-500/20 to-red-600/20 border-red-500/30',
    yellow: 'from-yellow-500/20 to-yellow-600/20 border-yellow-500/30',
    green: 'from-green-500/20 to-green-600/20 border-green-500/30',
  }

  return (
    <div className={`bg-gradient-to-br ${colorClasses[color as keyof typeof colorClasses]} border rounded-lg p-6`}>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
        <span className="text-2xl">{icon}</span>
      </div>
      <p className="text-3xl font-bold">{value}</p>
    </div>
  )
}

function Feature({ title, description }: { title: string; description: string }) {
  return (
    <div className="bg-gray-900/50 border border-gray-700 rounded-lg p-4">
      <h3 className="font-semibold mb-2">{title}</h3>
      <p className="text-sm text-gray-400">{description}</p>
    </div>
  )
}

function ActionCard({ title, description, link, icon }: { title: string; description: string; link: string; icon: string }) {
  return (
    <Link
      to={link}
      className="bg-gray-800/50 border border-gray-700 rounded-lg p-6 hover:border-sinx-primary transition group"
    >
      <div className="text-4xl mb-3">{icon}</div>
      <h3 className="text-xl font-semibold mb-2 group-hover:text-sinx-primary transition">{title}</h3>
      <p className="text-gray-400 text-sm">{description}</p>
    </Link>
  )
}
