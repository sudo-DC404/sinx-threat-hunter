import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'react-hot-toast'

// Import components (to be created)
import Dashboard from './components/Dashboard/Dashboard'
import Login from './components/Auth/Login'
import SIEM from './components/SIEM/LogExplorer'
import ThreatIntel from './components/ThreatIntel/IOCManager'
import Alerts from './components/Alerts/AlertList'
import Hunts from './components/Hunts/HuntList'
import SOAR from './components/SOAR/PlaybookList'

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
})

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="min-h-screen bg-sinx-darker">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<Dashboard />} />
            <Route path="/siem" element={<SIEM />} />
            <Route path="/intel" element={<ThreatIntel />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/hunts" element={<Hunts />} />
            <Route path="/soar" element={<SOAR />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </BrowserRouter>
      <Toaster
        position="top-right"
        toastOptions={{
          className: 'bg-gray-800 text-white',
          duration: 4000,
        }}
      />
    </QueryClientProvider>
  )
}

export default App
