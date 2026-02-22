import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import ReleaseGate from './pages/Dashboard'
import EvidenceExplorer from './pages/VulnerabilityList'
import RiskIntelligence from './pages/RiskIntelligence'

function App() {
    return (
        <div style={{ display: 'flex', minHeight: '100vh', background: '#0a0a0a' }}>
            <Sidebar />
            <main style={{ flex: 1, overflow: 'auto' }}>
                <Routes>
                    <Route path="/" element={<ReleaseGate />} />
                    <Route path="/evidence" element={<EvidenceExplorer />} />
                    <Route path="/intelligence" element={<RiskIntelligence />} />
                </Routes>
            </main>
        </div>
    )
}

export default App
