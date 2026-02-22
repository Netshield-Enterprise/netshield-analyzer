import { useState, useEffect } from 'react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'

const RiskIntelligence = () => {
    const [trends, setTrends] = useState(null)
    const [scans, setScans] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)

    useEffect(() => {
        loadData()
    }, [])

    const loadData = async () => {
        try {
            const [trendRes, scanRes] = await Promise.all([
                fetch('/api/trends'),
                fetch('/api/scans'),
            ])

            if (trendRes.status === 403) {
                setError('premium')
            } else if (trendRes.ok) {
                setTrends(await trendRes.json())
            }

            if (scanRes.ok) {
                setScans(await scanRes.json())
            }
        } catch (err) {
            setError('Failed to load data')
        } finally {
            setLoading(false)
        }
    }

    const s = {
        page: { padding: '2rem', maxWidth: '1100px' },
        card: { background: '#1a1a1a', border: '1px solid #27272a', borderRadius: '0.5rem', padding: '1.5rem', marginBottom: '1.5rem' },
        mono: { fontFamily: "'JetBrains Mono', monospace" },
    }

    if (loading) {
        return <div style={{ ...s.page, textAlign: 'center', paddingTop: '4rem' }}><div className="spinner" style={{ margin: '0 auto' }} /></div>
    }

    if (error === 'premium') {
        return (
            <div style={s.page}>
                <h1 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '0.5rem' }}>Risk Intelligence</h1>
                <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginBottom: '2rem' }}>Historical trends and supply chain analysis</p>

                <div style={{ ...s.card, textAlign: 'center', padding: '4rem 2rem' }}>
                    <span style={{ fontSize: '2.5rem', display: 'block', marginBottom: '1rem' }}>📊</span>
                    <h2 style={{ fontSize: '1.125rem', fontWeight: '600', marginBottom: '0.5rem' }}>Pro Feature</h2>
                    <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginBottom: '1.5rem', maxWidth: '400px', margin: '0 auto 1.5rem' }}>
                        Historical trends, scan comparison, and dependency risk analysis require a Pro or Enterprise license.
                    </p>
                    <div style={{ ...s.mono, fontSize: '0.8rem', color: '#52525b', background: '#141414', padding: '0.75rem 1.5rem', borderRadius: '0.375rem', display: 'inline-block' }}>
                        export NETSHIELD_LICENSE_KEY=your-key
                    </div>
                </div>
            </div>
        )
    }

    return (
        <div style={s.page}>
            <div style={{ marginBottom: '2rem', paddingBottom: '1rem', borderBottom: '1px solid #27272a' }}>
                <h1 style={{ fontSize: '1.25rem', fontWeight: '600' }}>Risk Intelligence</h1>
                <p style={{ color: '#a1a1aa', fontSize: '0.875rem' }}>Vulnerability trends over time</p>
            </div>

            {/* Trend Chart */}
            {trends && trends.length > 0 ? (
                <div style={s.card}>
                    <h3 style={{ fontSize: '0.875rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#a1a1aa', marginBottom: '1rem' }}>
                        Vulnerability Trend (30 days)
                    </h3>
                    <div style={{ height: '300px' }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={trends}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                                <XAxis dataKey="date" stroke="#52525b" fontSize={11} fontFamily="JetBrains Mono" />
                                <YAxis stroke="#52525b" fontSize={11} fontFamily="JetBrains Mono" />
                                <Tooltip
                                    contentStyle={{ background: '#1a1a1a', border: '1px solid #27272a', borderRadius: '0.375rem', fontFamily: 'JetBrains Mono', fontSize: '0.75rem' }}
                                    labelStyle={{ color: '#fff' }}
                                />
                                <Line type="monotone" dataKey="total_vulns" stroke="#a1a1aa" strokeWidth={1.5} dot={false} name="Total" />
                                <Line type="monotone" dataKey="reachable" stroke="#ef4444" strokeWidth={2} dot={false} name="Reachable" />
                                <Line type="monotone" dataKey="unreachable" stroke="#10b981" strokeWidth={1.5} dot={false} name="Unreachable" />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            ) : (
                <div style={{ ...s.card, textAlign: 'center', color: '#52525b', padding: '3rem' }}>
                    No trend data yet. Run multiple analyses over time to see trends.
                </div>
            )}

            {/* Scan History */}
            {scans && scans.length > 0 && (
                <div style={s.card}>
                    <h3 style={{ fontSize: '0.875rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#a1a1aa', marginBottom: '1rem' }}>
                        Scan History
                    </h3>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid #27272a' }}>
                                {['Scan', 'Timestamp', 'Total', 'Reachable', 'Unreachable'].map(h => (
                                    <th key={h} style={{ textAlign: 'left', padding: '0.5rem', fontSize: '0.7rem', color: '#52525b', fontWeight: '500', textTransform: 'uppercase' }}>{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {scans.map((scan, i) => (
                                <tr key={i} style={{ borderBottom: '1px solid #1e1e1e' }}>
                                    <td style={{ padding: '0.5rem', ...s.mono, fontSize: '0.75rem', color: '#00d4ff' }}>{scan.id?.slice(0, 16)}</td>
                                    <td style={{ padding: '0.5rem', fontSize: '0.75rem', color: '#a1a1aa' }}>
                                        {scan.timestamp ? new Date(scan.timestamp).toLocaleString() : 'N/A'}
                                    </td>
                                    <td style={{ padding: '0.5rem', ...s.mono, fontSize: '0.8rem', fontWeight: '600' }}>{scan.total_vulns}</td>
                                    <td style={{ padding: '0.5rem', ...s.mono, fontSize: '0.8rem', fontWeight: '600', color: '#ef4444' }}>{scan.reachable}</td>
                                    <td style={{ padding: '0.5rem', ...s.mono, fontSize: '0.8rem', fontWeight: '600', color: '#10b981' }}>{scan.unreachable}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    )
}

export default RiskIntelligence
