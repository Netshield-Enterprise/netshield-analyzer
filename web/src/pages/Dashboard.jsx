import { useState, useEffect } from 'react'

const ReleaseGate = () => {
    const [summary, setSummary] = useState(null)
    const [vulns, setVulns] = useState([])
    const [diff, setDiff] = useState(null)
    const [loading, setLoading] = useState(false)
    const [analyzing, setAnalyzing] = useState(false)
    const [error, setError] = useState(null)

    const fetchData = async () => {
        try {
            const [sumRes, vulnRes] = await Promise.all([
                fetch('/api/summary'),
                fetch('/api/vulnerabilities'),
            ])
            if (sumRes.ok) {
                setSummary(await sumRes.json())
                setError(null)
            } else if (sumRes.status === 404) {
                setError('no-analysis')
            }
            if (vulnRes.ok) {
                setVulns(await vulnRes.json() || [])
            }

            // Try diff (premium, may 403)
            try {
                const diffRes = await fetch('/api/diff')
                if (diffRes.ok) {
                    const d = await diffRes.json()
                    if (!d.message) setDiff(d)
                }
            } catch (e) { /* ignore */ }
        } catch (err) {
            setError('Failed to fetch data')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        setLoading(true)
        fetchData()
    }, [])

    const runAnalysis = async () => {
        setAnalyzing(true)
        setError(null)
        try {
            const res = await fetch('/api/analyze', { method: 'POST' })
            if (!res.ok) {
                const data = await res.json().catch(() => null)
                const msg = data?.error || `Analysis failed (HTTP ${res.status})`
                setError(msg)
            } else {
                await fetchData()
            }
        } catch (err) {
            setError(`Analysis error: ${err.message}`)
        } finally {
            setAnalyzing(false)
        }
    }

    // Compute live stats from vulns array (survives server restarts since vulns come from DB)
    const liveStats = (() => {
        if (vulns.length > 0) {
            const reachable = vulns.filter(v => v.status === 'REACHABLE').length
            const unreachable = vulns.filter(v => v.status === 'UNREACHABLE').length
            const unknown = vulns.filter(v => v.status !== 'REACHABLE' && v.status !== 'UNREACHABLE').length
            return { total: vulns.length, reachable, unreachable, unknown }
        }
        if (summary && summary.total > 0) {
            return { total: summary.total, reachable: summary.reachable || 0, unreachable: summary.unreachable || 0, unknown: summary.unknown || 0 }
        }
        return null
    })()

    // Release decision
    const getDecision = () => {
        if (!liveStats) return null
        const reachable = vulns.filter(v => v.status === 'REACHABLE')
        const criticalReachable = reachable.filter(v =>
            ['critical', 'high'].includes(v.vulnerability?.severity?.toLowerCase())
        )
        if (criticalReachable.length > 0) return { blocked: true, reason: `${criticalReachable.length} critical/high reachable CVE${criticalReachable.length > 1 ? 's' : ''}` }
        if (reachable.length > 0) return { blocked: true, reason: `${reachable.length} reachable CVE${reachable.length > 1 ? 's' : ''}` }
        if (liveStats.unknown > 0) return { blocked: false, reason: `${liveStats.unknown} unknown-status vulnerabilities — review recommended` }
        return { blocked: false, reason: 'All vulnerabilities are unreachable' }
    }

    // Top blockers
    const getBlockers = () => {
        const severityOrder = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3 }
        return vulns
            .filter(v => v.status === 'REACHABLE')
            .sort((a, b) => (severityOrder[a.vulnerability?.severity?.toLowerCase()] || 4) - (severityOrder[b.vulnerability?.severity?.toLowerCase()] || 4))
            .slice(0, 5)
    }

    // Confidence — UNKNOWN vulns penalize at 50% (could be reachable)
    const getConfidence = () => {
        if (!liveStats || liveStats.total === 0) return { pct: 0, label: 'N/A', staticCoverage: 0, reflectionUncertainty: 0 }
        const { total, unreachable, reachable, unknown } = liveStats
        const weightedSafe = unreachable + (unknown * 0.5)
        const pct = Math.round((weightedSafe / total) * 100)
        const label = pct >= 80 ? 'HIGH' : pct >= 50 ? 'MEDIUM' : 'LOW'
        const staticCoverage = Math.round(((unreachable + reachable) / total) * 100)
        const reflectionUncertainty = Math.round((unknown / total) * 100)
        return { pct, label, staticCoverage, reflectionUncertainty }
    }

    const s = {
        page: { padding: '2rem', maxWidth: '1100px' },
        header: {
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            marginBottom: '2rem', paddingBottom: '1rem', borderBottom: '1px solid #27272a',
        },
        btn: {
            background: '#00d4ff', color: '#0a0a0a', border: 'none',
            padding: '0.5rem 1.25rem', borderRadius: '0.375rem', fontWeight: '600',
            cursor: 'pointer', fontFamily: "'Inter', sans-serif", fontSize: '0.875rem',
        },
        card: {
            background: '#1a1a1a', border: '1px solid #27272a',
            borderRadius: '0.5rem', padding: '1.5rem', marginBottom: '1.5rem',
        },
        muted: { color: '#52525b', fontSize: '0.8rem', marginTop: '0.25rem' },
        mono: { fontFamily: "'JetBrains Mono', monospace" },
    }

    if (loading) {
        return <div style={{ ...s.page, textAlign: 'center', paddingTop: '4rem' }}><div className="spinner" style={{ margin: '0 auto' }} /></div>
    }

    const hasData = liveStats !== null || summary !== null
    const decision = getDecision()
    const blockers = getBlockers()
    const confidence = getConfidence()

    // Severity distribution from vulns
    const sevCounts = {}
    vulns.forEach(v => {
        const sev = (v.vulnerability?.severity || 'unknown').toLowerCase()
        sevCounts[sev] = (sevCounts[sev] || 0) + 1
    })
    const sevData = Object.keys(sevCounts).length > 0 ? sevCounts : summary?.by_severity

    return (
        <div style={s.page}>
            {/* Header */}
            <div style={s.header}>
                <div>
                    <h1 style={{ fontSize: '1.25rem', fontWeight: '600' }}>Release Gate</h1>
                    <p style={s.muted}>Can I ship?</p>
                </div>
                <button onClick={runAnalysis} disabled={analyzing} style={{ ...s.btn, opacity: analyzing ? 0.6 : 1 }}>
                    {analyzing ? 'Analyzing...' : '▶ Run Analysis'}
                </button>
            </div>

            {/* Error / No Analysis */}
            {error === 'no-analysis' && (
                <div style={{ ...s.card, textAlign: 'center', padding: '3rem' }}>
                    <span style={{ fontSize: '2rem', display: 'block', marginBottom: '0.75rem' }}>🔍</span>
                    <p style={{ fontSize: '1rem', fontWeight: '500', marginBottom: '0.5rem' }}>No analysis results yet</p>
                    <p style={{ color: '#52525b', fontSize: '0.8rem', marginBottom: '1.5rem', maxWidth: '500px', margin: '0 auto 1.5rem' }}>
                        Point the server at a Java project with a <code style={{ ...s.mono, color: '#00d4ff' }}>pom.xml</code> to get started.
                    </p>
                    <div style={{ ...s.mono, fontSize: '0.75rem', color: '#a1a1aa', background: '#141414', padding: '0.75rem 1rem', borderRadius: '0.375rem', textAlign: 'left', display: 'inline-block', marginBottom: '1.5rem' }}>
                        <div style={{ color: '#52525b', marginBottom: '0.25rem' }}># Start with your Java project</div>
                        <div>go run ./cmd/analyzer --serve --project /path/to/java-project</div>
                    </div>
                    <br />
                    <button onClick={runAnalysis} disabled={analyzing} style={s.btn}>
                        {analyzing ? 'Analyzing...' : '▶ Try Analysis'}
                    </button>
                </div>
            )}
            {error && error !== 'no-analysis' && (
                <div style={{ ...s.card, borderColor: '#7f1d1d', background: 'rgba(239,68,68,0.04)' }}>
                    <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                        <span style={{ fontSize: '1.25rem', flexShrink: 0 }}>⚠️</span>
                        <div>
                            <p style={{ color: '#ef4444', fontWeight: '500', marginBottom: '0.5rem' }}>Analysis Error</p>
                            <p style={{ ...s.mono, color: '#a1a1aa', fontSize: '0.8rem' }}>{error}</p>
                        </div>
                    </div>
                </div>
            )}

            {hasData && decision && (
                <>
                    {/* Decision Banner */}
                    <div style={{
                        ...s.card,
                        background: decision.blocked
                            ? 'linear-gradient(135deg, rgba(239,68,68,0.08) 0%, rgba(239,68,68,0.02) 100%)'
                            : 'linear-gradient(135deg, rgba(16,185,129,0.08) 0%, rgba(16,185,129,0.02) 100%)',
                        borderColor: decision.blocked ? '#7f1d1d' : '#064e3b',
                        padding: '2rem',
                    }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                            <span style={{ fontSize: '2.5rem' }}>{decision.blocked ? '🚫' : '✅'}</span>
                            <div>
                                <div style={{
                                    fontSize: '1.5rem', fontWeight: '700',
                                    color: decision.blocked ? '#ef4444' : '#10b981',
                                    ...s.mono,
                                }}>
                                    {decision.blocked ? 'RELEASE BLOCKED' : 'CLEAR TO SHIP'}
                                </div>
                                <div style={{ color: '#a1a1aa', fontSize: '0.9rem', marginTop: '0.25rem' }}>
                                    {decision.reason}
                                </div>
                            </div>
                        </div>

                        {/* Quick stats */}
                        <div style={{ display: 'flex', gap: '2rem', marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                            {[
                                { label: 'Total CVEs', value: liveStats?.total ?? 0, color: '#fff' },
                                { label: 'Reachable', value: liveStats?.reachable ?? 0, color: '#ef4444' },
                                { label: 'Unreachable', value: liveStats?.unreachable ?? 0, color: '#10b981' },
                                { label: 'Unknown', value: liveStats?.unknown ?? 0, color: '#f59e0b' },
                            ].map(item => (
                                <div key={item.label}>
                                    <div style={{ fontSize: '0.75rem', color: '#52525b', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{item.label}</div>
                                    <div style={{ fontSize: '1.5rem', fontWeight: '700', color: item.color, ...s.mono }}>{item.value}</div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Blocking Table */}
                    {blockers.length > 0 && (
                        <div style={s.card}>
                            <h3 style={{ fontSize: '0.875rem', fontWeight: '600', marginBottom: '1rem', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#a1a1aa' }}>
                                🔥 Blocking Release ({blockers.length})
                            </h3>
                            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                                <thead>
                                    <tr style={{ borderBottom: '1px solid #27272a' }}>
                                        {['Priority', 'CVE', 'Why It Matters', 'Fix'].map(h => (
                                            <th key={h} style={{ textAlign: 'left', padding: '0.5rem 0.75rem', fontSize: '0.75rem', color: '#52525b', fontWeight: '500', textTransform: 'uppercase' }}>{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {blockers.map((v, i) => (
                                        <tr key={i} style={{ borderBottom: '1px solid #1e1e1e' }}>
                                            <td style={{ padding: '0.625rem 0.75rem' }}>
                                                <span style={{ fontSize: '0.875rem' }}>
                                                    {['critical', 'high'].includes(v.vulnerability?.severity?.toLowerCase()) ? '🔴' : '🟡'}
                                                </span>
                                            </td>
                                            <td style={{ padding: '0.625rem 0.75rem', ...s.mono, fontSize: '0.8rem', color: '#00d4ff' }}>
                                                {v.vulnerability?.id}
                                            </td>
                                            <td style={{ padding: '0.625rem 0.75rem', fontSize: '0.8rem', color: '#a1a1aa', maxWidth: '400px' }}>
                                                {v.reason || v.vulnerability?.description || 'Reachable from application code'}
                                            </td>
                                            <td style={{ padding: '0.625rem 0.75rem', ...s.mono, fontSize: '0.8rem', color: '#10b981' }}>
                                                {v.recommendation ? v.recommendation.replace(/^URGENT: /, '') : `Upgrade ${v.vulnerability?.affected_package || ''}`}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* Release Confidence Bar */}
                    <div style={s.card}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                            <h3 style={{ fontSize: '0.875rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#a1a1aa' }}>
                                Release Confidence
                            </h3>
                            <span style={{
                                ...s.mono, fontWeight: '700', fontSize: '0.875rem',
                                color: confidence.label === 'HIGH' ? '#10b981' : confidence.label === 'MEDIUM' ? '#f59e0b' : confidence.label === 'LOW' ? '#ef4444' : '#52525b',
                            }}>
                                {confidence.label}
                            </span>
                        </div>

                        <div style={{ background: '#27272a', borderRadius: '4px', height: '24px', overflow: 'hidden', marginBottom: '1rem', ...s.mono }}>
                            <div style={{
                                height: '100%', borderRadius: '4px',
                                width: `${confidence.pct}%`,
                                background: confidence.pct >= 80 ? '#10b981' : confidence.pct >= 50 ? '#f59e0b' : '#ef4444',
                                display: 'flex', alignItems: 'center', justifyContent: 'flex-end', paddingRight: '8px',
                                fontSize: '0.75rem', fontWeight: '600', color: '#0a0a0a',
                                transition: 'width 0.5s ease-out',
                                minWidth: confidence.pct > 0 ? '32px' : '0px',
                            }}>
                                {confidence.pct > 0 ? `${confidence.pct}%` : ''}
                            </div>
                        </div>

                        <div style={{ display: 'flex', gap: '2rem', fontSize: '0.8rem' }}>
                            <div>
                                <span style={{ color: '#52525b' }}>Static coverage: </span>
                                <span style={{ ...s.mono, color: '#a1a1aa' }}>{confidence.staticCoverage}%</span>
                            </div>
                            <div>
                                <span style={{ color: '#52525b' }}>Reflection uncertainty: </span>
                                <span style={{ ...s.mono, color: '#f59e0b' }}>{confidence.reflectionUncertainty}%</span>
                            </div>
                        </div>
                    </div>

                    {/* Build-to-Build Comparison */}
                    <div style={s.card}>
                        {diff ? (
                            <>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                                    <h3 style={{ fontSize: '0.875rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#a1a1aa' }}>
                                        Build-to-Build Comparison
                                    </h3>
                                    <span style={{
                                        ...s.mono, fontSize: '0.75rem', fontWeight: '600',
                                        color: diff.risk_delta === 'decreasing' ? '#10b981' : diff.risk_delta === 'increasing' ? '#ef4444' : '#a1a1aa',
                                    }}>
                                        {diff.risk_delta === 'decreasing' ? '↓ IMPROVING' : diff.risk_delta === 'increasing' ? '↑ WORSENING' : '→ STABLE'}
                                    </span>
                                </div>

                                {diff.new && diff.new.length > 0 && (
                                    <div style={{ marginBottom: '1rem' }}>
                                        <div style={{ fontSize: '0.75rem', color: '#ef4444', fontWeight: '600', marginBottom: '0.5rem' }}>+ NEW ({diff.new.length})</div>
                                        {diff.new.map((v, i) => (
                                            <div key={i} style={{ padding: '0.375rem 0.75rem', background: 'rgba(239,68,68,0.06)', borderRadius: '0.25rem', marginBottom: '0.25rem', display: 'flex', gap: '0.75rem', fontSize: '0.8rem' }}>
                                                <span style={{ ...s.mono, color: '#ef4444' }}>+ {v.cve_id}</span>
                                                <span style={{ color: '#a1a1aa' }}>{v.status === 'REACHABLE' ? `Reachable via ${v.package}` : v.package}</span>
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {diff.fixed && diff.fixed.length > 0 && (
                                    <div>
                                        <div style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: '600', marginBottom: '0.5rem' }}>− FIXED ({diff.fixed.length})</div>
                                        {diff.fixed.map((v, i) => (
                                            <div key={i} style={{ padding: '0.375rem 0.75rem', background: 'rgba(16,185,129,0.06)', borderRadius: '0.25rem', marginBottom: '0.25rem', display: 'flex', gap: '0.75rem', fontSize: '0.8rem' }}>
                                                <span style={{ ...s.mono, color: '#10b981' }}>− {v.cve_id}</span>
                                                <span style={{ color: '#a1a1aa' }}>{v.package}</span>
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {(!diff.new || diff.new.length === 0) && (!diff.fixed || diff.fixed.length === 0) && (
                                    <p style={{ color: '#52525b', fontSize: '0.8rem' }}>No changes between last two scans.</p>
                                )}
                            </>
                        ) : (
                            <>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                                    <h3 style={{ fontSize: '0.875rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#a1a1aa' }}>
                                        Build-to-Build Comparison
                                    </h3>
                                    <span style={{ ...s.mono, fontSize: '0.75rem', color: '#52525b' }}>→ AWAITING DATA</span>
                                </div>
                                <p style={{ color: '#52525b', fontSize: '0.8rem' }}>Run analysis at least twice to see build-to-build changes.</p>
                            </>
                        )}
                    </div>

                    {/* Severity Distribution */}
                    {sevData && Object.keys(sevData).length > 0 && (
                        <div style={s.card}>
                            <h3 style={{ fontSize: '0.875rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#a1a1aa', marginBottom: '0.75rem' }}>
                                Severity Distribution
                            </h3>
                            <div style={{ display: 'flex', gap: '1rem' }}>
                                {Object.entries(sevData).map(([sev, count]) => {
                                    const color = { critical: '#ef4444', high: '#ef4444', medium: '#f59e0b', moderate: '#f59e0b', low: '#3b82f6' }[sev.toLowerCase()] || '#a1a1aa'
                                    return (
                                        <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: color, flexShrink: 0 }} />
                                            <span style={{ fontSize: '0.8rem', textTransform: 'capitalize', color: '#a1a1aa' }}>{sev}</span>
                                            <span style={{ ...s.mono, fontSize: '0.8rem', fontWeight: '600' }}>{count}</span>
                                        </div>
                                    )
                                })}
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    )
}

export default ReleaseGate
