import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'

const Sidebar = () => {
    const location = useLocation()
    const [license, setLicense] = useState(null)
    const [showKeyInput, setShowKeyInput] = useState(false)
    const [keyValue, setKeyValue] = useState('')
    const [activating, setActivating] = useState(false)
    const [activationMsg, setActivationMsg] = useState(null)

    const fetchLicense = () => {
        fetch('/api/license')
            .then(res => res.json())
            .then(data => setLicense(data))
            .catch(() => setLicense({ tier: 'free', features: [] }))
    }

    useEffect(() => { fetchLicense() }, [])

    const activateKey = async () => {
        if (!keyValue.trim()) return
        setActivating(true)
        setActivationMsg(null)
        try {
            const res = await fetch('/api/license', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: keyValue.trim() }),
            })
            const data = await res.json()
            if (data.activated) {
                setLicense(data.license)
                setActivationMsg({ ok: true, text: `${data.license.tier} license activated!` })
                setShowKeyInput(false)
                setKeyValue('')
                // Reload page to refresh feature gates
                setTimeout(() => window.location.reload(), 800)
            } else {
                setActivationMsg({ ok: false, text: data.license?.message || 'Invalid key' })
            }
        } catch {
            setActivationMsg({ ok: false, text: 'Failed to reach server' })
        } finally {
            setActivating(false)
        }
    }

    const isActive = (path) => location.pathname === path
    const isFree = !license?.tier || license.tier === 'free'

    const nav = [
        { path: '/', label: 'Release Gate', icon: '🚦' },
        { path: '/evidence', label: 'Evidence Explorer', icon: '🔬' },
        { path: '/intelligence', label: 'Risk Intelligence', icon: '📊' },
    ]

    const mono = { fontFamily: "'JetBrains Mono', monospace" }

    return (
        <div style={{
            width: '240px',
            minHeight: '100vh',
            background: '#141414',
            borderRight: '1px solid #27272a',
            display: 'flex',
            flexDirection: 'column',
            flexShrink: 0,
        }}>
            {/* Logo */}
            <div style={{
                padding: '1.25rem 1rem',
                borderBottom: '1px solid #27272a',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
            }}>
                <span style={{ fontSize: '1.25rem' }}>🛡️</span>
                <span style={{
                    ...mono,
                    fontWeight: '600',
                    fontSize: '0.9rem',
                    color: '#fff',
                    letterSpacing: '0.5px',
                }}>NETSHIELD</span>
                {!isFree && (
                    <span style={{
                        fontSize: '0.6rem',
                        fontWeight: '600',
                        background: '#00d4ff',
                        color: '#0a0a0a',
                        padding: '1px 5px',
                        borderRadius: '2px',
                        textTransform: 'uppercase',
                        marginLeft: 'auto',
                    }}>{license.tier}</span>
                )}
            </div>

            {/* Nav */}
            <nav style={{ padding: '0.5rem', flex: 1 }}>
                {nav.map(item => (
                    <Link
                        key={item.path}
                        to={item.path}
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.75rem',
                            padding: '0.625rem 0.75rem',
                            borderRadius: '0.375rem',
                            color: isActive(item.path) ? '#fff' : '#a1a1aa',
                            background: isActive(item.path) ? '#27272a' : 'transparent',
                            textDecoration: 'none',
                            fontSize: '0.875rem',
                            fontWeight: isActive(item.path) ? '500' : '400',
                            marginBottom: '2px',
                            borderLeft: isActive(item.path) ? '2px solid #00d4ff' : '2px solid transparent',
                        }}
                    >
                        <span style={{ fontSize: '1rem' }}>{item.icon}</span>
                        {item.label}
                    </Link>
                ))}
            </nav>

            {/* License Panel */}
            <div style={{
                padding: '0.75rem',
                borderTop: '1px solid #27272a',
            }}>
                {isFree ? (
                    <>
                        <div style={{
                            background: '#1a1a1a',
                            borderRadius: '0.375rem',
                            padding: '0.75rem',
                            border: '1px solid #27272a',
                        }}>
                            <p style={{ fontSize: '0.7rem', color: '#a1a1aa', marginBottom: '0.5rem' }}>
                                Unlock Call Graph, Trends & Export
                            </p>

                            {showKeyInput ? (
                                <div>
                                    <input
                                        type="text"
                                        placeholder="NSPRO-XXXX-XXXX-XXXXXXXX"
                                        value={keyValue}
                                        onChange={e => setKeyValue(e.target.value)}
                                        onKeyDown={e => e.key === 'Enter' && activateKey()}
                                        style={{
                                            width: '100%',
                                            padding: '0.375rem 0.5rem',
                                            background: '#0a0a0a',
                                            border: '1px solid #27272a',
                                            borderRadius: '0.25rem',
                                            color: '#fff',
                                            fontSize: '0.65rem',
                                            ...mono,
                                            outline: 'none',
                                            marginBottom: '0.375rem',
                                            boxSizing: 'border-box',
                                        }}
                                        autoFocus
                                    />
                                    <div style={{ display: 'flex', gap: '0.25rem' }}>
                                        <button
                                            onClick={activateKey}
                                            disabled={activating || !keyValue.trim()}
                                            style={{
                                                flex: 1,
                                                padding: '0.3rem',
                                                background: '#00d4ff',
                                                color: '#0a0a0a',
                                                border: 'none',
                                                borderRadius: '0.25rem',
                                                fontSize: '0.65rem',
                                                fontWeight: '600',
                                                cursor: 'pointer',
                                                opacity: activating ? 0.5 : 1,
                                            }}
                                        >{activating ? '...' : 'Activate'}</button>
                                        <button
                                            onClick={() => { setShowKeyInput(false); setActivationMsg(null) }}
                                            style={{
                                                padding: '0.3rem 0.5rem',
                                                background: 'transparent',
                                                color: '#52525b',
                                                border: '1px solid #27272a',
                                                borderRadius: '0.25rem',
                                                fontSize: '0.65rem',
                                                cursor: 'pointer',
                                            }}
                                        >✕</button>
                                    </div>
                                    {activationMsg && (
                                        <p style={{
                                            fontSize: '0.6rem',
                                            marginTop: '0.375rem',
                                            color: activationMsg.ok ? '#10b981' : '#ef4444',
                                        }}>{activationMsg.text}</p>
                                    )}
                                </div>
                            ) : (
                                <button
                                    onClick={() => setShowKeyInput(true)}
                                    style={{
                                        width: '100%',
                                        padding: '0.4rem',
                                        background: 'transparent',
                                        border: '1px solid #00d4ff',
                                        color: '#00d4ff',
                                        borderRadius: '0.25rem',
                                        fontSize: '0.7rem',
                                        fontWeight: '500',
                                        cursor: 'pointer',
                                    }}
                                >🔑 Enter License Key</button>
                            )}
                        </div>
                    </>
                ) : (
                    <div style={{
                        background: 'rgba(0,212,255,0.05)',
                        borderRadius: '0.375rem',
                        padding: '0.5rem 0.75rem',
                        border: '1px solid rgba(0,212,255,0.15)',
                    }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                            <span style={{ fontSize: '0.7rem' }}>✅</span>
                            <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: '500' }}>
                                {license.tier?.charAt(0).toUpperCase() + license.tier?.slice(1)} License
                            </span>
                        </div>
                        {license.message && (
                            <p style={{ fontSize: '0.6rem', color: '#52525b', marginTop: '0.25rem' }}>{license.message}</p>
                        )}
                    </div>
                )}
            </div>

            {/* Version */}
            <div style={{
                padding: '0.5rem 1rem',
                fontSize: '0.65rem',
                color: '#3f3f46',
                ...mono,
            }}>
                v1.0
            </div>
        </div>
    )
}

export default Sidebar
