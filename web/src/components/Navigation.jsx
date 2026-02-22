import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'

const Navigation = () => {
    const location = useLocation()
    const [license, setLicense] = useState(null)

    useEffect(() => {
        fetch('/api/license')
            .then(res => res.json())
            .then(data => setLicense(data))
            .catch(() => setLicense({ tier: 'free', features: [] }))
    }, [])

    const hasFeature = (feature) => {
        return license?.features?.includes(feature) || false
    }

    const isActive = (path) => location.pathname === path

    const navStyle = {
        background: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border-primary)',
        padding: '0 var(--spacing-xl)',
    }

    const containerStyle = {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        maxWidth: '1400px',
        margin: '0 auto',
        height: '64px',
    }

    const logoStyle = {
        fontSize: '1.5rem',
        fontWeight: '700',
        color: 'var(--text-primary)',
        textDecoration: 'none',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-sm)',
    }

    const navLinksStyle = {
        display: 'flex',
        gap: 'var(--spacing-md)',
        listStyle: 'none',
        alignItems: 'center',
    }

    const linkStyle = (active) => ({
        color: active ? 'var(--accent-primary)' : 'var(--text-secondary)',
        textDecoration: 'none',
        padding: 'var(--spacing-sm) var(--spacing-md)',
        borderRadius: 'var(--radius-md)',
        fontWeight: '500',
        transition: 'all var(--transition-base)',
        background: active ? 'rgba(88, 166, 255, 0.1)' : 'transparent',
    })

    const tierBadgeStyle = {
        fontSize: '0.7rem',
        fontWeight: '700',
        padding: '2px 6px',
        borderRadius: 'var(--radius-sm)',
        background: license?.tier === 'pro' ? 'var(--success)' :
            license?.tier === 'enterprise' ? 'var(--accent-primary)' : 'var(--text-tertiary)',
        color: 'white',
        textTransform: 'uppercase',
    }

    return (
        <nav style={navStyle}>
            <div style={containerStyle}>
                <Link to="/" style={logoStyle}>
                    🛡️ NetShield
                    {license?.tier && license.tier !== 'free' && (
                        <span style={tierBadgeStyle}>{license.tier}</span>
                    )}
                </Link>

                <ul style={navLinksStyle}>
                    <li>
                        <Link to="/" style={linkStyle(isActive('/'))}>
                            Dashboard
                        </Link>
                    </li>
                    <li>
                        <Link to="/vulnerabilities" style={linkStyle(isActive('/vulnerabilities'))}>
                            Vulnerabilities
                        </Link>
                    </li>
                    {hasFeature('callgraph') && (
                        <li>
                            <Link to="/callgraph" style={linkStyle(isActive('/callgraph'))}>
                                Call Graph
                            </Link>
                        </li>
                    )}
                    {!hasFeature('callgraph') && (
                        <li>
                            <span style={{
                                ...linkStyle(false),
                                opacity: 0.5,
                                cursor: 'not-allowed',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '4px',
                            }}>
                                Call Graph
                                <span style={{ fontSize: '0.7rem', background: 'var(--warning)', padding: '1px 4px', borderRadius: '3px' }}>PRO</span>
                            </span>
                        </li>
                    )}
                </ul>
            </div>
        </nav>
    )
}

export default Navigation
