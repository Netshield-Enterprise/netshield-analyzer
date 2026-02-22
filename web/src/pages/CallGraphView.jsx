import { useState, useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'
import cola from 'cytoscape-cola'

// Register layout
cytoscape.use(cola)

const CallGraphView = () => {
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [graphData, setGraphData] = useState(null)
    const [selectedVuln, setSelectedVuln] = useState(null)
    const [vulnerabilities, setVulnerabilities] = useState([])
    const [renderError, setRenderError] = useState(null)
    const [noResults, setNoResults] = useState(false)
    const [searchTerm, setSearchTerm] = useState('')
    const [filterMode, setFilterMode] = useState('smart') // 'smart' | 'search' | 'all'
    const containerRef = useRef(null)
    const cyRef = useRef(null)
    const allNodesRef = useRef([])
    const allEdgesRef = useRef([])

    useEffect(() => {
        loadData()
    }, [])

    useEffect(() => {
        if (graphData && containerRef.current) {
            prepareGraphData()
        }
    }, [graphData])

    // Debounce search to prevent rapid re-renders
    useEffect(() => {
        if (!graphData || allNodesRef.current.length === 0) return

        const timer = setTimeout(() => {
            try {
                updateGraph()
            } catch (err) {
                console.error('Search update error:', err)
            }
        }, 300) // 300ms debounce

        return () => clearTimeout(timer)
    }, [searchTerm, filterMode])

    const loadData = async () => {
        try {
            const controller = new AbortController()
            const timeout = setTimeout(() => controller.abort(), 30000)

            const cgResponse = await fetch('/api/callgraph', { signal: controller.signal })
            clearTimeout(timeout)

            if (!cgResponse.ok) {
                throw new Error('No call graph available. Run analysis first.')
            }
            const cgData = await cgResponse.json()
            setGraphData(cgData)

            const vulnResponse = await fetch('/api/vulnerabilities')
            if (vulnResponse.ok) {
                const vulnData = await vulnResponse.json()
                setVulnerabilities(vulnData || [])
            }
        } catch (err) {
            if (err.name === 'AbortError') {
                setError('Request timed out. The call graph might be too large.')
            } else {
                setError(err.message)
            }
        } finally {
            setLoading(false)
        }
    }

    const prepareGraphData = () => {
        const nodes = Object.entries(graphData.nodes || {}).map(([id, node]) => ({
            data: {
                id,
                label: `${node.method_name}`,
                isExternal: node.is_external,
                isReflective: node.is_reflective,
                isLambda: node.is_lambda,
                isDynamic: node.is_dynamic,
                className: node.class_name,
                fullLabel: `${node.class_name}.${node.method_name}`,
            }
        }))

        const edges = (graphData.edges || []).map((edge, idx) => ({
            data: {
                id: `e${idx}`,
                source: edge.from,
                target: edge.to,
                type: edge.type,
            }
        }))

        allNodesRef.current = nodes
        allEdgesRef.current = edges
        updateGraph()
    }

    const getFilteredNodes = () => {
        const allNodes = allNodesRef.current
        const allEdges = allEdgesRef.current

        // Safety check
        if (!allNodes || allNodes.length === 0) {
            return { nodes: [], edges: [], isFiltered: false, matchCount: 0 }
        }

        // Search mode: filter by search term
        if (searchTerm.trim()) {
            const term = searchTerm.toLowerCase()
            const matchingNodes = allNodes.filter(n =>
                n.data.fullLabel.toLowerCase().includes(term) ||
                n.data.className.toLowerCase().includes(term) ||
                n.data.label.toLowerCase().includes(term)
            )

            if (matchingNodes.length === 0) {
                return { nodes: [], edges: [], isFiltered: true, matchCount: 0 }
            }

            // Start with matching nodes
            const matchingIds = new Set(matchingNodes.map(n => n.data.id))

            // Find edges connected to matching nodes
            const relatedEdges = allEdges.filter(e =>
                matchingIds.has(e.data.source) || matchingIds.has(e.data.target)
            )

            // Collect all node IDs that we need (matching + neighbors from edges)
            const allIncludedIds = new Set(matchingIds)
            relatedEdges.forEach(e => {
                allIncludedIds.add(e.data.source)
                allIncludedIds.add(e.data.target)
            })

            // Include matching nodes + their neighbors (but only nodes that actually EXIST)
            const allNodeIds = new Set(allNodes.map(n => n.data.id))
            const finalNodeIds = new Set()
            allIncludedIds.forEach(id => {
                if (allNodeIds.has(id)) {
                    finalNodeIds.add(id)
                }
            })

            const nodesWithNeighbors = allNodes.filter(n => finalNodeIds.has(n.data.id))

            // CRITICAL: Filter edges to only those where BOTH source and target exist
            const validEdges = relatedEdges.filter(e =>
                finalNodeIds.has(e.data.source) && finalNodeIds.has(e.data.target)
            )

            return {
                nodes: nodesWithNeighbors.slice(0, 1000),
                edges: validEdges.slice(0, 2000),
                isFiltered: true,
                matchCount: matchingNodes.length
            }
        }

        // Smart sampling mode (default)
        let maxNodes = 1000
        if (allNodes.length > 10000) maxNodes = 300
        else if (allNodes.length > 5000) maxNodes = 500
        else if (allNodes.length > 2000) maxNodes = 800

        const appNodes = allNodes.filter(n => !n.data.isExternal)
        const externalNodes = allNodes.filter(n => n.data.isExternal)

        const sampledNodes = [
            ...appNodes.slice(0, Math.min(appNodes.length, Math.floor(maxNodes * 0.7))),
            ...externalNodes.slice(0, Math.min(externalNodes.length, Math.floor(maxNodes * 0.3)))
        ].slice(0, maxNodes)

        const nodeIds = new Set(sampledNodes.map(n => n.data.id))
        const sampledEdges = allEdges.filter(e =>
            nodeIds.has(e.data.source) && nodeIds.has(e.data.target)
        )

        return {
            nodes: sampledNodes,
            edges: sampledEdges,
            isFiltered: false,
            matchCount: 0
        }
    }

    const updateGraph = () => {
        if (!containerRef.current || !allNodesRef.current || allNodesRef.current.length === 0) {
            console.log('Graph container or nodes not ready yet')
            return
        }

        try {
            const { nodes, edges } = getFilteredNodes()

            // Clear any previous error
            setRenderError(null)

            if (nodes.length === 0) {
                console.log('No nodes to display')
                setNoResults(true)
                // Keep existing graph visible but show no results message
                return
            }

            setNoResults(false)

            // Destroy existing graph
            if (cyRef.current) {
                cyRef.current.destroy()
                cyRef.current = null
            }

            cyRef.current = cytoscape({
                container: containerRef.current,
                elements: { nodes, edges },
                style: [
                    {
                        selector: 'node',
                        style: {
                            'background-color': (ele) => {
                                if (ele.data('isReflective')) return '#f85149'
                                if (ele.data('isLambda')) return '#d29922'
                                if (ele.data('isExternal')) return '#484f58'
                                return '#58a6ff'
                            },
                            'label': 'data(label)',
                            'color': '#e6edf3',
                            'font-size': '10px',
                            'text-valign': 'center',
                            'text-halign': 'center',
                            'width': 30,
                            'height': 30,
                        }
                    },
                    {
                        selector: 'edge',
                        style: {
                            'width': 2,
                            'line-color': '#30363d',
                            'target-arrow-color': '#30363d',
                            'target-arrow-shape': 'triangle',
                            'curve-style': 'bezier',
                            'arrow-scale': 1,
                        }
                    },
                    {
                        selector: '.highlighted',
                        style: {
                            'background-color': '#3fb950',
                            'line-color': '#3fb950',
                            'target-arrow-color': '#3fb950',
                            'width': 4,
                            'z-index': 999,
                        }
                    },
                    {
                        selector: '.vulnerable',
                        style: {
                            'background-color': '#f85149',
                            'border-width': 3,
                            'border-color': '#ff7b72',
                        }
                    },
                    {
                        selector: '.search-match',
                        style: {
                            'background-color': '#d29922',
                            'border-width': 2,
                            'border-color': '#f0b72f',
                        }
                    }
                ],
                layout: {
                    name: 'cola',
                    animate: false,
                    nodeDimensionsIncludeLabels: true,
                    flow: { axis: 'y', minSeparation: 60 },
                    edgeLength: 100,
                    maxSimulationTime: 3000,
                    ready: function () {
                        console.log('Layout ready, nodes:', nodes.length)
                    },
                    stop: function () {
                        console.log('Layout complete, fitting to viewport')
                        if (cyRef.current) {
                            cyRef.current.fit()
                            cyRef.current.center()
                        }
                    },
                },
                minZoom: 0.1,
                maxZoom: 3,
            })

            console.log('Graph created with nodes:', nodes.length, 'edges:', edges.length)

            // Run layout explicitly
            const layout = cyRef.current.layout({
                name: 'cola',
                animate: false,
                nodeDimensionsIncludeLabels: true,
                flow: { axis: 'y', minSeparation: 60 },
                edgeLength: 100,
                maxSimulationTime: 2000,
            })

            layout.run()

            // Force fit after a small delay to ensure layout completes
            setTimeout(() => {
                if (cyRef.current) {
                    cyRef.current.fit()
                    cyRef.current.center()
                    console.log('Graph fitted to viewport')
                }
            }, 500)

            // Highlight search matches
            if (searchTerm.trim()) {
                const term = searchTerm.toLowerCase()
                cyRef.current.nodes().forEach(node => {
                    if (node.data('fullLabel').toLowerCase().includes(term)) {
                        node.addClass('search-match')
                    }
                })
            }

            cyRef.current.on('tap', 'node', (evt) => {
                const node = evt.target
                console.log('🔍 Method:', node.data('fullLabel'))
            })
        } catch (err) {
            console.error('Failed to render graph:', err)
            // Only set render error if this is the initial render (no search term)
            if (!searchTerm) {
                setRenderError('Failed to render graph. The project might be too large.')
            }
        }
    }

    const highlightVulnerabilityPath = (vuln) => {
        if (!cyRef.current) return

        cyRef.current.elements().removeClass('highlighted vulnerable')

        if (!vuln || !vuln.affected_methods || vuln.affected_methods.length === 0) {
            setSelectedVuln(null)
            return
        }

        setSelectedVuln(vuln.vulnerability?.id)

        vuln.affected_methods.forEach(methodId => {
            const node = cyRef.current.getElementById(methodId)
            if (node.length > 0) {
                node.addClass('vulnerable')
                node.incomers('edge').addClass('highlighted')
                node.incomers('node').addClass('highlighted')
            }
        })

        const highlighted = cyRef.current.elements('.highlighted, .vulnerable')
        if (highlighted.length > 0) {
            cyRef.current.fit(highlighted, 100)
        }
    }

    if (loading) {
        return (
            <div className="container" style={{ textAlign: 'center', paddingTop: '3rem' }}>
                <div className="spinner" style={{ margin: '0 auto' }}></div>
                <p style={{ marginTop: 'var(--spacing-md)' }}>Loading call graph...</p>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)', marginTop: 'var(--spacing-sm)' }}>
                    This may take a while for large projects
                </p>
            </div>
        )
    }

    if (error) {
        return (
            <div className="container">
                <div className="card" style={{ textAlign: 'center', padding: 'var(--spacing-2xl)', background: 'rgba(248, 81, 73, 0.1)', borderColor: 'var(--danger)' }}>
                    <h2 style={{ marginBottom: 'var(--spacing-md)', color: 'var(--danger)' }}>⚠️ Call Graph Not Available</h2>
                    <p style={{ marginBottom: 'var(--spacing-lg)' }}>{error}</p>
                    <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', textAlign: 'left', background: 'var(--bg-tertiary)', padding: 'var(--spacing-md)', borderRadius: 'var(--radius-md)' }}>
                        <strong>Possible reasons:</strong>
                        <ul style={{ marginTop: 'var(--spacing-sm)', paddingLeft: 'var(--spacing-lg)' }}>
                            <li>Backend server crashed (check terminal)</li>
                            <li>Analysis hasn't been run yet</li>
                            <li>Project is too large and exceeded timeout (30s)</li>
                            <li>No JAR files found in project</li>
                        </ul>
                    </div>
                </div>
            </div>
        )
    }

    if (renderError) {
        return (
            <div className="container">
                <div className="card" style={{ textAlign: 'center', padding: 'var(--spacing-2xl)', background: 'rgba(248, 81, 73, 0.1)', borderColor: 'var(--danger)' }}>
                    <h2 style={{ marginBottom: 'var(--spacing-md)', color: 'var(--danger)' }}>⚠️ Graph Rendering Failed</h2>
                    <p>{renderError}</p>
                </div>
            </div>
        )
    }

    const totalNodes = allNodesRef.current?.length || 0
    const totalEdges = allEdgesRef.current?.length || 0
    const filtered = getFilteredNodes()
    const displayedCount = filtered.nodes.length
    const matchCount = filtered.matchCount

    return (
        <div className="container">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 'var(--spacing-lg)', gap: 'var(--spacing-lg)' }}>
                <div style={{ flex: 1 }}>
                    <h1 style={{ marginBottom: 'var(--spacing-sm)' }}>Call Graph</h1>
                    <p style={{ color: 'var(--text-secondary)' }}>
                        Interactive visualization of method call relationships
                    </p>
                </div>

                {/* Legend */}
                <div className="card" style={{ padding: 'var(--spacing-md)', minWidth: '200px' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: 'var(--spacing-sm)' }}>Legend</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-xs)', fontSize: '0.85rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)' }}>
                            <div style={{ width: '16px', height: '16px', borderRadius: '50%', background: '#58a6ff' }}></div>
                            <span>App Methods</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)' }}>
                            <div style={{ width: '16px', height: '16px', borderRadius: '50%', background: '#484f58' }}></div>
                            <span>External</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)' }}>
                            <div style={{ width: '16px', height: '16px', borderRadius: '50%', background: '#f85149' }}></div>
                            <span>Reflective</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)' }}>
                            <div style={{ width: '16px', height: '16px', borderRadius: '50%', background: '#d29922' }}></div>
                            <span>Lambda/Search</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Search Bar */}
            <div className="card" style={{ marginBottom: 'var(--spacing-lg)' }}>
                <h3 style={{ fontSize: '0.9rem', marginBottom: 'var(--spacing-sm)' }}>🔍 Search Methods</h3>
                <input
                    type="text"
                    placeholder="Search by method name, class, or package (e.g. 'PetController', 'findAll', 'org.springframework')..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    style={{
                        width: '100%',
                        padding: 'var(--spacing-sm) var(--spacing-md)',
                        background: 'var(--bg-tertiary)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 'var(--radius-md)',
                        color: 'var(--text-primary)',
                        fontSize: '1rem',
                    }}
                />
                {searchTerm && matchCount > 0 && (
                    <div style={{ marginTop: 'var(--spacing-sm)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        Found <strong style={{ color: 'var(--accent-primary)' }}>{matchCount}</strong> matching methods
                        {displayedCount < matchCount && ` (showing ${displayedCount} with neighbors)`}
                    </div>
                )}
                {searchTerm && matchCount === 0 && (
                    <div style={{ marginTop: 'var(--spacing-sm)', fontSize: '0.85rem', color: 'var(--warning)' }}>
                        No methods found matching "<strong>{searchTerm}</strong>"
                    </div>
                )}
            </div>

            {/* Vulnerability selector */}
            {vulnerabilities.length > 0 && (
                <div className="card" style={{ marginBottom: 'var(--spacing-lg)' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: 'var(--spacing-sm)' }}>Highlight Reachability Path</h3>
                    <select
                        value={selectedVuln || ''}
                        onChange={(e) => {
                            const vuln = vulnerabilities.find(v => v.vulnerability?.id === e.target.value)
                            highlightVulnerabilityPath(vuln)
                        }}
                        style={{
                            width: '100%',
                            padding: 'var(--spacing-sm) var(--spacing-md)',
                            background: 'var(--bg-tertiary)',
                            border: '1px solid var(--border-primary)',
                            borderRadius: 'var(--radius-md)',
                            color: 'var(--text-primary)',
                            fontSize: '0.95rem',
                        }}
                    >
                        <option value="">Select vulnerability to highlight path...</option>
                        {vulnerabilities.map((vuln, idx) => (
                            <option key={idx} value={vuln.vulnerability?.id}>
                                {vuln.vulnerability?.id} - {vuln.status}
                            </option>
                        ))}
                    </select>
                </div>
            )}

            {/* Sampling Warning */}
            {totalNodes > 1000 && !searchTerm && (
                <div className="card" style={{ marginBottom: 'var(--spacing-lg)', background: 'rgba(210, 153, 34, 0.1)', borderColor: 'var(--warning)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)' }}>
                        <span style={{ fontSize: '1.5rem' }}>⚠️</span>
                        <div>
                            <strong style={{ color: 'var(--warning)' }}>Large Graph Detected</strong>
                            <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                                Showing {displayedCount} out of {totalNodes} nodes for performance. App methods are prioritized.
                                <br />
                                <strong>💡 Tip:</strong> Use the search box above to find specific methods across all {totalNodes} nodes.
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* No Results Message */}
            {noResults && searchTerm && (
                <div className="card" style={{ marginBottom: 'var(--spacing-lg)', background: 'rgba(88, 166, 255, 0.1)', borderColor: 'var(--accent-primary)', textAlign: 'center', padding: 'var(--spacing-xl)' }}>
                    <span style={{ fontSize: '2rem' }}>🔍</span>
                    <h3 style={{ marginTop: 'var(--spacing-md)', marginBottom: 'var(--spacing-sm)' }}>No Methods Found</h3>
                    <p style={{ color: 'var(--text-secondary)', marginBottom: 'var(--spacing-md)' }}>
                        No methods match "<strong>{searchTerm}</strong>"
                    </p>
                    <button
                        onClick={() => setSearchTerm('')}
                        style={{
                            padding: 'var(--spacing-sm) var(--spacing-lg)',
                            background: 'var(--accent-primary)',
                            color: 'white',
                            border: 'none',
                            borderRadius: 'var(--radius-md)',
                            cursor: 'pointer',
                            fontWeight: '600',
                        }}
                    >
                        Clear Search
                    </button>
                </div>
            )}

            <div className="card" style={{ padding: 0, minHeight: '700px', overflow: 'hidden' }}>
                <div ref={containerRef} style={{ width: '100%', height: '700px' }}></div>
            </div>

            <div className="card" style={{ marginTop: 'var(--spacing-lg)' }}>
                <h3 style={{ marginBottom: 'var(--spacing-md)' }}>Controls & Stats</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--spacing-md)', marginBottom: 'var(--spacing-md)' }}>
                    <div>
                        <div style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)' }}>Total Nodes</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--accent-primary)' }}>{totalNodes}</div>
                    </div>
                    <div>
                        <div style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)' }}>Total Edges</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--accent-primary)' }}>{totalEdges}</div>
                    </div>
                    <div>
                        <div style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)' }}>Displayed</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: '700', color: searchTerm ? 'var(--success)' : totalNodes > 1000 ? 'var(--warning)' : 'var(--success)' }}>
                            {displayedCount}
                        </div>
                    </div>
                    {searchTerm && matchCount > 0 && (
                        <div>
                            <div style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)' }}>Search Matches</div>
                            <div style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--accent-primary)' }}>{matchCount}</div>
                        </div>
                    )}
                </div>
                <ul style={{ paddingLeft: 'var(--spacing-lg)', lineHeight: 1.8, color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                    <li><strong>Search:</strong> Type method/class/package name to filter graph</li>
                    <li><strong>Zoom:</strong> Mouse wheel or pinch gesture</li>
                    <li><strong>Pan:</strong> Click and drag on empty space</li>
                    <li><strong>Select Node:</strong> Click to see full method signature in console</li>
                    <li><strong>Highlight Path:</strong> Select a vulnerability from dropdown</li>
                </ul>
            </div>
        </div>
    )
}

export default CallGraphView
