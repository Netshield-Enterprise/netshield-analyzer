# NetShield Web UI

Modern web interface for NetShield vulnerability analyzer.

## Features

- 📊 **Dashboard** - Summary cards, severity breakdown, reachability status
- 🔍 **Vulnerability List** - Search and filter vulnerabilities by status
- 🕸️ **Call Graph** - Visualize method call relationships
- ⚡ **Real-time Analysis** - Run analysis directly from the UI

## Quick Start

### 1. Install Dependencies

```bash
cd web
npm install
```

### 2. Start Backend API

```bash
# From project root
./netshield --serve --project /path/to/java/project
```

The API server will start on `http://localhost:8080`

### 3. Start Development Server

```bash
# In web directory
npm run dev
```

The UI will be available at `http://localhost:3000`

## Build for Production

```bash
npm run build
```

The production build will be in `web/dist/`

## Tech Stack

- **Framework**: React 18
- **Build Tool**: Vite
- **Routing**: React Router v6
- **Visualization**: Cytoscape.js (planned)
- **Charts**: Recharts

## API Endpoints

The frontend communicates with these backend endpoints:

- `POST /api/analyze` - Run vulnerability analysis
- `GET /api/summary` - Get analysis summary
- `GET /api/vulnerabilities` - Get all vulnerabilities
- `GET /api/callgraph` - Get call graph data

## Development

### Project Structure

```
web/
├── src/
│   ├── components/
│   │   └── Navigation.jsx
│   ├── pages/
│   │   ├── Dashboard.jsx
│   │   ├── VulnerabilityList.jsx
│   │   └── CallGraphView.jsx
│   ├── App.jsx
│   ├── main.jsx
│   └── index.css
├── index.html
├── package.json
└── vite.config.js
```

### Design System

The UI uses a modern dark theme with CSS variables defined in `index.css`:

- Colors: Primary, secondary, tertiary backgrounds
- Typography: System fonts with hierarchy
- Components: Cards, buttons, badges
- Utilities: Grid, flex, spacing, transitions

## Usage

1. **Run Analysis**: Click "Run Analysis" on Dashboard
2. **Filter Vulnerabilities**: Use status filters (Reachable/Unreachable/Unknown)
3. **Search**: Search by CVE ID or dependency name
4. **View Details**: Click on vulnerability cards for more information
