# NetShield Quick Start

## Installation

### From Source
```bash
git clone https://github.com/Netshield-Enterprise/netshield-analyzer.git
cd netshield-analyzer
go build -o netshield ./cmd/analyzer
```

### Using Go Install
```bash
go install github.com/Netshield-Enterprise/netshield-analyzer/cmd/analyzer@latest
```

## Basic Usage

```bash
# Navigate to your Maven project
cd /path/to/your/maven/project

# Run analysis (Executive format - default)
netshield --packages com.yourcompany

# CI/CD mode (minimal output)
netshield --packages com.yourcompany --format core

# Debug mode (technical deep-dive)
netshield --packages com.yourcompany --format debug

# JSON output for tooling
netshield --packages com.yourcompany --format json
```

## Output Formats

### Core (CI/CD Optimized)
Fast decision snapshot. Returns exit code 1 if reachable vulnerabilities found.

```bash
netshield --packages com.example --format core
```

### Executive (Default)
Decision + intelligence + foresight. Includes executive summary, supply chain score, and blast radius projection.

```bash
netshield --packages com.example
```

### Debug
Full technical analysis with call graphs and reachability paths.

```bash
netshield --packages com.example --format debug
```

### JSON
Machine-readable output for integration with other tools.

```bash
netshield --packages com.example --format json
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Safe to ship | Continue deployment |
| 1 | Reachable vulnerability | Block deployment |
| 2 | Analysis failure | Investigate and retry |

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  netshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install NetShield
        run: go install github.com/Netshield-Enterprise/netshield-analyzer/cmd/analyzer@latest
      
      - name: Run Security Analysis
        run: netshield --packages com.yourcompany --format core
```

### GitLab CI

```yaml
netshield:
  image: golang:1.21
  script:
    - go install github.com/Netshield-Enterprise/netshield-analyzer/cmd/analyzer@latest
    - netshield --packages com.yourcompany --format core
  only:
    - merge_requests
    - main
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Analysis') {
            steps {
                sh 'go install github.com/Netshield-Enterprise/netshield-analyzer/cmd/analyzer@latest'
                sh 'netshield --packages com.yourcompany --format core'
            }
        }
    }
}
```

## Common Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--packages` | Root package to analyze (required) | - |
| `--format` | Output format: core, executive, debug, json | executive |
| `--pom` | Path to pom.xml | ./pom.xml |
| `--help` | Show help message | - |

## Troubleshooting

### "No pom.xml found"
Ensure you're running NetShield from the root of a Maven project, or specify the path:
```bash
netshield --packages com.example --pom /path/to/pom.xml
```

### "Failed to download JAR"
Check network connectivity to Maven Central. If behind a corporate proxy, configure Maven settings.

### "Analysis incomplete"
Some methods may be marked as `Unknown` due to reflection or dynamic loading. Review manually.

## Next Steps

- Read the full [README](README.md) for detailed documentation
- Review [LICENSE](LICENSE) for dual licensing options
- Report issues at https://github.com/Netshield-Enterprise/netshield-analyzer/issues
