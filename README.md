# NetShield

**Reachability-based vulnerability analysis for Java applications**

---

## Why NetShield Exists

Traditional Software Composition Analysis tools answer one question:

> *"Does a vulnerable version exist in the dependency tree?"*

That produces large volumes of alerts but does not answer the question that determines risk:

> *"Can the application actually execute the vulnerable code?"*

NetShield performs static reachability analysis on Java bytecode to determine whether vulnerable methods are reachable from application entry points.

The result is a triage classification:

- **REACHABLE** — Vulnerable method is called by your application → fix immediately
- **UNREACHABLE** — Vulnerable code exists but cannot be triggered → deprioritize
- **UNKNOWN** — Analysis incomplete → manual review recommended

---

## Real-World Benchmark

NetShield was tested against [OWASP WebGoat](https://github.com/WebGoat/WebGoat):

| Metric | Value |
|--------|-------|
| Dependencies scanned | 203 |
| Call graph nodes | 158,410 |
| Call graph edges | 3,059,079 |
| Reachable methods | 76,710 |
| CVEs detected | 39 |
| Reachable | 36 |
| Unreachable | 2 |
| Unknown | 1 |
| Analysis time | 29 seconds |

---

## Installation

**From Release (Recommended):**
```bash
# Linux AMD64
curl -LO https://github.com/Netshield-Enterprise/netshield-analyzer/releases/latest/download/netshield-analyzer-linux-amd64
chmod +x netshield-analyzer-linux-amd64
sudo mv netshield-analyzer-linux-amd64 /usr/local/bin/netshield-analyzer

# macOS Apple Silicon
curl -LO https://github.com/Netshield-Enterprise/netshield-analyzer/releases/latest/download/netshield-analyzer-darwin-arm64
chmod +x netshield-analyzer-darwin-arm64
sudo mv netshield-analyzer-darwin-arm64 /usr/local/bin/netshield-analyzer

# Windows: Download netshield-analyzer-windows-amd64.exe and add to PATH
```

**From Source:**
```bash
git clone https://github.com/Netshield-Enterprise/netshield-analyzer.git
cd netshield-analyzer
go build -o netshield-analyzer ./cmd/analyzer
```

**Using Go Install:**
```bash
go install github.com/Netshield-Enterprise/netshield-analyzer/cmd/analyzer@latest
```

---

## Quick Start

```bash
cd /path/to/your/maven/project
netshield-analyzer --packages com.yourcompany
```

NetShield will:
1. Resolve your Maven dependency tree
2. Parse bytecode from all dependency JARs (in parallel)
3. Build a method-level call graph
4. Query the OSV vulnerability database
5. Classify each CVE as Reachable, Unreachable, or Unknown

---

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| **Executive** (default) | `--format executive` | Decision + intelligence + supply chain scoring |
| **Core** | `--format core` | Minimal CI/CD output with exit codes |
| **Debug** | `--format debug` | Full technical analysis with call graph details |
| **JSON** | `--format json` | Machine-readable for tooling integration |

### Output Control Flags

| Flag | Short | Effect |
|------|-------|--------|
| `--quiet` | `-q` | Suppress all stderr progress output |
| `--no-progress` | | Suppress per-dependency CVE log, keep step headers |
| `--summary-only` | | Show executive summary only, omit individual CVE details |

### Usage Examples

```bash
# Basic scan
netshield-analyzer --packages com.yourcompany.app

# Scan a specific project path
netshield-analyzer --project /path/to/project --packages com.yourcompany

# Quiet mode for CI/CD pipelines
netshield-analyzer --packages com.yourcompany --quiet

# Minimal CI output (no progress, no CVE details)
netshield-analyzer --packages com.yourcompany --quiet --summary-only

# JSON output for programmatic consumption
netshield-analyzer --packages com.yourcompany --format json --quiet

# Start the web dashboard
netshield-analyzer --serve --port 9090
```

---

## CI/CD Integration

NetShield uses exit codes designed for pipeline integration:

| Exit Code | Meaning | CI/CD Action |
|-----------|---------|--------------|
| **0** | Safe to ship | ✅ Pass build |
| **1** | Reachable vulnerability detected | ❌ Fail build |
| **2** | Analysis failure | ❌ Fail build |

### GitHub Actions

```yaml
- name: Security Gate
  run: netshield-analyzer --packages com.yourcompany --format core --quiet
```

### GitLab CI

```yaml
netshield:
  script:
    - netshield-analyzer --packages com.yourcompany --format core --quiet
```

### Jenkins

```groovy
sh 'netshield-analyzer --packages com.yourcompany --format core --quiet'
```

---

## How It Works

```
┌─────────────────┐    ┌──────────────────┐    ┌───────────────────────┐
│  Maven Project   │───▶│  Dependency Tree  │───▶│  Parallel JAR         │
│    pom.xml       │    │  (transitive)     │    │  bytecode parsing     │
└─────────────────┘    └──────────────────┘    │  (10 workers)         │
                                                └───────────┬───────────┘
                                                            │
┌─────────────────┐    ┌──────────────────┐    ┌────────────▼──────────┐
│  Risk Triage    │◀───│  OSV CVE Lookup  │◀───│  Call Graph           │
│  + Trust Score  │    │  (10 concurrent) │    │  (bytecode DFS)       │
└─────────────────┘    └──────────────────┘    └───────────────────────┘
```

1. **Dependency Resolution** — Parses `pom.xml` and resolves the full transitive dependency tree
2. **JAR Analysis** — Downloads and parses bytecode from all JARs using a 10-worker parallel pool
3. **Call Graph Construction** — Builds method-level call graphs with virtual dispatch resolution
4. **CVE Lookup** — Queries the OSV API concurrently for known vulnerabilities
5. **Reachability Analysis** — O(V+E) depth-first search from application entry points
6. **Risk Classification** — Categorizes each finding with business risk scoring

---

## Limitations

NetShield uses static bytecode analysis and cannot fully resolve:

- **Reflection** — Methods invoked via reflection are marked as Unknown
- **Dynamic Loading** — Dynamically loaded classes may not be analyzed
- **Runtime Proxies** — CGLIB/ByteBuddy-generated methods are not visible in bytecode
- **JNI** — Native code execution paths are not analyzed
- **Build Tool** — Currently supports Maven only (Gradle support planned)
- **Language** — Java bytecode only (Kotlin/Scala supported if compiled to JVM bytecode)

These cases are reported as `UNKNOWN` to avoid false negatives.

---

## Roadmap

Planned improvements:

- Additional CVE data sources (NVD, GitHub Advisory Database)
- Deeper Spring framework entry point discovery
- Reflection resolution improvements
- Gradle build support
- SARIF output format for GitHub Security

---

## All Flags

```
Flags:
  -a, --packages strings       Application package prefixes (comma-separated)
  -p, --project string         Path to the Java project (default ".")
  -f, --format string          Output format: core, executive, debug, json (default "executive")
  -q, --quiet                  Suppress all progress output (stderr)
      --no-progress            Suppress per-dependency CVE query log (keep step headers)
      --summary-only           Show executive summary only, omit individual CVE details
  -e, --entry-points strings   Custom entry points (format: Package.Class.method(Signature))
      --skip-cve               Skip CVE lookup (only build call graph)
      --serve                  Start web UI server instead of CLI analysis
      --port int               Web UI server port (use with --serve) (default 8080)
      --key-stdin              Read API key securely from stdin
  -h, --help                   Help for netshield
```

---

## Releasing

Releases are automated via GitHub Actions. Pushing a version tag triggers cross-platform binary builds:

```bash
git tag -a v0.3.1 -m "Release v0.3.1"
git push origin v0.3.1

# Automatically builds for:
# - Linux (amd64, arm64)
# - macOS (Intel, Apple Silicon)
# - Windows (amd64)
```

---

## IDE Plugins

NetShield integrates directly into your IDE:

- **VS Code** — [NetShield for VS Code](https://marketplace.visualstudio.com/items?itemName=netshield-enterprise.netshield-vscode)
- **IntelliJ IDEA** — [NetShield for IntelliJ](https://plugins.jetbrains.com/plugin/netshield-intellij)

---

## License

NetShield Analyzer is dual licensed.

- **AGPL-3.0** — Open source community version ([LICENSE](LICENSE))
- **Commercial** — For organizations that cannot comply with AGPL ([LICENSE-COMMERCIAL](LICENSE-COMMERCIAL))

See [LICENSING.md](LICENSING.md) for details.

---

## Security Disclosure

To report security vulnerabilities in NetShield itself: security@net-shield.net

Do not open public issues for security concerns.
