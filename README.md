# NetShield

**Reachability-based vulnerability analysis for Java applications**

NetShield determines whether vulnerabilities in your dependencies are actually exploitable by analyzing bytecode call graphs. It answers one question: *Can this CVE be triggered by my application code?*

Most vulnerability scanners report every CVE in your dependency tree. NetShield tells you which ones actually matter.

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
5. Classify each CVE as **Reachable**, **Unreachable**, or **Unknown**

---

## What Problem This Solves

| Traditional SCA | NetShield |
|---|---|
| "You have 39 CVEs" | "You have 36 **reachable** CVEs, 2 unreachable, 1 unknown" |
| Every CVE treated equally | Risk prioritized by exploitability |
| Alert fatigue, wasted patching | Fix what matters, defer what doesn't |
| Binary pass/fail | Graduated: **DO NOT SHIP** / **SHIP WITH CAUTION** / **SAFE TO SHIP** |

### Reachability Classification

- **REACHABLE** — Vulnerable method is called by your application code → fix immediately
- **UNREACHABLE** — Vulnerable code exists but cannot be triggered → deprioritize
- **UNKNOWN** — Package is used but specific vulnerable methods not identified → review

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

## Example Output

### Executive Report (default)

```
════════════════════════════════════════════════════════════════
                   NetShield Release Analysis
════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
────────────────────────────────────────────────────────────────
Critical exploitable vulnerabilities detected (36 reachable).
Release is blocked until patches are applied.

RELEASE STATUS
✗ DO NOT SHIP

BUSINESS RISK
────────────────────────────────────────────────────────────────
Exploit Risk         HIGH
Production Exposure  ACTIVE RISK
Patch Urgency        IMMEDIATE
Engineering Impact   Release Blocking

SUPPLY CHAIN TRUST SCORE
────────────────────────────────────────────────────────────────
55 / 100  (Poor)

SECURITY EVIDENCE
────────────────────────────────────────────────────────────────
39 vulnerabilities detected.

CVE: GHSA-hvv8-336g-rx3m
Package: com.thoughtworks.xstream:xstream
Severity: CRITICAL
Reachability: REACHABLE
Reason: Vulnerable method is called by application

ACTIVE PROTECTION
────────────────────────────────────────────────────────────────
If future code makes any vulnerability reachable, NetShield will
fail the build automatically.
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
  run: |
    netshield-analyzer --packages com.yourcompany --format core --quiet
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
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Maven Project   │───▶│  Dependency Tree  │───▶│  JAR Download   │
│    pom.xml       │    │  (transitive)     │    │  (parallel)     │
└─────────────────┘    └──────────────────┘    └────────┬────────┘
                                                        │
┌─────────────────┐    ┌──────────────────┐    ┌────────▼────────┐
│  Risk Triage    │◀───│  OSV CVE Lookup  │◀───│  Call Graph     │
│  Classification │    │  (concurrent)    │    │  (bytecode DFS) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

1. **Dependency Resolution** — Parses `pom.xml` and resolves the full transitive dependency tree
2. **JAR Analysis** — Downloads and parses bytecode from all JARs using a 10-worker parallel pool
3. **Call Graph Construction** — Builds method-level call graphs with virtual dispatch resolution (158K+ nodes, 3M+ edges for large projects)
4. **CVE Lookup** — Queries the OSV API concurrently for known vulnerabilities across all dependencies
5. **Reachability Analysis** — O(V+E) depth-first search from application entry points to determine which vulnerable methods are actually callable
6. **Risk Classification** — Categorizes each finding as Reachable, Unreachable, or Unknown with business risk scoring

---

## Performance

NetShield is optimized for speed with parallel JAR parsing, concurrent CVE queries, and an adjacency-list-based DFS.

| Project Size | Dependencies | Typical Time |
|--------------|:------------:|:------------:|
| Small        | < 50         | ~5 seconds   |
| Medium       | 50–200       | ~15 seconds  |
| Large (e.g., WebGoat) | 200+ | ~30 seconds |
| Enterprise   | 500+         | ~1–2 minutes |

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

## Dashboard & Monitoring

NetShield includes a built-in web dashboard and can upload results to a remote server for historical tracking:

```bash
# Start the local web dashboard
netshield-analyzer --serve --port 8080

# Scan and upload results to NetShield dashboard
netshield-analyzer monitor --packages com.yourcompany
```

---

## Limitations

1. **Reflection** — Methods invoked via reflection are marked as **Unknown**
2. **Dynamic Loading** — Dynamically loaded classes may not be analyzed
3. **Build Tool** — Currently supports Maven only (Gradle support planned)
4. **Language** — Java bytecode only (Kotlin/Scala supported if compiled to JVM bytecode)
5. **Accuracy** — Call graph construction is best-effort; complex frameworks may reduce precision

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

NetShield is dual-licensed:

- **AGPL-3.0** — Free for open source projects ([LICENSE-AGPL](LICENSE-AGPL))
- **Commercial** — For proprietary use ([LICENSE-COMMERCIAL](LICENSE-COMMERCIAL))

For commercial licensing: licensing@net-shield.net

---

## Security Disclosure

To report security vulnerabilities in NetShield itself: security@net-shield.net

Do not open public issues for security concerns.
