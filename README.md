# NetShield

**Reachability-based vulnerability analysis for Java applications**

NetShield determines whether vulnerabilities in your dependencies are actually exploitable by analyzing bytecode call graphs. It answers one question: *Can this CVE be triggered by my application code?*

---

## Quick Start

### Installation

**From Source:**
```bash
git clone https://github.com/Netshield-Enterprise/netshield-analyzer.git
cd netshield-analyzer
go build -o netshield ./cmd/analyzer
```

**Using Go Install:**
```bash
go install github.com/Netshield-Enterprise/netshield-analyzer/cmd/analyzer@latest
```

**From Release (Recommended):**
```bash
# Linux/macOS
curl -LO https://github.com/Netshield-Enterprise/netshield-analyzer/releases/latest/download/netshield-linux-amd64.tar.gz
tar xzf netshield-linux-amd64.tar.gz
sudo mv netshield /usr/local/bin/
```

### Basic Usage

```bash
# Analyze a Maven project
cd /path/to/your/maven/project
netshield --packages com.yourcompany

# CI/CD mode (minimal output, proper exit codes)
netshield --packages com.yourcompany --format core

# JSON output for tooling
netshield --packages com.yourcompany --format json
```

---

## What Problem This Solves

Most vulnerability scanners report every CVE in your dependency tree, regardless of whether your code can reach the vulnerable methods. This creates:

- **Alert fatigue**: Security teams drowning in non-exploitable findings
- **Prioritization paralysis**: No clear signal on what to fix first
- **Wasted engineering time**: Patching vulnerabilities that pose no real risk

NetShield performs **static reachability analysis** to classify vulnerabilities as:
- **Reachable**: Vulnerable code is called by your application (fix immediately)
- **Unreachable**: Vulnerable code exists but cannot be triggered (deprioritize)
- **Unknown**: Analysis incomplete (manual review recommended)

---

## CI/CD Integration

NetShield is designed for CI/CD pipelines with proper exit codes:

| Exit Code | Meaning | CI/CD Action |
|-----------|---------|--------------|
| **0** | Safe to ship | ✅ Pass build |
| **1** | Reachable vulnerability | ❌ Fail build |
| **2** | Analysis failure | ❌ Fail build |

### GitHub Actions

```yaml
- name: Security Gate
  run: netshield --packages com.yourcompany --format core
```

### GitLab CI

```yaml
netshield:
  script:
    - netshield --packages com.yourcompany --format core
```

### Jenkins

```groovy
sh 'netshield --packages com.yourcompany --format core'
```

---

## Output Formats

### Core (CI/CD Optimized)
Minimal output, clear decision, proper exit codes.

```bash
netshield --packages com.example --format core
```

### Executive (Default)
Decision + intelligence + supply chain scoring.

```bash
netshield --packages com.example
```

### Debug
Full technical analysis with call graphs.

```bash
netshield --packages com.example --format debug
```

### JSON
Machine-readable for tooling integration.

```bash
netshield --packages com.example --format json
```

---

## Example Output

```
════════════════════════════════════════════════════════════════
                   NetShield Release Analysis
════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
────────────────────────────────────────────────────────────────
1 vulnerability exists in dependencies but cannot be triggered by application code.
No exploitable security risk exists in this release.

RELEASE STATUS
✓ SAFE TO SHIP

RELEASE CONFIDENCE
High confidence this release introduces no exploitable security risk.

BUSINESS RISK
────────────────────────────────────────────────────────────────
Exploit Risk         NONE
Production Exposure  NONE
Patch Urgency        LOW (maintenance window)
Engineering Impact   None

SUPPLY CHAIN TRUST SCORE
────────────────────────────────────────────────────────────────
96 / 100  (Excellent)

SECURITY EVIDENCE
────────────────────────────────────────────────────────────────
1 critical vulnerability detected but unreachable from execution paths.

CVE: GHSA-mjmj-j48q-9wg2
Package: org.yaml:snakeyaml
Severity: CRITICAL
Reachability: UNREACHABLE
```

---

## How It Works

1. **Dependency Resolution**: Parses `pom.xml` and resolves transitive dependencies
2. **JAR Extraction**: Downloads and extracts bytecode from Maven Central
3. **Call Graph Construction**: Builds method-level call graphs using bytecode analysis
4. **CVE Lookup**: Queries OSV API for known vulnerabilities
5. **Reachability Analysis**: Determines if application code paths reach vulnerable methods
6. **Risk Classification**: Categorizes findings as Reachable, Unreachable, or Unknown

---

## Limitations

1. **Reflection**: Methods invoked via reflection are marked as `Unknown`
2. **Dynamic Loading**: Dynamically loaded classes may not be analyzed
3. **Build Tool**: Currently supports Maven only (Gradle support planned)
4. **Language**: Java bytecode only (Kotlin/Scala supported if compiled to JVM)
5. **Accuracy**: Call graph construction is best-effort; complex frameworks may reduce precision

---

## Performance

| Project Size | Dependencies | Analysis Time |
|--------------|--------------|---------------|
| Small | < 50 | ~10 seconds |
| Medium | 50-200 | ~30 seconds |
| Large | 200-500 | ~60 seconds |
| Enterprise | 500+ | ~2-5 minutes |

---

## Roadmap

- [ ] Gradle support
- [ ] SARIF output format for GitHub Security
- [ ] Improved reflection analysis
- [ ] Historical trend tracking
- [ ] GitHub PR comment integration
- [ ] Custom policy enforcement (SOC2, PCI-DSS)

---

## Creating Releases

```bash
# Tag a version
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# GitHub Actions automatically builds binaries for:
# - Linux (amd64, arm64)
# - macOS (Intel, Apple Silicon)
# - Windows (amd64)
```

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## License

NetShield is dual-licensed:

- **AGPL-3.0**: Free for open source projects ([LICENSE-AGPL](LICENSE-AGPL))
- **Commercial**: For proprietary use ([LICENSE-COMMERCIAL](LICENSE-COMMERCIAL))

For commercial licensing: licensing@net-shield.net

---

## Security Disclosure

To report security vulnerabilities in NetShield itself: security@net-shield.net

Do not open public issues for security concerns.
