# NetShield

**Reachability-based vulnerability analysis for Java applications**

NetShield determines whether vulnerabilities in your dependencies are actually exploitable by analyzing bytecode call graphs. It answers one question: *Can this CVE be triggered by my application code?*

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

## Who This Is For

- **DevSecOps Engineers**: Integrate security checks into CI/CD without blocking every build
- **Security Teams**: Focus on exploitable risks, not theoretical ones
- **Platform Teams**: Enforce release policies based on real risk, not CVE count

---

## Core Capabilities

1. **Dependency Analysis**: Parses Maven `pom.xml` to extract transitive dependencies
2. **Bytecode Call Graph Construction**: Builds method-level call graphs from JAR files
3. **CVE Intelligence**: Queries OSV database for known vulnerabilities
4. **Reachability Classification**: Determines if vulnerable methods are invoked by application code

---

## CI/CD Usage Philosophy

NetShield is designed to answer: **"Can I safely ship this release?"**

It provides three output formats:
- **Core**: Minimal decision snapshot for CI/CD pipelines
- **Executive**: Decision + intelligence for security reports
- **Debug**: Technical deep-dive for investigation

## Exit Code Behavior

| Exit Code | Meaning | CI/CD Action | When It Happens |
|-----------|---------|--------------|-----------------|
| **0** | Safe to ship | ✅ Pass build | No reachable vulnerabilities detected |
| **1** | Reachable vulnerability | ❌ Fail build | At least one reachable vulnerability found |
| **2** | Analysis failure | ❌ Fail build | Error during analysis (network, parsing, etc.) |

## How It Works

1. **Exit 0 (Success)**: All vulnerabilities are unreachable or no vulnerabilities found
2. **Exit 1 (Block)**: At least one vulnerability is reachable from application code
3. **Exit 2 (Error)**: Analysis couldn't complete (Maven parse error, network failure, etc.)

## Testing Exit Codes Locally

```bash
# Run analysis
netshield --packages com.example --format core

# Check exit code
echo $?

# 0 = safe to ship
# 1 = reachable vulnerability (would fail CI/CD)
# 2 = analysis error (would fail CI/CD)
```

## Output Format Recommendation for CI/CD

Use `--format core` for CI/CD pipelines:
- Minimal output (fast to parse in logs)
- Clear decision (SAFE TO SHIP / DO NOT SHIP)
- Proper exit codes

```bash
netshield --packages com.yourcompany --format core
```

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

### Basic Usage

```bash
# Analyze a Maven project
cd /path/to/your/maven/project
netshield --packages com.yourcompany

# CI/CD mode (minimal output)
netshield --packages com.yourcompany --format core

# Generate JSON for tooling integration
netshield --packages com.yourcompany --format json
```

### Example Command

```bash
netshield --packages com.example.app --format executive
```

---

## Example Output (Executive Format)

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

Factors:
✔ No reachable CVEs
✔ Complete reachability analysis
✔ All vulnerabilities unreachable
✔ Standard dependency management

SECURITY EVIDENCE
────────────────────────────────────────────────────────────────
1 critical vulnerability detected but unreachable from execution paths.

CVE: GHSA-mjmj-j48q-9wg2
Package: org.yaml:snakeyaml
Severity: CRITICAL

Reachability: UNREACHABLE
Reason: Vulnerable method exists but is never invoked

ACTIVE PROTECTION
────────────────────────────────────────────────────────────────
If future code makes any vulnerability reachable, NetShield will
fail the build automatically.
```

---

## How It Works

1. **Dependency Resolution**: Parses `pom.xml` and resolves transitive dependencies
2. **JAR Extraction**: Downloads and extracts bytecode from Maven Central
3. **Call Graph Construction**: Builds method-level call graphs using bytecode analysis
4. **CVE Lookup**: Queries OSV API for known vulnerabilities in dependencies
5. **Reachability Analysis**: Determines if application code paths reach vulnerable methods
6. **Risk Classification**: Categorizes findings as Reachable, Unreachable, or Unknown

---

## Threat Model

### In Scope
- Vulnerabilities in Maven dependencies (direct and transitive)
- Static reachability analysis via bytecode call graphs
- Known CVEs from OSV database

### Out of Scope
- Runtime behavior analysis
- Reflection-based invocations (marked as Unknown)
- Dynamic class loading
- Native code vulnerabilities
- Configuration-based vulnerabilities
- Gradle projects (Maven only currently)

---

## Limitations

1. **Reflection**: Methods invoked via reflection are marked as `Unknown` (conservative approach)
2. **Dynamic Loading**: Dynamically loaded classes may not be analyzed
3. **Build Tool**: Currently supports Maven only (Gradle support planned)
4. **Language**: Java bytecode only (Kotlin/Scala supported if compiled to JVM bytecode)
5. **Accuracy**: Call graph construction is best-effort; complex frameworks may reduce precision

---

## Performance Expectations

| Project Size | Dependencies | Analysis Time |
|--------------|--------------|---------------|
| Small | < 50 | ~10 seconds |
| Medium | 50-200 | ~30 seconds |
| Large | 200-500 | ~60 seconds |
| Enterprise | 500+ | ~2-5 minutes |

*Times are approximate and depend on network speed (Maven Central) and CPU.*

---

## Roadmap

- [ ] Gradle support
- [ ] SARIF output format for GitHub Security integration
- [ ] Improved reflection analysis
- [ ] Historical trend tracking
- [ ] GitHub PR comment integration
- [ ] Custom policy enforcement (e.g., SOC2, PCI-DSS)

---

## License

NetShield is dual-licensed:

- **AGPL-3.0**: Free for open source projects and evaluation ([LICENSE-AGPL](LICENSE-AGPL))
- **Commercial**: For proprietary use without copyleft requirements ([LICENSE-COMMERCIAL](LICENSE-COMMERCIAL))

For commercial licensing inquiries: licensing@net-shield.net

---

## Contributing

Contributions are welcome. Please open an issue before submitting large changes.

---

## Security Disclosure

To report security vulnerabilities in NetShield Real Risk Analyzer itself, email: security@net-shield.net

Do not open public issues for security concerns.
