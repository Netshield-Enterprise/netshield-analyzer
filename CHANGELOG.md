# Changelog

All notable changes to NetShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Gradle support
- SARIF output format
- GitHub PR comment integration
- Historical trend tracking
- Custom policy enforcement

## [0.1.0] - 2026-02-02

### Added
- Initial public release
- Maven dependency analysis
- Bytecode call graph construction
- OSV CVE database integration
- Reachability-based vulnerability classification
- Three output formats: Core, Executive, Debug
- JSON output for tooling integration
- CI/CD exit codes (0=safe, 1=vulnerable, 2=error)
- Supply chain trust scoring (0-100)
- Executive summary generation
- Blast radius projection for unreachable vulnerabilities
- Dual licensing (AGPL-3.0 + Commercial)

### Supported Platforms
- Linux (amd64, arm64)
- macOS (Intel, Apple Silicon)
- Windows (amd64)

### Known Limitations
- Maven projects only (no Gradle support yet)
- Reflection-based method calls marked as Unknown
- Dynamic class loading not analyzed
- Best-effort call graph construction

---

## Release Notes Template

Use this template for future releases:

```markdown
## [X.X.X] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing functionality

### Fixed
- Bug fixes

### Security
- Security improvements

### Deprecated
- Features marked for removal

### Removed
- Removed features
```
