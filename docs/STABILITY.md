# API Stability Policy

This document defines the stability guarantees for agent-audit's public interfaces. Understanding these levels helps you decide which features to depend on in production environments.

## Stability Levels

| Level | Definition | Compatibility Promise |
|-------|------------|----------------------|
| **Stable** | Production-ready, follows semantic versioning | Backward compatible within major version; breaking changes require new major version with migration guide |
| **Semi-Stable** | Mostly stable, may evolve | Backward compatible; new fields may be added but existing fields won't be removed or renamed |
| **Evolving** | Active development, may change | May change between minor versions; migration guides provided for breaking changes |
| **Experimental** | For testing only | No compatibility guarantees; may change or be removed without notice |

---

## Public Interface Stability

### Command Line Interface

| Interface | Level | Since | Notes |
|-----------|-------|-------|-------|
| `agent-audit scan <path>` | **Stable** | v0.1.0 | Core scanning command |
| `agent-audit inspect <server>` | **Stable** | v0.2.0 | MCP server inspection |
| `agent-audit init` | **Stable** | v0.3.0 | Configuration initialization |
| `--format` option | **Stable** | v0.1.0 | Output formats: terminal, json, sarif, markdown |
| `--severity` option | **Stable** | v0.3.0 | Filter by severity: info, low, medium, high, critical |
| `--fail-on` option | **Stable** | v0.1.0 | Exit code threshold |
| `--baseline` option | **Stable** | v0.4.0 | Incremental scanning with baseline |
| `--save-baseline` option | **Stable** | v0.4.0 | Save current findings as baseline |
| `--output` / `-o` option | **Stable** | v0.1.0 | Output file path |
| `--rules-dir` option | **Stable** | v0.2.0 | Custom rules directory |
| `--min-tier` option | Semi-Stable | v0.8.0 | Confidence tier filtering |
| `--verbose` / `-v` option | **Stable** | v0.1.0 | Verbose output |
| `--quiet` / `-q` option | **Stable** | v0.1.0 | Quiet mode |
| `--no-color` option | **Stable** | v0.2.0 | Disable colored output |

### Rule Identifiers

| Interface | Level | Since | Notes |
|-----------|-------|-------|-------|
| Rule IDs (AGENT-XXX) | **Stable** | v0.1.0 | **Once published, rule IDs are never reused or semantically redefined** |
| Rule severity values | **Stable** | v0.3.0 | critical, high, medium, low, info |
| OWASP Agentic mapping (ASI-XX) | **Stable** | v0.3.0 | Maps to OWASP Agentic Top 10 2026 |
| CWE mapping | **Stable** | v0.1.0 | Common Weakness Enumeration IDs |

### Output Formats

| Interface | Level | Since | Notes |
|-----------|-------|-------|-------|
| SARIF 2.1.0 output | **Stable** | v0.2.0 | Conforms to [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) |
| JSON output schema | Semi-Stable | v0.1.0 | Core fields stable; new fields may be added |
| Terminal output format | Evolving | v0.1.0 | Visual formatting may change |
| Markdown output | Evolving | v0.3.0 | Report structure may change |

### Configuration Files

| Interface | Level | Since | Notes |
|-----------|-------|-------|-------|
| `.agent-audit.yaml` schema | Evolving | v0.3.0 | Configuration format may evolve with migration support |
| Baseline file format (JSON) | Semi-Stable | v0.4.0 | New fields may be added; existing fields preserved |
| `# noaudit` inline suppression | **Stable** | v0.2.0 | Comment-based suppression marker |

### Programmatic API

| Interface | Level | Since | Notes |
|-----------|-------|-------|-------|
| `import agent_audit` | **Experimental** | - | Python API for programmatic use; not recommended for external dependencies |
| Scanner classes | **Experimental** | - | Internal implementation details |
| Model classes (Finding, etc.) | **Experimental** | - | May change without notice |

---

## Rule Lifecycle Policy

### Rule States

```
ACTIVE ──────► DEPRECATED ──────► REMOVED
              (2 major versions)
```

| State | Description | Scan Behavior |
|-------|-------------|---------------|
| **Active** | Rule is actively maintained and enforced | Findings reported normally |
| **Deprecated** | Rule is scheduled for removal | Findings reported with deprecation warning |
| **Removed** | Rule no longer exists | Rule ID reserved, never reused |

### Rule ID Assignment

1. **New rules** receive the next available AGENT-XXX ID
2. **Rule IDs are permanent** — once assigned, an ID is never reused for a different vulnerability
3. **Semantic changes** require a new rule ID — if a rule's detection logic changes fundamentally, create a new rule and deprecate the old one
4. **ID renumbering is prohibited** — existing IDs must not be changed to maintain baseline compatibility

### Deprecation Process

When a rule is deprecated:

1. The rule YAML gains `deprecated: true` and `deprecated_since: "vX.Y.0"`
2. Scans emit a warning: `AGENT-XXX is deprecated and will be removed in vX+2.0.0`
3. The rule remains functional for 2 major versions
4. After removal, the ID is reserved and documented in [RULES.md](RULES.md)

### Example Timeline

```
v1.0.0: AGENT-099 introduced (Active)
v2.0.0: AGENT-099 deprecated (deprecated: true, deprecated_since: v2.0.0)
v3.0.0: AGENT-099 still works with warning
v4.0.0: AGENT-099 removed (ID reserved forever)
```

---

## Version Compatibility

### Semantic Versioning

agent-audit follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH
  │     │     └── Bug fixes only, no interface changes
  │     └──────── New features, Stable interfaces remain compatible
  └────────────── Breaking changes to Stable interfaces (with migration guide)
```

### Compatibility Matrix

| Version Change | Stable | Semi-Stable | Evolving | Experimental |
|---------------|--------|-------------|----------|--------------|
| Patch (0.15.x) | No changes | No changes | No changes | May change |
| Minor (0.x.0) | No breaking changes | May add fields | May change | May change |
| Major (x.0.0) | May break with migration | May break with migration | May break | May break |

### Upgrade Guidance

**Patch upgrades (e.g., 0.15.0 → 0.15.1)**
- Safe to upgrade immediately
- No action required

**Minor upgrades (e.g., 0.15.0 → 0.16.0)**
- Review CHANGELOG for new features
- Existing integrations continue to work
- Consider adopting new capabilities

**Major upgrades (e.g., 0.x.0 → 1.0.0)**
- Review migration guide in CHANGELOG
- Test in staging environment first
- Update baseline files if schema changed
- Review deprecated rules for removal

---

## Baseline File Compatibility

Baseline files created by older versions remain readable by newer versions:

| Baseline Version | Readable By |
|-----------------|-------------|
| v0.4.0 format | v0.4.0+ |
| v0.8.0 format (with tiers) | v0.8.0+ |
| v0.15.0 format (with confidence) | v0.15.0+ |

When upgrading, existing baselines continue to function. New findings may appear if:
- New rules were added
- Detection logic was improved
- Confidence thresholds changed

---

## SARIF Schema Stability

The SARIF output conforms to [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and includes:

### Standard Fields (Stable)
- `version`: Always "2.1.0"
- `$schema`: Standard SARIF schema URL
- `runs[].tool`: Tool identification
- `runs[].results[]`: Finding details
- `runs[].results[].ruleId`: AGENT-XXX identifiers
- `runs[].results[].level`: error/warning/note/none
- `runs[].results[].message`: Finding description
- `runs[].results[].locations[]`: File and line information

### Extension Fields (Semi-Stable)
Custom fields in `properties` objects may be added but not removed:
- `properties.owasp_agentic_id`: ASI-XX mapping
- `properties.confidence`: Confidence score (0.0-1.0)
- `properties.tier`: BLOCK/WARN/INFO/SUPPRESSED
- `properties.cwe_id`: CWE identifier
- `properties.tags[]`: Classification tags

---

## Questions and Support

For questions about stability guarantees or upgrade assistance:

1. Check the [CHANGELOG](../CHANGELOG.md) for version-specific notes
2. Review [GitHub Issues](https://github.com/agent-audit/agent-audit/issues) for known compatibility issues
3. Open a new issue with the `stability` label for clarification requests

---

*Last updated: v0.16.0*
