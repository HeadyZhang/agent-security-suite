# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-03

### Added

- **Full OWASP Agentic Top 10 Coverage** - Expanded from 5 rules to complete coverage of all 10 ASI categories
- Custom rules support via `--rules-dir` option
- New detection rules:
  - AGENT-010: System Prompt Injection Vector (ASI-01)
  - AGENT-011: Missing Goal Validation (ASI-01)
  - AGENT-013: Long-Lived/Shared Credentials (ASI-03)
  - AGENT-014: Overly Permissive Agent Role (ASI-03)
  - AGENT-015: Untrusted MCP Server Source (ASI-04)
  - AGENT-016: Unvalidated RAG Data Source (ASI-04)
  - AGENT-017: Unsandboxed Code Execution (ASI-05)
  - AGENT-018: Unsanitized Memory Write (ASI-06)
  - AGENT-019: Unbounded Memory (ASI-06)
  - AGENT-020: Insecure Inter-Agent Communication (ASI-07)
  - AGENT-021: Missing Circuit Breaker (ASI-08)
  - AGENT-022: Tool Without Error Handling (ASI-08)
  - AGENT-023: Opaque Agent Output (ASI-09)
  - AGENT-024: No Kill Switch (ASI-10)
  - AGENT-025: No Observability (ASI-10)
- SARIF output now includes `OWASP-Agentic-{ASI-XX}` tags in `properties.tags`
- Extended Category enum with all OWASP Agentic categories
- OWASP Agentic ID mapping in Finding model

### Changed

- Improved Python AST scanner with additional detection patterns
- Enhanced rule engine to support OWASP Agentic ID mapping
- Updated SARIF formatter to include OWASP Agentic tags

### Fixed

- mypy type errors with class-level dict annotations
- Loop variable naming conflicts in scan command
- Cross-platform path normalization

## [0.1.0] - 2025-01-XX

### Added

- Initial release
- Python AST scanning for dangerous patterns
- MCP configuration scanning
- Secret detection (AWS keys, API tokens, etc.)
- Runtime MCP server inspection
- Output formats: terminal, JSON, SARIF, Markdown
- GitHub Action for CI/CD integration
- Baseline scanning for incremental analysis
- Configuration via `.agent-audit.yaml`
- Original 5 rules:
  - AGENT-001: Command Injection
  - AGENT-002: Excessive Permissions
  - AGENT-003: Data Exfiltration Chain
  - AGENT-004: Hardcoded Credentials
  - AGENT-005: Unverified MCP Server
