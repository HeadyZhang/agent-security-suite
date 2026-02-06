# Agent Audit Architecture

> **Version:** v0.15.1
> **Last Updated:** 2026-02-06

---

## Overview

Agent Audit is a CLI static analysis tool for AI agent security — "ESLint for AI agents". It detects vulnerabilities mapped to the OWASP Agentic Top 10 (2026).

---

## 1. Directory Structure

```
agent-security-suite/
├── packages/audit/                    # Core Python package (Poetry managed)
│   └── agent_audit/
│       ├── __init__.py               # Package entry, version import
│       ├── version.py                # Version number (0.15.1)
│       ├── cli/                      # Command line interface
│       │   ├── main.py              # Click CLI entry point
│       │   ├── commands/            # Subcommand implementations
│       │   │   ├── scan.py          # Core scanning workflow
│       │   │   ├── inspect_cmd.py   # MCP runtime inspection
│       │   │   └── init.py          # Config file initialization
│       │   └── formatters/          # Output formatters
│       │       ├── terminal.py      # Rich colored output
│       │       ├── json.py          # JSON output
│       │       ├── sarif.py         # SARIF 2.1.0 format
│       │       └── markdown.py      # Markdown reports
│       ├── scanners/                 # Static analysis scanners
│       │   ├── base.py              # BaseScanner ABC
│       │   ├── python_scanner.py    # Python AST scanner (~4000 lines)
│       │   ├── mcp_config_scanner.py # MCP config analysis (~1100 lines)
│       │   ├── secret_scanner.py    # Credential detection (~850 lines)
│       │   ├── privilege_scanner.py # Privilege escalation (~1150 lines)
│       │   └── mcp_inspector.py     # Runtime MCP inspection
│       ├── analysis/                 # Analysis modules (v0.10+)
│       │   ├── semantic_analyzer.py # Multi-stage credential analysis
│       │   ├── taint_tracker.py     # Data flow tracking
│       │   ├── framework_detector.py # Framework-specific FP reduction
│       │   ├── dangerous_operation_analyzer.py # AGENT-034 analysis
│       │   ├── context_classifier.py # Context-based confidence
│       │   └── confidence_matrix.py # Confidence calibration
│       ├── rules/                    # Rule engine
│       │   ├── engine.py            # Rule execution engine
│       │   └── loader.py            # YAML rule loader
│       ├── models/                   # Data models
│       │   ├── finding.py           # Finding dataclass, OWASP mapping
│       │   ├── risk.py              # Severity/Category enums
│       │   └── tool.py              # ToolDefinition dataclass
│       └── config/                   # Configuration management
│           └── ignore.py            # .agent-audit.yaml parser
│
├── rules/builtin/                     # Built-in YAML rule definitions
│   ├── owasp_agentic.yaml           # Original rules (AGENT-001~005)
│   ├── owasp_agentic_v2.yaml        # Extended rules (AGENT-010~025)
│   ├── langchain_security_v030.yaml # LangChain framework rules
│   ├── mcp_security_v030.yaml       # MCP configuration rules
│   └── asi_coverage_v030.yaml       # Tool misuse & trust rules
│
├── tests/                             # Test suite (at project root!)
│   ├── fixtures/                    # Test code samples
│   ├── benchmark/                   # Benchmark test suite
│   ├── test_scanners/               # Scanner unit tests
│   ├── test_cli/                    # CLI command tests
│   ├── test_analysis/               # Semantic analysis tests
│   └── test_formatters/             # Output formatter tests
│
├── docs/                              # Documentation
│   ├── STABILITY.md                 # API stability policy
│   ├── RULES.md                     # Rule reference (40 rules)
│   ├── CI-INTEGRATION.md            # CI/CD integration guide
│   └── ARCHITECTURE.md              # This file
│
├── .github/
│   ├── workflows/                   # CI/CD pipelines
│   │   ├── ci.yml                  # Tests + lint
│   │   ├── benchmark.yml           # Benchmark tests
│   │   └── publish.yml             # PyPI release
│   └── ISSUE_TEMPLATE/              # Issue templates
│
├── action.yml                         # GitHub Action definition
├── CONTRIBUTING.md                    # Contributor guide
└── README.md                          # Project overview
```

---

## 2. Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI Layer                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ scan.py  │  │ inspect  │  │ init.py  │  │ formatters/*.py  │ │
│  └────┬─────┘  └──────────┘  └──────────┘  └────────┬─────────┘ │
└───────┼─────────────────────────────────────────────┼───────────┘
        │                                             │
        ▼                                             │
┌───────────────────────────────────────────┐         │
│              Scanner Layer                 │         │
│  ┌────────────────┐  ┌─────────────────┐  │         │
│  │ python_scanner │  │ mcp_config_scan │  │         │
│  │  (AST-based)   │  │  (JSON/YAML)    │  │         │
│  └───────┬────────┘  └────────┬────────┘  │         │
│          │                    │           │         │
│  ┌───────┴────────┐  ┌────────┴────────┐  │         │
│  │ secret_scanner │  │privilege_scanner│  │         │
│  │  (regex/entropy)│  │  (escalation)   │  │         │
│  └────────────────┘  └─────────────────┘  │         │
└──────────────────────┬────────────────────┘         │
                       │                              │
                       ▼                              │
┌──────────────────────────────────────────┐          │
│           Analysis Layer (v0.10+)         │          │
│  ┌────────────────┐  ┌────────────────┐  │          │
│  │semantic_analyzer│  │ taint_tracker  │  │          │
│  │ (3-stage cred) │  │ (data flow)    │  │          │
│  └────────────────┘  └────────────────┘  │          │
│  ┌────────────────┐  ┌────────────────┐  │          │
│  │framework_detect│  │confidence_matrix│  │          │
│  │ (FP reduction) │  │ (calibration)  │  │          │
│  └────────────────┘  └────────────────┘  │          │
└──────────────────────┬───────────────────┘          │
                       │                              │
                       ▼                              │
┌──────────────────────────────────────────┐          │
│             Rules Engine                  │          │
│  ┌────────────┐  ┌─────────────────────┐ │          │
│  │ engine.py  │──│ rules/builtin/*.yaml│ │          │
│  │ (evaluate) │  │   (40 rules)        │ │          │
│  └─────┬──────┘  └─────────────────────┘ │          │
└────────┼─────────────────────────────────┘          │
         │                                            │
         ▼                                            │
┌─────────────────────────────────────────────────────┤
│                  Data Models                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ Finding  │  │ Severity │  │ Location │──────────┘
│  │(dataclass)│  │ (enum)   │  │(dataclass)│
│  └──────────┘  └──────────┘  └──────────┘
└─────────────────────────────────────────────────────┘
```

---

## 3. Scanning Workflow

```
agent-audit scan <path> --format sarif --fail-on high
                │
                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. Initialization                                                │
│    - Load .agent-audit.yaml (IgnoreManager)                     │
│    - Load rules/builtin/*.yaml (RuleEngine)                     │
│    - Initialize scanners                                         │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. File Discovery                                                │
│    - Walk directory tree                                         │
│    - Filter by extension (.py, .json, .yaml, etc.)              │
│    - Apply exclude patterns                                      │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Parallel Scanning                                             │
│    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│    │   Python    │  │     MCP     │  │   Secret    │            │
│    │   Scanner   │  │   Scanner   │  │   Scanner   │            │
│    │  (AST parse)│  │(config parse)│  │(regex match)│            │
│    └──────┬──────┘  └──────┬──────┘  └──────┬──────┘            │
│           │                │                │                    │
│           └────────────────┼────────────────┘                    │
│                            │                                     │
│                            ▼                                     │
│              ┌─────────────────────────┐                        │
│              │   Merge ScanResults     │                        │
│              └─────────────────────────┘                        │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Rule Evaluation                                               │
│    - Pattern matching against scan results                       │
│    - Create Finding objects                                      │
│    - Apply semantic analysis (v0.10+)                           │
│    - Calculate confidence scores                                 │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Post-Processing                                               │
│    - Apply ignore rules (suppression)                           │
│    - Filter by baseline (incremental)                           │
│    - Filter by min_severity                                      │
│    - Assign confidence tiers (BLOCK/WARN/INFO/SUPPRESSED)       │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Output                                                        │
│    - Format as terminal/json/sarif/markdown                     │
│    - Calculate exit code based on --fail-on                     │
│    - Write to stdout or --output file                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Rule Coverage

### OWASP Agentic Top 10 (2026)

| ASI | Category | Rules | Status |
|-----|----------|-------|--------|
| ASI-01 | Agent Goal Hijacking | AGENT-010, 011, 027, 050 | ✅ |
| ASI-02 | Tool Misuse | AGENT-001, 026, 029, 032, 034-036, 040, 041 | ✅ |
| ASI-03 | Privilege Abuse | AGENT-002, 013, 014, 042 | ✅ |
| ASI-04 | Supply Chain | AGENT-004, 005, 015, 016, 030 | ✅ |
| ASI-05 | Code Execution | AGENT-003, 017, 031 | ✅ |
| ASI-06 | Memory Poisoning | AGENT-018, 019 | ✅ |
| ASI-07 | Inter-Agent Comms | AGENT-020 | ✅ |
| ASI-08 | Cascading Failures | AGENT-021, 022, 028 | ✅ |
| ASI-09 | Trust Exploitation | AGENT-023, 033, 037-039, 052 | ✅ |
| ASI-10 | Rogue Agents | AGENT-024, 025, 053 | ✅ |

**Coverage: 10/10 ASI categories, 40 rules total**

---

## 5. Key Interfaces

### Scanner Base Class

```python
# scanners/base.py
from abc import ABC, abstractmethod
from typing import Sequence

class BaseScanner(ABC):
    name: str

    @abstractmethod
    def scan(self, path: Path) -> Sequence[ScanResult]:
        """Return Sequence (not List) to support covariant subtypes."""
        pass
```

### Finding Model

```python
# models/finding.py
@dataclass
class Finding:
    rule_id: str              # "AGENT-034"
    title: str
    description: str
    severity: Severity        # CRITICAL/HIGH/MEDIUM/LOW/INFO
    category: Category
    location: Location        # file_path, line, snippet

    # Confidence & tiering (v0.5+)
    confidence: float = 1.0   # 0.0-1.0
    tier: str = "WARN"        # BLOCK/WARN/INFO/SUPPRESSED

    # Suppression
    suppressed: bool = False
    suppressed_reason: Optional[str] = None

    # Metadata
    cwe_id: Optional[str] = None
    owasp_agentic_id: Optional[str] = None
```

### Rule YAML Schema

```yaml
rules:
  - id: AGENT-XXX
    title: "Rule Title"
    description: "What this rule detects"
    severity: high  # critical/high/medium/low/info
    category: tool_misuse
    owasp_agentic_id: "ASI-02"
    cwe_id: "CWE-XX"

    detection:
      type: ast  # ast/config/regex
      patterns:
        - pattern_type: "..."
          # Pattern-specific fields

    remediation:
      description: "How to fix"
      code_example: |
        # Fixed code
      references:
        - "https://..."
```

---

## 6. Confidence-Based Tiering

v0.5+ introduced confidence-based result tiering:

| Tier | Confidence | Action |
|------|------------|--------|
| **BLOCK** | >= 0.90 | Fix immediately, very high confidence |
| **WARN** | >= 0.60 | Should fix, high confidence |
| **INFO** | >= 0.30 | Review recommended |
| **SUPPRESSED** | < 0.30 | Likely false positive |

Confidence factors:
- Context (tool decorator, class method, standalone)
- Value analysis (entropy, placeholder patterns)
- Framework detection (Pydantic, LangChain internals)
- File path (test files, examples)

---

## 7. Test Structure

```bash
# Run all tests (from packages/audit/)
poetry run pytest ../../tests/ -v

# Run with coverage
poetry run pytest ../../tests/ -v --cov=agent_audit

# Run specific scanner tests
poetry run pytest ../../tests/test_scanners/ -v

# Run benchmark tests
poetry run python ../../tests/benchmark/agent-vuln-bench/harness/run_harness.py
```

Test categories:
- `test_scanners/` - Scanner unit tests
- `test_cli/` - CLI command tests
- `test_analysis/` - Semantic analysis tests
- `test_formatters/` - Output formatter tests
- `benchmark/` - Accuracy benchmark suite

---

## 8. Extension Points

### Adding a New Rule

1. Define in `rules/builtin/*.yaml`
2. Implement detection in appropriate scanner
3. Add test fixture in `tests/fixtures/`
4. Add test case in `tests/test_scanners/`
5. Update `docs/RULES.md`

### Adding a New Scanner

1. Create `scanners/your_scanner.py`
2. Extend `BaseScanner`
3. Return `Sequence[ScanResult]`
4. Register in `cli/commands/scan.py`
5. Add tests

### Adding a New Output Format

1. Create `cli/formatters/your_format.py`
2. Register in CLI options
3. Add tests

---

## 9. References

- [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Rule Reference](RULES.md)
- [API Stability](STABILITY.md)
- [CI Integration](CI-INTEGRATION.md)
