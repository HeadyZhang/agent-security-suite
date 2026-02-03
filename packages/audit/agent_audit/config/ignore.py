"""
Ignore and Allowlist configuration management.

Handles:
- Loading .agent-audit.yaml configuration
- Rule-level and path-level ignore rules
- Confidence score adjustment based on allowlists
- Baseline scanning support
"""

import fnmatch
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

import yaml

from agent_core.models.finding import Finding

logger = logging.getLogger(__name__)


@dataclass
class IgnoreRule:
    """Single ignore rule definition."""
    rule_id: Optional[str] = None        # Rule ID to ignore, e.g., "AGENT-003"
    paths: List[str] = field(default_factory=list)  # Glob path patterns
    tools: List[str] = field(default_factory=list)  # Tool names
    reason: str = ""


@dataclass
class ScanConfig:
    """Scan configuration."""
    exclude: List[str] = field(default_factory=list)
    min_severity: str = "low"
    fail_on: str = "high"


@dataclass
class AllowlistConfig:
    """Allowlist configuration."""
    # Network hosts allowed for AGENT-003 (data exfiltration)
    allowed_hosts: List[str] = field(default_factory=list)

    # File paths allowed for file access
    allowed_paths: List[str] = field(default_factory=list)

    # Ignore rules
    ignore_rules: List[IgnoreRule] = field(default_factory=list)

    # Inline ignore marker (like # noqa)
    inline_ignore_marker: str = "# noaudit"

    # Scan configuration
    scan: ScanConfig = field(default_factory=ScanConfig)


class IgnoreManager:
    """
    Manager for ignore rules and allowlist configuration.

    Loads configuration from .agent-audit.yaml and provides methods
    to check if findings should be suppressed or have adjusted confidence.
    """

    CONFIG_FILENAMES = ['.agent-audit.yaml', '.agent-audit.yml', 'agent-audit.yaml']

    def __init__(self):
        self.config: Optional[AllowlistConfig] = None
        self._loaded_from: Optional[Path] = None
        self._base_path: Optional[Path] = None  # Base path for relative path matching

    def load(self, project_path: Path) -> bool:
        """
        Load ignore configuration from project path.

        Searches for config in:
        1. The scan target directory (project_path)
        2. Current working directory (if different)
        3. Parent directories up to filesystem root

        Args:
            project_path: Root path of the project to scan

        Returns:
            True if configuration was loaded successfully
        """
        # Resolve to absolute path
        project_path = project_path.resolve()
        cwd = Path.cwd().resolve()

        # Collect search paths (deduplicated, ordered)
        search_paths: List[Path] = []

        # 1. Scan target directory
        search_paths.append(project_path)

        # 2. CWD if different from target
        if cwd != project_path:
            search_paths.append(cwd)

        # 3. Parent directories of project_path up to root
        parent = project_path.parent
        while parent != parent.parent:
            if parent not in search_paths:
                search_paths.append(parent)
            parent = parent.parent

        # Search each path for config files
        for search_path in search_paths:
            for filename in self.CONFIG_FILENAMES:
                config_path = search_path / filename
                if config_path.exists():
                    # Store base path as the scan target (for relative path matching)
                    self._base_path = project_path
                    return self._load_file(config_path)

        return False

    def get_exclude_patterns(self) -> List[str]:
        """Get the list of exclude patterns from scan config."""
        if self.config and self.config.scan:
            return self.config.scan.exclude
        return []

    def _load_file(self, path: Path) -> bool:
        """Load configuration from a specific file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data:
                return False

            # Parse ignore rules
            ignore_rules = []
            for rule_data in data.get('ignore', []):
                rule = IgnoreRule(
                    rule_id=rule_data.get('rule_id'),
                    paths=rule_data.get('paths', []),
                    tools=rule_data.get('tools', []),
                    reason=rule_data.get('reason', '')
                )
                ignore_rules.append(rule)

            # Parse scan configuration (handle None value from YAML)
            scan_data = data.get('scan') or {}
            scan_config = ScanConfig(
                exclude=scan_data.get('exclude') or [],
                min_severity=scan_data.get('min_severity') or 'low',
                fail_on=scan_data.get('fail_on') or 'high'
            )

            self.config = AllowlistConfig(
                allowed_hosts=data.get('allowed_hosts', []),
                allowed_paths=data.get('allowed_paths', []),
                ignore_rules=ignore_rules,
                inline_ignore_marker=data.get('inline_ignore_marker', '# noaudit'),
                scan=scan_config
            )
            self._loaded_from = path
            logger.debug(f"Loaded config from {path}")
            return True

        except yaml.YAMLError as e:
            logger.warning(f"Failed to parse {path}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Error loading {path}: {e}")
            return False

    def should_ignore(
        self,
        rule_id: str,
        file_path: str,
        tool_name: str = ""
    ) -> Optional[str]:
        """
        Check if a finding should be ignored.

        Args:
            rule_id: The rule ID (e.g., "AGENT-003")
            file_path: Path of the file where finding was detected
            tool_name: Optional tool name involved

        Returns:
            Ignore reason if should be ignored, None otherwise
        """
        if not self.config:
            return None

        # Compute relative path for matching
        rel_path = self._get_relative_path(file_path)

        for ignore in self.config.ignore_rules:
            # Match rule ID if specified (support "*" as wildcard for all rules)
            if ignore.rule_id and ignore.rule_id != "*" and ignore.rule_id != rule_id:
                continue

            # Match paths if specified
            if ignore.paths:
                path_matched = self._match_any_pattern(rel_path, ignore.paths)
                if not path_matched:
                    continue

            # Match tool name if specified
            if ignore.tools:
                if tool_name and tool_name not in ignore.tools:
                    continue

            # All conditions matched
            return ignore.reason or f"Suppressed by config ({self._loaded_from})"

        return None

    def _get_relative_path(self, file_path: str) -> str:
        """
        Convert a file path to a relative path for pattern matching.

        If the file_path is absolute and within the base_path,
        returns the relative portion. Otherwise returns the original path.
        """
        try:
            file_path_obj = Path(file_path)
            if file_path_obj.is_absolute() and self._base_path:
                try:
                    return str(file_path_obj.relative_to(self._base_path))
                except ValueError:
                    # file_path is not relative to base_path
                    pass
            return file_path
        except Exception:
            return file_path

    def _match_any_pattern(self, path: str, patterns: List[str]) -> bool:
        """
        Check if a path matches any of the given glob patterns.

        Handles both simple patterns (tests/**) and recursive patterns.
        Uses forward slashes for cross-platform consistency.
        """
        # Normalize path separators to forward slashes
        normalized_path = path.replace('\\', '/')

        for pattern in patterns:
            normalized_pattern = pattern.replace('\\', '/')

            # Try direct fnmatch
            if fnmatch.fnmatch(normalized_path, normalized_pattern):
                return True

            # For patterns like "tests/**", also match exact prefix "tests/"
            if normalized_pattern.endswith('/**'):
                prefix = normalized_pattern[:-3]  # Remove "/**"
                if normalized_path.startswith(prefix + '/') or normalized_path == prefix:
                    return True

            # For patterns like "**/test_*", match against filename
            if normalized_pattern.startswith('**/'):
                suffix_pattern = normalized_pattern[3:]  # Remove "**/"
                filename = Path(normalized_path).name
                if fnmatch.fnmatch(filename, suffix_pattern):
                    return True
                # Also try matching any path component
                for part in Path(normalized_path).parts:
                    if fnmatch.fnmatch(part, suffix_pattern):
                        return True

        return False

    def should_exclude_path(self, file_path: str) -> bool:
        """
        Check if a file path should be excluded from scanning.

        Args:
            file_path: Path to check (can be absolute or relative)

        Returns:
            True if the path should be excluded
        """
        if not self.config or not self.config.scan.exclude:
            return False

        rel_path = self._get_relative_path(file_path)
        return self._match_any_pattern(rel_path, self.config.scan.exclude)

    def adjust_confidence(
        self,
        rule_id: str,
        finding_metadata: Dict[str, Any]
    ) -> float:
        """
        Calculate confidence adjustment based on allowlist.

        Args:
            rule_id: The rule ID
            finding_metadata: Metadata from the finding (may contain target_host, file_path, etc.)

        Returns:
            Confidence multiplier (0.0 to 1.0)
        """
        if not self.config:
            return 1.0

        adjustment = 1.0

        # For AGENT-003 (data exfiltration), check if target is allowed
        if rule_id == "AGENT-003":
            target_host = finding_metadata.get('target_host', '')
            if target_host:
                for pattern in self.config.allowed_hosts:
                    if fnmatch.fnmatch(target_host, pattern):
                        adjustment *= 0.3  # Significant reduction
                        break

        # Check if file path is in allowed paths
        file_path = finding_metadata.get('file_path', '')
        if file_path:
            for allowed in self.config.allowed_paths:
                if file_path.startswith(allowed):
                    adjustment *= 0.7
                    break

        return adjustment

    def apply_to_finding(self, finding: Finding) -> Finding:
        """
        Apply ignore rules and confidence adjustments to a finding.

        Args:
            finding: The finding to process

        Returns:
            The finding with suppressed/confidence fields updated
        """
        # Check if should be suppressed
        tool_name = finding.metadata.get('tool_name', '')
        ignore_reason = self.should_ignore(
            finding.rule_id,
            finding.location.file_path,
            tool_name
        )

        if ignore_reason:
            finding.suppressed = True
            finding.suppressed_reason = ignore_reason
            finding.suppressed_by = str(self._loaded_from) if self._loaded_from else None

        # Adjust confidence
        adjustment = self.adjust_confidence(finding.rule_id, finding.metadata)
        finding.confidence *= adjustment

        return finding


# Baseline scanning support

def compute_fingerprint(finding: Finding) -> str:
    """
    Compute a stable fingerprint for a finding.

    The fingerprint is used for baseline comparison and deduplication.
    It's stable across reruns for the same issue.
    """
    components = [
        finding.rule_id,
        finding.location.file_path,
        str(finding.location.start_line),
        (finding.location.snippet or "")[:50]
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def save_baseline(findings: List[Finding], output_path: Path):
    """
    Save findings as a baseline file.

    Args:
        findings: List of findings to save as baseline
        output_path: Path to save the baseline file
    """
    baseline = {
        "version": "1.0",
        "created_at": datetime.utcnow().isoformat(),
        "fingerprints": [compute_fingerprint(f) for f in findings]
    }
    output_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load_baseline(baseline_path: Path) -> Set[str]:
    """
    Load fingerprints from a baseline file.

    Args:
        baseline_path: Path to the baseline file

    Returns:
        Set of fingerprints from the baseline
    """
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        return set(data.get("fingerprints", []))
    except Exception as e:
        logger.warning(f"Failed to load baseline from {baseline_path}: {e}")
        return set()


def filter_by_baseline(
    findings: List[Finding],
    baseline: Set[str]
) -> List[Finding]:
    """
    Filter findings to only include those not in the baseline.

    Args:
        findings: List of findings to filter
        baseline: Set of fingerprints from the baseline

    Returns:
        List of findings that are new (not in baseline)
    """
    return [
        f for f in findings
        if compute_fingerprint(f) not in baseline
    ]


def create_default_config() -> str:
    """
    Create a default .agent-audit.yaml configuration template.

    Returns:
        YAML string with default configuration
    """
    return '''# Agent Audit Configuration
# https://github.com/your-org/agent-audit

# Scan settings
scan:
  exclude:
    - "tests/**"
    - "venv/**"
    - "node_modules/**"
    - ".git/**"
  min_severity: low
  fail_on: high

# Allowed network hosts (reduces confidence for AGENT-003)
# Use wildcards: *.internal.company.com
allowed_hosts:
  - "*.internal.company.com"
  - "api.openai.com"
  - "api.anthropic.com"

# Allowed file paths
allowed_paths:
  - "/tmp"
  - "/app/data"

# Ignore rules
ignore:
  # Example: Ignore data exfiltration warnings in auth module
  # - rule_id: AGENT-003
  #   paths:
  #     - "auth/**"
  #   reason: "Auth module legitimately communicates with auth service"

  # Example: Ignore excessive permissions for admin agent
  # - rule_id: AGENT-002
  #   paths:
  #     - "admin_agent.py"
  #   reason: "Admin agent requires broad permissions by design"
'''
