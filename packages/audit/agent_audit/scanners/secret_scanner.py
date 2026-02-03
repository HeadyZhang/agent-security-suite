"""Secret scanner for detecting hardcoded credentials."""

import re
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Pattern, Tuple
from dataclasses import dataclass, field

from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class SecretMatch:
    """A detected secret."""
    pattern_name: str
    line_number: int
    line_content: str
    matched_text: str
    start_col: int
    end_col: int
    severity: str  # critical, high, medium


@dataclass
class SecretScanResult(ScanResult):
    """Result of secret scanning."""
    secrets: List[SecretMatch] = field(default_factory=list)


class SecretScanner(BaseScanner):
    """
    Regex-based secret detection scanner.

    Detects:
    - AWS access keys
    - API keys (OpenAI, Anthropic, GitHub, etc.)
    - Generic tokens and passwords
    - Private keys
    """

    name = "Secret Scanner"

    # Secret patterns with severity levels
    SECRET_PATTERNS: List[Tuple[Pattern, str, str]] = [
        # AWS
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID", "critical"),
        (re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
         "Potential AWS Secret Key", "high"),

        # OpenAI
        (re.compile(r'sk-[a-zA-Z0-9]{48,}'), "OpenAI API Key", "critical"),
        (re.compile(r'sk-proj-[a-zA-Z0-9]{48,}'), "OpenAI Project API Key", "critical"),

        # Anthropic
        (re.compile(r'sk-ant-[a-zA-Z0-9-]{40,}'), "Anthropic API Key", "critical"),

        # GitHub
        (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub Personal Access Token", "critical"),
        (re.compile(r'gho_[a-zA-Z0-9]{36}'), "GitHub OAuth Token", "critical"),
        (re.compile(r'ghs_[a-zA-Z0-9]{36}'), "GitHub App Token", "critical"),
        (re.compile(r'ghr_[a-zA-Z0-9]{36}'), "GitHub Refresh Token", "critical"),

        # Google
        (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google API Key", "critical"),

        # Stripe
        (re.compile(r'sk_live_[a-zA-Z0-9]{24,}'), "Stripe Live Secret Key", "critical"),
        (re.compile(r'sk_test_[a-zA-Z0-9]{24,}'), "Stripe Test Secret Key", "high"),
        (re.compile(r'pk_live_[a-zA-Z0-9]{24,}'), "Stripe Live Publishable Key", "medium"),

        # Generic patterns
        (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
         "Generic API Key", "high"),
        (re.compile(r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?'),
         "Generic Secret/Password", "high"),
        (re.compile(r'(?i)(token|auth[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
         "Generic Token", "high"),

        # Private keys
        (re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
         "Private Key Header", "critical"),
        (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
         "PGP Private Key", "critical"),

        # Database connection strings
        (re.compile(r'(?i)(?:mysql|postgres|postgresql|mongodb|redis)://[^\s"\']+:[^\s"\']+@'),
         "Database Connection String with Credentials", "critical"),

        # JWT secrets
        (re.compile(r'(?i)jwt[_-]?secret\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'),
         "JWT Secret", "high"),

        # Slack
        (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
         "Slack Token", "critical"),

        # Twilio
        (re.compile(r'SK[a-f0-9]{32}'), "Twilio API Key", "critical"),

        # SendGrid
        (re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
         "SendGrid API Key", "critical"),
    ]

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml',
        '.env', '.cfg', '.conf', '.config', '.ini', '.properties',
        '.sh', '.bash', '.zsh', '.toml', '.xml', '.md', '.txt'
    }

    # Files to always skip
    SKIP_FILES = {
        'package-lock.json', 'yarn.lock', 'poetry.lock',
        'Cargo.lock', 'go.sum', 'pnpm-lock.yaml'
    }

    def __init__(
        self,
        exclude_paths: Optional[List[str]] = None,
        custom_patterns: Optional[List[Tuple[str, str, str]]] = None
    ):
        """
        Initialize the secret scanner.

        Args:
            exclude_paths: Path patterns to exclude
            custom_patterns: Additional patterns as (regex, name, severity) tuples
        """
        self.exclude_paths = set(exclude_paths or [])
        self.patterns = list(self.SECRET_PATTERNS)

        # Add custom patterns
        if custom_patterns:
            for regex_str, name, severity in custom_patterns:
                self.patterns.append((re.compile(regex_str), name, severity))

    def scan(self, path: Path) -> List[SecretScanResult]:
        """
        Scan for secrets in files.

        Args:
            path: File or directory to scan

        Returns:
            List of scan results
        """
        results = []
        files = self._find_files(path)

        for file_path in files:
            result = self._scan_file(file_path)
            if result and result.secrets:
                results.append(result)

        return results

    def _find_files(self, path: Path) -> List[Path]:
        """Find files to scan."""
        if path.is_file():
            if self._should_scan_file(path):
                return [path]
            return []

        files = []
        for file_path in path.rglob('*'):
            if not file_path.is_file():
                continue

            if not self._should_scan_file(file_path):
                continue

            # Check exclude patterns
            rel_path = str(file_path.relative_to(path))
            if any(excl in rel_path for excl in self.exclude_paths):
                continue

            files.append(file_path)

        return files

    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned."""
        # Skip known non-secret files
        if file_path.name in self.SKIP_FILES:
            return False

        # Skip hidden directories
        if any(part.startswith('.') and part not in {'.env'}
              for part in file_path.parts[:-1]):
            return False

        # Skip common non-source directories
        skip_dirs = {'node_modules', 'venv', '.venv', '__pycache__',
                    'dist', 'build', '.git'}
        if any(part in skip_dirs for part in file_path.parts):
            return False

        # Check extension
        if file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS:
            return True

        # Also scan .env files regardless of extension
        if '.env' in file_path.name:
            return True

        return False

    def _scan_file(self, file_path: Path) -> Optional[SecretScanResult]:
        """Scan a single file for secrets."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")
            return None

        secrets = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines and comments
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            # Check each pattern
            for pattern, name, severity in self.patterns:
                for match in pattern.finditer(line):
                    # Filter out false positives
                    if self._is_false_positive(line, match, file_path):
                        continue

                    secret = SecretMatch(
                        pattern_name=name,
                        line_number=line_num,
                        line_content=self._mask_secret(line, match),
                        matched_text=self._mask_match(match.group()),
                        start_col=match.start(),
                        end_col=match.end(),
                        severity=severity
                    )
                    secrets.append(secret)

        return SecretScanResult(
            source_file=str(file_path),
            secrets=secrets
        )

    def _is_false_positive(
        self,
        line: str,
        match: re.Match,
        file_path: Path
    ) -> bool:
        """
        Check if a match is likely a false positive.

        Filters out:
        - Example/placeholder values
        - Test fixtures
        - Documentation
        """
        matched_text = match.group().lower()
        line_lower = line.lower()

        # Common placeholder patterns
        placeholders = [
            'example', 'placeholder', 'your_', 'my_', 'xxx',
            'test', 'fake', 'dummy', 'sample', 'demo', '<your',
            'insert_', 'replace_', 'changeme', 'undefined'
        ]
        if any(p in matched_text for p in placeholders):
            return True

        # Check if this looks like documentation
        if '# example' in line_lower or '// example' in line_lower:
            return True

        # Check file path for test/example indicators
        path_str = str(file_path).lower()
        if any(p in path_str for p in ['test', 'example', 'fixture', 'mock', 'sample']):
            return True

        # Environment variable references (not actual values)
        if '${' in line or '$(' in line:
            if matched_text in line[match.start():match.end()+5]:
                # Check if the match is inside a variable reference
                before = line[:match.start()]
                if '${' in before[-10:] or '$(' in before[-10:]:
                    return True

        return False

    def _mask_secret(self, line: str, match: re.Match) -> str:
        """Mask the secret value in a line for safe display."""
        start = match.start()
        end = match.end()
        matched_len = end - start

        if matched_len <= 8:
            masked = '*' * matched_len
        else:
            # Show first and last 4 chars
            original = match.group()
            masked = original[:4] + '*' * (matched_len - 8) + original[-4:]

        return line[:start] + masked + line[end:]

    def _mask_match(self, text: str) -> str:
        """Mask a matched secret for display."""
        if len(text) <= 8:
            return '*' * len(text)
        return text[:4] + '*' * (len(text) - 8) + text[-4:]
