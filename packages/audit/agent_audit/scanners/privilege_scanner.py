"""
Privilege and Permission Detection Scanner (AGENT-043~048).

Cross-language scanner for detecting privilege escalation patterns,
unsandboxed execution, and permission boundary violations.

Supports: .py, .ts, .js, .sh, .md files

ASI Coverage:
- ASI-02: Tool Misuse (AGENT-045, AGENT-047)
- ASI-03: Identity & Privilege Abuse (AGENT-043, AGENT-044)
- ASI-04: Supply Chain (AGENT-048)
- ASI-05: Unexpected Code Execution (AGENT-046)
- ASI-07: Inter-Agent Communication (AGENT-048)
- ASI-08: Cascading Failures (AGENT-047)
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Sequence

from agent_audit.models.finding import (
    Finding,
    Remediation,
    confidence_to_tier,
    compute_tier_with_context,
    BLOCK_EXEMPT_RULES,
)
from agent_audit.models.risk import Severity, Category, Location
from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class PrivilegeFinding:
    """Internal finding from privilege scanner before conversion to Finding."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    owasp_id: str
    cwe_id: str
    line: int
    snippet: str
    confidence: float
    file_path: str
    remediation: str


@dataclass
class PrivilegeScanResult(ScanResult):
    """Result of privilege scanning."""
    findings: List[PrivilegeFinding] = field(default_factory=list)


class PrivilegeScanner(BaseScanner):
    """
    Scanner for privilege escalation and permission boundary issues.

    Implements rules AGENT-043 through AGENT-048:
    - AGENT-043: Daemon privilege escalation
    - AGENT-044: Sudoers NOPASSWD config
    - AGENT-045: Browser automation without sandbox
    - AGENT-046: System credential store access
    - AGENT-047: Subprocess execution without sandbox
    - AGENT-048: Extension/plugin permission boundaries
    """

    name = "Privilege Scanner"

    # File extensions to scan
    SUPPORTED_EXTENSIONS: Set[str] = {'.py', '.ts', '.js', '.sh', '.md', '.bash', '.zsh'}

    # AGENT-043: Daemon/service patterns
    DAEMON_FILENAME_PATTERNS: Set[str] = {
        'daemon', 'service', 'worker', 'background',
        'systemd', 'launchd', 'pm2', 'supervisor',
    }

    # v0.5.2: Tightened daemon detection - only true daemon registration patterns
    # Patterns that indicate ACTUAL daemon/service registration (persistent)
    DAEMON_REGISTRATION_PATTERNS: List[re.Pattern] = [
        # macOS launchd
        re.compile(r'\blaunchctl\s+(load|bootstrap|enable)', re.IGNORECASE),
        re.compile(r'LaunchDaemon', re.IGNORECASE),
        re.compile(r'com\.apple\.loginitems', re.IGNORECASE),
        # Linux systemd
        re.compile(r'\bsystemctl\s+(enable|daemon-reload)', re.IGNORECASE),
        re.compile(r'/etc/systemd/system/.*\.service', re.IGNORECASE),
        re.compile(r'update-rc\.d\s+\w+\s+(defaults|enable)', re.IGNORECASE),
        re.compile(r'chkconfig\s+--add', re.IGNORECASE),
        # Process managers (persistence)
        re.compile(r'\bpm2\s+(save|startup)', re.IGNORECASE),
        re.compile(r'\bforever\s+start', re.IGNORECASE),
        re.compile(r'\bsupervisor.*\.conf', re.IGNORECASE),
    ]

    # Patterns that are NOT daemon registration (just process management)
    NOT_DAEMON_PATTERNS: List[re.Pattern] = [
        re.compile(r'\bpkill\s+', re.IGNORECASE),        # Killing processes
        re.compile(r'\bkill\s+(-\d+\s+)?', re.IGNORECASE),  # Killing processes
        re.compile(r'\bkillall\s+', re.IGNORECASE),      # Killing processes
        re.compile(r'&\s*$', re.MULTILINE),              # Background run (not persistence)
        re.compile(r'\bnohup\s+', re.IGNORECASE),        # Background run (temporary)
        re.compile(r'\bscreen\s+-', re.IGNORECASE),      # Screen session
        re.compile(r'\btmux\s+', re.IGNORECASE),         # Tmux session
        re.compile(r'\bbg\s*$', re.IGNORECASE),          # Background job
        re.compile(r'\blaunchctl\s+(unload|stop|remove)', re.IGNORECASE),  # Stopping service
        re.compile(r'\bsystemctl\s+(stop|disable|restart|reload)', re.IGNORECASE),  # Managing service
        re.compile(r'\bpm2\s+(stop|delete|restart|reload)', re.IGNORECASE),  # Managing pm2
    ]

    # Legacy pattern list for backwards compatibility (not used in v0.5.2+)
    DAEMON_COMMAND_PATTERNS: List[re.Pattern] = DAEMON_REGISTRATION_PATTERNS

    # AGENT-044: Sudoers/NOPASSWD patterns
    SUDOERS_PATTERNS: List[re.Pattern] = [
        re.compile(r'NOPASSWD\s*:', re.IGNORECASE),
        re.compile(r'visudo', re.IGNORECASE),
        re.compile(r'/etc/sudoers', re.IGNORECASE),
        re.compile(r'ALL=\s*\(ALL\)\s*ALL', re.IGNORECASE),
        re.compile(r'%\w+\s+ALL=', re.IGNORECASE),  # Group sudo access
    ]

    # AGENT-045: Browser automation patterns
    BROWSER_AUTOMATION_IMPORTS: Set[str] = {
        'puppeteer', 'playwright', 'selenium',
        'chrome-remote-interface', 'chromedp',
        'webdriver', 'pyppeteer',
    }

    BROWSER_DANGEROUS_PATTERNS: List[re.Pattern] = [
        re.compile(r'page\.evaluate\s*\(', re.IGNORECASE),
        re.compile(r'addScriptTag\s*\(', re.IGNORECASE),
        re.compile(r'exposeFunction\s*\(', re.IGNORECASE),
        re.compile(r'ws://.*devtools', re.IGNORECASE),
        re.compile(r'--no-sandbox', re.IGNORECASE),
        re.compile(r'--disable-web-security', re.IGNORECASE),
        re.compile(r'setBypassCSP\s*\(\s*true', re.IGNORECASE),
    ]

    BROWSER_READONLY_PATTERNS: Set[str] = {
        'screenshot', 'pdf', 'title', 'url', 'content', 'textContent',
    }

    # AGENT-046: Credential store access patterns
    CREDENTIAL_STORE_PATTERNS: List[tuple] = [
        # macOS Keychain (command line and in strings/arrays)
        (re.compile(r'security\s+find-generic-password', re.IGNORECASE), 'macOS Keychain', 0.85),
        (re.compile(r'security\s+find-internet-password', re.IGNORECASE), 'macOS Keychain', 0.85),
        (re.compile(r"'security'.*'find-generic-password'", re.IGNORECASE), 'macOS Keychain', 0.85),
        (re.compile(r'"security".*"find-generic-password"', re.IGNORECASE), 'macOS Keychain', 0.85),
        (re.compile(r'find-generic-password', re.IGNORECASE), 'macOS Keychain', 0.80),
        (re.compile(r'SecItemCopyMatching', re.IGNORECASE), 'macOS Keychain API', 0.85),
        (re.compile(r'kSecClass', re.IGNORECASE), 'macOS Keychain API', 0.80),
        # Linux credential stores
        (re.compile(r'gnome-keyring', re.IGNORECASE), 'GNOME Keyring', 0.80),
        (re.compile(r'secret-tool\s+lookup', re.IGNORECASE), 'Secret Service API', 0.80),
        (re.compile(r'pass\s+show', re.IGNORECASE), 'pass password store', 0.80),
        # Password managers
        (re.compile(r'rbw\s+get', re.IGNORECASE), 'Bitwarden CLI', 0.75),
        (re.compile(r'op\s+(item\s+)?get', re.IGNORECASE), '1Password CLI', 0.75),
        (re.compile(r'lpass\s+show', re.IGNORECASE), 'LastPass CLI', 0.75),
        # Windows
        (re.compile(r'CredRead', re.IGNORECASE), 'Windows Credential Manager', 0.85),
        (re.compile(r'Get-StoredCredential', re.IGNORECASE), 'Windows Credential Manager', 0.85),
        # Node.js keychain libraries
        (re.compile(r'keytar\.(get|set)Password', re.IGNORECASE), 'Node keytar library', 0.80),
        (re.compile(r'node-keychain', re.IGNORECASE), 'Node keychain library', 0.80),
    ]

    # AGENT-047: Subprocess patterns
    SUBPROCESS_DANGEROUS_PYTHON: List[str] = [
        'subprocess.run', 'subprocess.Popen', 'subprocess.call',
        'subprocess.check_output', 'subprocess.check_call',
        'os.system', 'os.popen', 'os.spawn',
    ]

    # AGENT-047: Actual subprocess execution patterns (not just imports)
    # v0.5.1: Fixed to only match actual function calls, not import statements
    # v0.5.1b: Removed standalone exec() patterns that match db.exec() SQL calls
    SUBPROCESS_DANGEROUS_JS: List[re.Pattern] = [
        # Actual function calls on child_process module
        re.compile(r'child_process\.(exec|spawn|execFile|fork)\s*\(', re.IGNORECASE),
        # child_process functions called with variable (dangerous - dynamic command)
        re.compile(r'(?:^|\s)(exec|execSync|spawn|spawnSync|execFile|fork)\s*\(\s*[a-z_][a-z0-9_]*\s*[,)]', re.IGNORECASE),
        # child_process functions called with string literal
        re.compile(r'(?:^|\s)(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*[\'"`]', re.IGNORECASE),
        # execa library (npm package for shell commands)
        re.compile(r'\bexeca\s*\(\s*[\'"`]', re.IGNORECASE),
        re.compile(r'\bexecaSync\s*\(\s*[\'"`]', re.IGNORECASE),
        # shelljs
        re.compile(r'shelljs\.(exec|which)\s*\(', re.IGNORECASE),
        # shell: true option indicates shell command execution
        re.compile(r'spawn\s*\([^)]*shell\s*:\s*true', re.IGNORECASE),
    ]

    # Patterns that are NOT subprocess execution (just imports/types/database)
    SUBPROCESS_IMPORT_ONLY_JS: List[re.Pattern] = [
        re.compile(r'^\s*import\s+type\s+', re.IGNORECASE),  # TypeScript type-only import
        re.compile(r'^\s*import\s+\{[^}]*\}\s+from\s+[\'"]', re.IGNORECASE),  # Regular import statement
        re.compile(r'^\s*import\s+\*\s+as\s+', re.IGNORECASE),  # Namespace import
        re.compile(r'^\s*const\s+\{[^}]*\}\s*=\s*require', re.IGNORECASE),  # Destructured require
        # Database exec patterns (not subprocess)
        re.compile(r'\bdb\.exec\s*\(', re.IGNORECASE),  # db.exec() - SQL
        re.compile(r'\bthis\.db\.exec\s*\(', re.IGNORECASE),  # this.db.exec()
        re.compile(r'\bparams\.db\.exec\s*\(', re.IGNORECASE),  # params.db.exec()
        re.compile(r'\.exec\s*\(`', re.IGNORECASE),  # .exec(` template string - usually SQL
    ]

    # Build/deploy directories (lower confidence)
    BUILD_DEPLOY_DIRS: Set[str] = {
        'scripts', 'build', 'deploy', 'ci', 'tools', 'bin',
        '.github', '.gitlab', 'devops', 'infra', 'setup',
    }

    # v0.5.2: Documentation/tutorial paths - daemon setup commands in docs
    # (e.g. "sudo systemctl enable openclaw", "launchctl bootstrap") are
    # expected setup instructions, not agent runtime code.
    # Downgrade AGENT-043 to INFO tier for these paths.
    DOCS_TUTORIAL_PATH_SEGMENTS: Set[str] = {
        'docs', 'doc', 'documentation', 'examples', 'example',
        'tutorials', 'tutorial', 'guides', 'guide', 'howto',
        'getting-started', 'quickstart',
    }

    # AGENT-047: Safe commands that are commonly used in build/deploy scripts
    # v0.5.2: Extended list based on openclaw scan analysis
    SAFE_COMMANDS: Set[str] = {
        # Package managers and build tools
        'git', 'npm', 'npx', 'node', 'pnpm', 'yarn', 'bun',
        'tsc', 'tsx', 'eslint', 'prettier', 'jest', 'vitest', 'mocha',
        'python', 'python3', 'pip', 'pip3', 'poetry', 'uv',
        'cargo', 'rustc', 'go', 'make', 'cmake',
        'docker', 'docker-compose', 'kubectl', 'terraform',
        # macOS specific (v0.5.2)
        'open',         # Open files/URLs
        'pbcopy',       # Clipboard
        'pbpaste',      # Clipboard
        'say',          # Text-to-speech
        'osascript',    # AppleScript (low risk)
        'defaults',     # macOS defaults
        'mdfind',       # Spotlight search
        'mdls',         # Spotlight metadata
        # System info commands
        'which', 'where', 'whoami', 'uname', 'hostname', 'date',
        'sleep', 'true', 'false', 'test',
        # Path/file utilities
        'readlink', 'dirname', 'basename', 'realpath', 'pwd',
        'stat', 'file', 'touch', 'chmod', 'chown',
        # Text processing
        'wc', 'head', 'tail', 'grep', 'sed', 'awk',
        'sort', 'uniq', 'tr', 'cut', 'tee', 'xargs',
        'cat', 'echo', 'printf',
        # File operations
        'find', 'ls', 'cp', 'mv', 'rm', 'mkdir', 'rmdir',
        'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2',
        # Network (read-only)
        'curl', 'wget', 'ssh', 'scp', 'rsync', 'ping', 'dig', 'nslookup',
        # Environment
        'env', 'printenv', 'export', 'source',
    }

    # AGENT-048: Extension/plugin patterns
    EXTENSION_DIR_PATTERNS: Set[str] = {
        'extensions', 'plugins', 'addons', 'modules',
        'contrib', 'third_party', 'vendor',
    }

    EXTENSION_IMPORT_PATTERNS: List[re.Pattern] = [
        # Python: from .. import x, from ...pkg import x, from ....pkg.mod import x
        re.compile(r'from\s+\.\.+', re.IGNORECASE),
        # JS/TS: require('../core'), require('../../utils')
        re.compile(r'require\s*\(\s*[\'"]\.\./', re.IGNORECASE),
        # ES6: import { x } from '../core', import x from '../../utils'
        re.compile(r'import.*from\s*[\'"]\.\./', re.IGNORECASE),
    ]

    def __init__(self, exclude_patterns: Optional[List[str]] = None):
        """Initialize the privilege scanner."""
        self.exclude_patterns = exclude_patterns or []

    def scan(self, path: Path) -> Sequence[PrivilegeScanResult]:
        """
        Scan path for privilege-related issues.

        Args:
            path: File or directory to scan

        Returns:
            List of scan results with privilege findings
        """
        results: List[PrivilegeScanResult] = []
        files_to_scan = self._find_files(path)

        for file_path in files_to_scan:
            try:
                result = self._scan_file(file_path)
                if result and result.findings:
                    results.append(result)
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")

        return results

    def scan_and_convert(self, path: Path) -> List[Finding]:
        """
        Scan and convert results to Finding objects.

        Args:
            path: File or directory to scan

        Returns:
            List of Finding objects
        """
        findings: List[Finding] = []
        scan_results = self.scan(path)

        for result in scan_results:
            for priv_finding in result.findings:
                finding = self._convert_to_finding(priv_finding)
                findings.append(finding)

        return findings

    def _find_files(self, path: Path) -> List[Path]:
        """Find files to scan."""
        if path.is_file():
            if path.suffix in self.SUPPORTED_EXTENSIONS:
                return [path]
            return []

        files: List[Path] = []
        for ext in self.SUPPORTED_EXTENSIONS:
            for file_path in path.rglob(f'*{ext}'):
                # Skip common non-source directories
                skip_dirs = {'.git', 'venv', '.venv', '__pycache__', 'dist',
                            'build', 'node_modules', '.tox', '.pytest_cache'}
                if any(part in skip_dirs for part in file_path.parts):
                    continue

                files.append(file_path)

        return files

    def _scan_file(self, file_path: Path) -> Optional[PrivilegeScanResult]:
        """Scan a single file for privilege issues."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Cannot read {file_path}: {e}")
            return None

        findings: List[PrivilegeFinding] = []
        lines = content.splitlines()
        file_str = str(file_path)

        # Determine file type
        suffix = file_path.suffix.lower()
        filename_lower = file_path.name.lower()

        # Check for daemon patterns (AGENT-043)
        daemon_findings = self._check_daemon_patterns(
            file_path, content, lines, filename_lower
        )
        findings.extend(daemon_findings)

        # Check for sudoers patterns (AGENT-044)
        sudoers_findings = self._check_sudoers_patterns(
            file_path, content, lines, suffix
        )
        findings.extend(sudoers_findings)

        # Check for browser automation (AGENT-045)
        if suffix in {'.ts', '.js', '.py'}:
            browser_findings = self._check_browser_patterns(
                file_path, content, lines
            )
            findings.extend(browser_findings)

        # Check for credential store access (AGENT-046)
        credential_findings = self._check_credential_patterns(
            file_path, content, lines
        )
        findings.extend(credential_findings)

        # Check for subprocess execution (AGENT-047)
        subprocess_findings = self._check_subprocess_patterns(
            file_path, content, lines, suffix
        )
        findings.extend(subprocess_findings)

        # Check for extension permission issues (AGENT-048)
        extension_findings = self._check_extension_patterns(
            file_path, content, lines
        )
        findings.extend(extension_findings)

        if findings:
            return PrivilegeScanResult(
                source_file=file_str,
                findings=findings
            )

        return None

    def _check_daemon_patterns(
        self,
        file_path: Path,
        content: str,
        lines: List[str],
        filename_lower: str
    ) -> List[PrivilegeFinding]:
        """Check for AGENT-043: Daemon privilege escalation.

        v0.5.2: Tightened detection - only true daemon registration patterns.
        Process management operations (pkill, kill, nohup, &) are excluded.
        """
        findings: List[PrivilegeFinding] = []
        file_str = str(file_path)

        # Check if filename suggests daemon/service
        is_daemon_file = any(
            pattern in filename_lower
            for pattern in self.DAEMON_FILENAME_PATTERNS
        )

        # Find daemon registration patterns (v0.5.2: use DAEMON_REGISTRATION_PATTERNS)
        found_commands: List[tuple] = []
        for line_num, line in enumerate(lines, start=1):
            # v0.5.2: Skip lines that match NOT_DAEMON_PATTERNS first
            if any(pattern.search(line) for pattern in self.NOT_DAEMON_PATTERNS):
                continue

            # Check for true daemon registration patterns
            for pattern in self.DAEMON_REGISTRATION_PATTERNS:
                if pattern.search(line):
                    found_commands.append((line_num, line.strip()))
                    break

        if found_commands:
            # v0.5.2: Downgrade docs/tutorial paths - daemon setup commands in
            # docs (e.g. "sudo systemctl enable", "launchctl bootstrap") are
            # expected installation instructions, not agent runtime code.
            is_docs_path = any(
                part.lower() in self.DOCS_TUTORIAL_PATH_SEGMENTS
                for part in file_path.parts
            )
            if is_docs_path:
                confidence = 0.35  # INFO tier - don't count toward BLOCK+WARN
            elif is_daemon_file and found_commands:
                confidence = 0.85
            elif found_commands:
                confidence = 0.80
            else:
                confidence = 0.40

            # Use first occurrence for location
            line_num, snippet = found_commands[0]
            daemon_severity = Severity.INFO if is_docs_path else Severity.HIGH

            findings.append(PrivilegeFinding(
                rule_id="AGENT-043",
                title="Daemon Privilege Escalation",
                description=(
                    "Agent registers as system daemon/service, gaining persistent elevated "
                    "privileges. Daemon processes often run with elevated permissions "
                    "and can survive user logout."
                ),
                severity=daemon_severity,
                category=Category.IDENTITY_PRIVILEGE_ABUSE,
                owasp_id="ASI-03",
                cwe_id="CWE-250",
                line=line_num,
                snippet=snippet,
                confidence=confidence,
                file_path=file_str,
                remediation=(
                    "Run agents with minimal required privileges using dedicated "
                    "service accounts. Implement proper privilege separation."
                )
            ))

        elif is_daemon_file:
            # Filename suggests daemon but no substantive content
            findings.append(PrivilegeFinding(
                rule_id="AGENT-043",
                title="Daemon Privilege Escalation",
                description=(
                    "File appears to be related to daemon/service functionality. "
                    "Review for potential privilege escalation."
                ),
                severity=Severity.INFO,
                category=Category.IDENTITY_PRIVILEGE_ABUSE,
                owasp_id="ASI-03",
                cwe_id="CWE-250",
                line=1,
                snippet=file_path.name,
                confidence=0.40,
                file_path=file_str,
                remediation="Review daemon configuration for proper privilege separation."
            ))

        return findings

    def _check_sudoers_patterns(
        self,
        file_path: Path,
        content: str,
        lines: List[str],
        suffix: str
    ) -> List[PrivilegeFinding]:
        """Check for AGENT-044: Sudoers NOPASSWD configuration."""
        findings: List[PrivilegeFinding] = []
        file_str = str(file_path)

        # Determine severity based on file type
        is_doc = suffix == '.md'
        base_severity = Severity.HIGH if not is_doc else Severity.MEDIUM

        for line_num, line in enumerate(lines, start=1):
            for pattern in self.SUDOERS_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Calculate confidence
                    # v0.8.0: Raised NOPASSWD confidence to 0.95 to ensure BLOCK tier
                    if 'NOPASSWD' in line.upper():
                        confidence = 0.95 if not is_doc else 0.80
                    elif 'ALL=(ALL)' in line.upper():
                        confidence = 0.90
                    else:
                        confidence = 0.75

                    findings.append(PrivilegeFinding(
                        rule_id="AGENT-044",
                        title="Sudoers NOPASSWD Configuration",
                        description=(
                            "Configures or guides NOPASSWD sudoers entry. This allows "
                            "password-less sudo access which can be exploited if the "
                            "agent is compromised."
                        ),
                        severity=base_severity,
                        category=Category.IDENTITY_PRIVILEGE_ABUSE,
                        owasp_id="ASI-03",
                        cwe_id="CWE-269",
                        line=line_num,
                        snippet=line.strip()[:100],
                        confidence=confidence,
                        file_path=file_str,
                        remediation=(
                            "Avoid NOPASSWD sudoers entries. Use targeted sudo rules "
                            "with specific commands instead of ALL."
                        )
                    ))
                    break  # One finding per line

        return findings

    def _check_browser_patterns(
        self,
        file_path: Path,
        content: str,
        lines: List[str]
    ) -> List[PrivilegeFinding]:
        """Check for AGENT-045: Browser automation without sandbox."""
        findings: List[PrivilegeFinding] = []
        file_str = str(file_path)

        # Check for browser automation imports/requires
        has_browser_import = any(
            lib in content.lower()
            for lib in self.BROWSER_AUTOMATION_IMPORTS
        )

        if not has_browser_import:
            return findings

        dangerous_patterns_found: List[tuple] = []
        has_no_sandbox = False
        has_readonly_only = True

        for line_num, line in enumerate(lines, start=1):
            line_lower = line.lower()

            # Check for dangerous patterns
            for pattern in self.BROWSER_DANGEROUS_PATTERNS:
                if pattern.search(line):
                    dangerous_patterns_found.append((line_num, line.strip()))
                    if '--no-sandbox' in line_lower:
                        has_no_sandbox = True
                    # Check if this is NOT a readonly operation
                    if not any(ro in line_lower for ro in self.BROWSER_READONLY_PATTERNS):
                        has_readonly_only = False

        if dangerous_patterns_found:
            # Calculate confidence
            base_confidence = 0.85 if 'page.evaluate' in content.lower() else 0.80
            if has_no_sandbox:
                base_confidence = min(1.0, base_confidence + 0.10)
            if has_readonly_only:
                base_confidence = 0.50

            line_num, snippet = dangerous_patterns_found[0]

            findings.append(PrivilegeFinding(
                rule_id="AGENT-045",
                title="Browser Automation Without Sandbox",
                description=(
                    "Browser automation without sandbox restrictions. page.evaluate() "
                    "and similar APIs can execute arbitrary JavaScript in the browser "
                    "context, potentially leading to credential theft or DOM manipulation."
                ),
                severity=Severity.HIGH,
                category=Category.TOOL_MISUSE,
                owasp_id="ASI-02",
                cwe_id="CWE-94",
                line=line_num,
                snippet=snippet[:100],
                confidence=base_confidence,
                file_path=file_str,
                remediation=(
                    "Enable browser sandbox (remove --no-sandbox flag). "
                    "Avoid page.evaluate() with untrusted input. Use browser "
                    "automation with minimal permissions."
                )
            ))

        return findings

    def _check_credential_patterns(
        self,
        file_path: Path,
        content: str,
        lines: List[str]
    ) -> List[PrivilegeFinding]:
        """Check for AGENT-046: System credential store access."""
        findings: List[PrivilegeFinding] = []
        file_str = str(file_path)

        for line_num, line in enumerate(lines, start=1):
            for pattern, store_name, base_confidence in self.CREDENTIAL_STORE_PATTERNS:
                if pattern.search(line):
                    findings.append(PrivilegeFinding(
                        rule_id="AGENT-046",
                        title="System Credential Store Access",
                        description=(
                            f"Agent accesses system credential store ({store_name}). "
                            "This grants access to sensitive credentials that may be "
                            "used for privilege escalation or lateral movement."
                        ),
                        severity=Severity.HIGH,
                        category=Category.UNEXPECTED_CODE_EXECUTION,
                        owasp_id="ASI-05",
                        cwe_id="CWE-522",
                        line=line_num,
                        snippet=line.strip()[:100],
                        confidence=base_confidence,
                        file_path=file_str,
                        remediation=(
                            "Minimize credential store access. Use dedicated secrets "
                            "management with proper access controls. Log all "
                            "credential access attempts."
                        )
                    ))
                    break  # One finding per line

        return findings

    def _check_subprocess_patterns(
        self,
        file_path: Path,
        content: str,
        lines: List[str],
        suffix: str
    ) -> List[PrivilegeFinding]:
        """Check for AGENT-047: Subprocess execution without sandbox."""
        findings: List[PrivilegeFinding] = []

        # Determine if this is a build/deploy script
        is_build_script = any(
            dir_name in file_path.parts
            for dir_name in self.BUILD_DEPLOY_DIRS
        )

        # Base severity
        base_severity = Severity.MEDIUM if is_build_script else Severity.HIGH

        if suffix == '.py':
            findings.extend(self._check_python_subprocess(
                file_path, content, lines, base_severity, is_build_script
            ))
        elif suffix in {'.ts', '.js'}:
            findings.extend(self._check_js_subprocess(
                file_path, content, lines, base_severity, is_build_script
            ))

        return findings

    def _check_python_subprocess(
        self,
        file_path: Path,
        content: str,
        lines: List[str],
        base_severity: Severity,
        is_build_script: bool
    ) -> List[PrivilegeFinding]:
        """Check Python files for subprocess patterns."""
        findings: List[PrivilegeFinding] = []
        file_str = str(file_path)

        try:
            tree = ast.parse(content, filename=file_str)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._get_call_name(node)
            if not func_name:
                continue

            if func_name not in self.SUBPROCESS_DANGEROUS_PYTHON:
                continue

            # Check for shell=True
            has_shell_true = False
            has_hardcoded_args = True
            command_name: Optional[str] = None

            for keyword in node.keywords:
                if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        has_shell_true = True

            # Check if command is hardcoded and extract command name
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.Name, ast.Attribute, ast.Subscript)):
                    has_hardcoded_args = False
                elif isinstance(first_arg, ast.JoinedStr):  # f-string
                    has_hardcoded_args = False
                elif isinstance(first_arg, ast.List) and first_arg.elts:
                    # Extract command from list like ["git", "status"]
                    first_el = first_arg.elts[0]
                    if isinstance(first_el, ast.Constant) and isinstance(first_el.value, str):
                        command_name = first_el.value.split('/')[-1]  # Handle /usr/bin/git
                elif isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    # String command like "git status"
                    command_name = first_arg.value.split()[0].split('/')[-1] if first_arg.value else None

            # Calculate confidence with stackable multipliers
            if has_shell_true:
                base_confidence = 0.85
            elif not has_hardcoded_args:
                base_confidence = 0.80
            else:
                base_confidence = 0.80  # Start at 0.80 for all

            confidence = base_confidence

            # Apply stackable confidence reductions
            # 1. Build/deploy directory: ×0.50
            if is_build_script:
                confidence *= 0.50

            # 2. Safe command: ×0.50
            if command_name and command_name in self.SAFE_COMMANDS:
                confidence *= 0.50

            # 3. Hardcoded arguments: ×0.60
            if has_hardcoded_args:
                confidence *= 0.60

            # Minimum confidence floor
            confidence = max(0.15, confidence)

            # Skip low confidence findings
            if confidence < 0.30:
                continue

            line_num = getattr(node, 'lineno', 1)
            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else func_name

            findings.append(PrivilegeFinding(
                rule_id="AGENT-047",
                title="Subprocess Execution Without Sandbox",
                description=(
                    f"Agent executes subprocess ({func_name}) without sandbox isolation. "
                    "Subprocess execution with dynamic input can lead to command injection."
                ),
                severity=base_severity,
                category=Category.TOOL_MISUSE,
                owasp_id="ASI-02",
                cwe_id="CWE-78",
                line=line_num,
                snippet=snippet[:100],
                confidence=confidence,
                file_path=file_str,
                remediation=(
                    "Avoid shell=True. Use parameterized commands with shlex.quote(). "
                    "Consider sandboxing subprocess execution with containers or "
                    "restricted shells."
                )
            ))

        return findings

    def _check_js_subprocess(
        self,
        file_path: Path,
        content: str,
        lines: List[str],
        base_severity: Severity,
        is_build_script: bool
    ) -> List[PrivilegeFinding]:
        """Check JavaScript/TypeScript files for subprocess patterns."""
        findings: List[PrivilegeFinding] = []
        file_str = str(file_path)

        for line_num, line in enumerate(lines, start=1):
            # v0.5.1: Skip import-only lines (they don't execute code)
            is_import_only = any(
                pattern.search(line) for pattern in self.SUBPROCESS_IMPORT_ONLY_JS
            )
            if is_import_only:
                continue

            for pattern in self.SUBPROCESS_DANGEROUS_JS:
                if pattern.search(line):
                    # v0.5.2: Improved command extraction - check for quoted strings
                    # Match any quoted string argument (single, double, or backtick)
                    has_hardcoded = bool(re.search(r'[\'"`][^\'"`]+[\'"`]', line))

                    # Extract command name from the first word of hardcoded string
                    command_name: Optional[str] = None
                    cmd_match = re.search(r'[\'"`]([a-zA-Z0-9_./\-]+)', line)
                    if cmd_match:
                        # Get first word (command name), handle paths
                        first_word = cmd_match.group(1).split()[0] if ' ' in cmd_match.group(1) else cmd_match.group(1)
                        command_name = first_word.split('/')[-1]

                    # Calculate confidence with stackable multipliers
                    base_confidence = 0.80
                    confidence = base_confidence

                    # 1. Build/deploy directory: ×0.50
                    if is_build_script:
                        confidence *= 0.50

                    # 2. Safe command: ×0.50
                    if command_name and command_name in self.SAFE_COMMANDS:
                        confidence *= 0.50

                    # 3. Hardcoded arguments: ×0.60
                    if has_hardcoded:
                        confidence *= 0.60

                    # Minimum confidence floor
                    confidence = max(0.15, confidence)

                    if confidence < 0.30:
                        continue

                    findings.append(PrivilegeFinding(
                        rule_id="AGENT-047",
                        title="Subprocess Execution Without Sandbox",
                        description=(
                            "Agent executes subprocess (child_process) without sandbox "
                            "isolation. Command execution with dynamic input can lead "
                            "to command injection."
                        ),
                        severity=base_severity,
                        category=Category.TOOL_MISUSE,
                        owasp_id="ASI-02",
                        cwe_id="CWE-78",
                        line=line_num,
                        snippet=line.strip()[:100],
                        confidence=confidence,
                        file_path=file_str,
                        remediation=(
                            "Use spawn() with array arguments instead of exec(). "
                            "Avoid string interpolation in commands. Consider "
                            "sandboxing with containers."
                        )
                    ))
                    break

        return findings

    def _get_extension_root(self, file_path: Path) -> Optional[Path]:
        """
        Find the extension root directory for a file.

        For a file at extensions/tlon/src/monitor/utils.ts, returns extensions/tlon/
        Returns None if the file is not in an extension directory.

        v0.5.1: Only consider top-level extension directories, not nested ones.
        E.g., `extensions/my_ext/` is an extension dir, but `src/plugins/` is not
        because it's nested inside `src/` which indicates it's core source code.
        """
        parts = file_path.parts
        for i, part in enumerate(parts):
            if part in self.EXTENSION_DIR_PATTERNS:
                # v0.5.1: Skip if the extension dir is inside a source directory
                # Common source directory names that indicate core code, not extensions
                source_dirs = {'src', 'lib', 'core', 'app', 'packages'}
                is_nested_in_source = any(p in source_dirs for p in parts[:i])

                if is_nested_in_source:
                    # This is a plugins/modules directory inside source code (e.g., src/plugins/)
                    # Not a third-party extension directory
                    continue

                # The extension root is the extension directory + the extension name
                # e.g., extensions/tlon/ or plugins/my_plugin/
                if i + 1 < len(parts):
                    return Path(*parts[:i + 2])
        return None

    def _import_crosses_extension_boundary(
        self,
        file_path: Path,
        import_path: str,
        extension_root: Path
    ) -> bool:
        """
        Check if a relative import crosses the extension boundary.

        Args:
            file_path: The source file containing the import
            import_path: The relative import path (e.g., "../targets.js", "../../core/api")
            extension_root: The extension root directory (e.g., extensions/tlon/)

        Returns:
            True if the import target is outside the extension root
        """
        # Get the directory containing the source file
        source_dir = file_path.parent

        # Count the number of ".." in the import path and extract the relative part
        # Handle various import formats:
        # - from "../targets.js"
        # - require('../core')
        # - import { x } from '../../utils'

        # Extract just the path portion from the import
        path_match = re.search(r'[\'"]([\.\/]+[^\'"]+)[\'"]', import_path)
        if not path_match:
            # Try Python-style: from .. import x
            if 'from ..' in import_path:
                # Count dots: "from .. import" = 2 dots = 1 level up
                # "from ... import" = 3 dots = 2 levels up
                dot_match = re.search(r'from\s+(\.+)', import_path)
                if dot_match:
                    num_levels = len(dot_match.group(1)) - 1  # Number of parent dirs
                    try:
                        target_dir = source_dir
                        for _ in range(num_levels):
                            target_dir = target_dir.parent
                        # Check if target is still within extension root
                        try:
                            target_dir.relative_to(extension_root)
                            return False  # Still inside extension
                        except ValueError:
                            return True  # Outside extension boundary
                    except Exception:
                        return True  # Assume violation on error
            return False  # Can't parse, don't flag

        rel_path = path_match.group(1)

        # Resolve the relative path from the source directory
        try:
            # Normalize the path: remove .js/.ts extensions for comparison
            clean_path = re.sub(r'\.(js|ts|tsx|jsx|py)$', '', rel_path)

            # Resolve against source directory
            target_path = (source_dir / clean_path).resolve()

            # Check if target is still within extension root
            # v0.5.1: Also resolve extension_root to handle symlinks (e.g., /tmp -> /private/tmp on macOS)
            ext_root_resolved = extension_root.resolve()

            try:
                target_path.relative_to(ext_root_resolved)
                return False  # Target is inside extension root
            except ValueError:
                return True  # Target is outside extension root

        except Exception:
            # On any error (permission, invalid path), assume it might be a violation
            # but only if path clearly goes beyond extension (multiple parent refs)
            parent_count = rel_path.count('..')
            # Count how deep we are in the extension
            try:
                rel_to_ext = file_path.relative_to(extension_root)
                depth = len(rel_to_ext.parts) - 1  # -1 for the filename itself
                return parent_count > depth
            except ValueError:
                return True

    def _check_extension_patterns(
        self,
        file_path: Path,
        content: str,
        lines: List[str]
    ) -> List[PrivilegeFinding]:
        """Check for AGENT-048: Extension/plugin permission boundaries."""
        findings: List[PrivilegeFinding] = []
        file_str = str(file_path)

        # Find the extension root for this file
        extension_root = self._get_extension_root(file_path)

        if extension_root is None:
            return findings  # Not in an extension directory

        # Check for imports from parent directories that cross the extension boundary
        for line_num, line in enumerate(lines, start=1):
            for pattern in self.EXTENSION_IMPORT_PATTERNS:
                if pattern.search(line):
                    # Check if this import actually crosses the extension boundary
                    if not self._import_crosses_extension_boundary(
                        file_path, line, extension_root
                    ):
                        continue  # Internal import, skip

                    # v0.5.1: Determine confidence based on import type
                    # Pure type imports (TypeScript "import type") are lower risk
                    # as they don't execute at runtime
                    stripped_line = line.strip()
                    is_type_only_import = (
                        stripped_line.startswith("import type ")
                        or "import type {" in stripped_line
                        or re.search(r"import\s+type\s+\{", stripped_line)
                    )
                    confidence = 0.50 if is_type_only_import else 0.80

                    findings.append(PrivilegeFinding(
                        rule_id="AGENT-048",
                        title="Extension Permission Boundary Violation",
                        description=(
                            "Extension/plugin directly imports from core modules without "
                            "permission boundaries. Extensions should use defined APIs "
                            "rather than direct imports to maintain security isolation."
                        ),
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN_AGENTIC,
                        owasp_id="ASI-04",
                        cwe_id="CWE-863",
                        line=line_num,
                        snippet=stripped_line[:100],
                        confidence=confidence,
                        file_path=file_str,
                        remediation=(
                            "Implement permission manifest for extensions. "
                            "Use defined extension APIs instead of direct imports. "
                            "Sandbox extension execution."
                        )
                    ))
                    break

        return findings

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract the full function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts: List[str] = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return None

    def _convert_to_finding(self, priv_finding: PrivilegeFinding) -> Finding:
        """Convert PrivilegeFinding to Finding model.

        v0.8.0: Uses compute_tier_with_context for BLOCK exemption rules.
        v0.8.0 P7: Applies context multipliers for non-exempt rules (AGENT-045, 047).
        """
        from agent_audit.analysis.context_classifier import classify_file_context
        from agent_audit.analysis.rule_context_config import get_context_multiplier

        confidence = priv_finding.confidence

        # v0.8.0 P7: Apply context multipliers for non-exempt rules
        # AGENT-045 (browser automation) in test files should be suppressed
        if priv_finding.rule_id not in BLOCK_EXEMPT_RULES:
            file_context = classify_file_context(priv_finding.file_path)
            multiplier = get_context_multiplier(priv_finding.rule_id, file_context)
            if multiplier < 1.0:
                confidence *= multiplier

        # v0.8.0: BLOCK-exempt rules (AGENT-043, 044, 046) should always BLOCK
        # regardless of file context when confidence is high enough
        if priv_finding.rule_id in BLOCK_EXEMPT_RULES:
            tier = compute_tier_with_context(
                confidence,
                "production",  # Treat as production for exempt rules
                priv_finding.rule_id
            )
        else:
            tier = confidence_to_tier(confidence)

        return Finding(
            rule_id=priv_finding.rule_id,
            title=priv_finding.title,
            description=priv_finding.description,
            severity=priv_finding.severity,
            category=priv_finding.category,
            location=Location(
                file_path=priv_finding.file_path,
                start_line=priv_finding.line,
                end_line=priv_finding.line,
                snippet=priv_finding.snippet
            ),
            cwe_id=priv_finding.cwe_id,
            owasp_id=priv_finding.owasp_id,
            confidence=confidence,  # v0.8.0 P7: Use adjusted confidence
            tier=tier,
            remediation=Remediation(
                description=priv_finding.remediation
            )
        )
