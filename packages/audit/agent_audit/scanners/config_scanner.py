"""Configuration scanner for YAML/JSON config files."""

import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Set
from dataclasses import dataclass, field

import yaml

from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class ConfigIssue:
    """A configuration issue."""
    issue_type: str
    description: str
    key_path: str
    current_value: Any
    recommended_value: Optional[Any] = None
    severity: str = "medium"


@dataclass
class ConfigScanResult(ScanResult):
    """Result of configuration scanning."""
    issues: List[ConfigIssue] = field(default_factory=list)
    config_data: Dict[str, Any] = field(default_factory=dict)


class ConfigScanner(BaseScanner):
    """
    Scanner for YAML/JSON configuration files.

    Checks for:
    - Dangerous default settings
    - Overly permissive configurations
    - Security misconfigurations
    - Missing security settings
    """

    name = "Config Scanner"

    # Configuration patterns to check
    DANGEROUS_PATTERNS: Dict[str, Dict[str, Any]] = {
        # Debug/development settings that shouldn't be in production
        'debug': {
            'dangerous_values': [True, 'true', 'True', '1', 'yes'],
            'severity': 'high',
            'description': 'Debug mode should be disabled in production'
        },
        'DEBUG': {
            'dangerous_values': [True, 'true', 'True', '1', 'yes'],
            'severity': 'high',
            'description': 'Debug mode should be disabled in production'
        },

        # SSL/TLS verification
        'verify_ssl': {
            'dangerous_values': [False, 'false', 'False', '0', 'no'],
            'severity': 'critical',
            'description': 'SSL verification should not be disabled'
        },
        'ssl_verify': {
            'dangerous_values': [False, 'false', 'False', '0', 'no'],
            'severity': 'critical',
            'description': 'SSL verification should not be disabled'
        },
        'insecure': {
            'dangerous_values': [True, 'true', 'True', '1', 'yes'],
            'severity': 'critical',
            'description': 'Insecure mode should not be enabled'
        },

        # Authentication/authorization
        'allow_anonymous': {
            'dangerous_values': [True, 'true', 'True'],
            'severity': 'high',
            'description': 'Anonymous access should be disabled'
        },
        'auth_required': {
            'dangerous_values': [False, 'false', 'False'],
            'severity': 'high',
            'description': 'Authentication should be required'
        },
        'require_authentication': {
            'dangerous_values': [False, 'false', 'False'],
            'severity': 'high',
            'description': 'Authentication should be required'
        },

        # CORS
        'cors_allow_all': {
            'dangerous_values': [True, 'true', 'True'],
            'severity': 'medium',
            'description': 'CORS should not allow all origins'
        },
        'allowed_origins': {
            'dangerous_values': ['*'],
            'severity': 'medium',
            'description': 'CORS should specify allowed origins'
        },

        # Admin/root access
        'admin_enabled': {
            'dangerous_values': [True, 'true', 'True'],
            'severity': 'medium',
            'description': 'Admin interface should be carefully controlled'
        },

        # Sandbox/security modes
        'sandbox': {
            'dangerous_values': [False, 'false', 'False', 'disabled'],
            'severity': 'high',
            'description': 'Sandbox mode should be enabled'
        },
        'safe_mode': {
            'dangerous_values': [False, 'false', 'False', 'disabled'],
            'severity': 'high',
            'description': 'Safe mode should be enabled'
        },
    }

    # Required security settings (should be present)
    REQUIRED_SETTINGS = {
        'rate_limit': 'Rate limiting should be configured',
        'max_requests': 'Request limits should be set',
        'timeout': 'Timeouts should be configured',
        'log_level': 'Logging should be configured',
    }

    def __init__(
        self,
        exclude_paths: Optional[List[str]] = None,
        config_filenames: Optional[List[str]] = None
    ):
        """
        Initialize the config scanner.

        Args:
            exclude_paths: Path patterns to exclude
            config_filenames: Specific config file names to look for
        """
        self.exclude_paths = set(exclude_paths or [])
        self.config_filenames = set(config_filenames or [
            'config.yaml', 'config.yml', 'config.json',
            'settings.yaml', 'settings.yml', 'settings.json',
            'app.yaml', 'app.yml', 'app.json',
            '.env.yaml', '.env.json',
            'agent.yaml', 'agent.yml', 'agent.json',
        ])

    def scan(self, path: Path) -> List[ConfigScanResult]:
        """
        Scan for configuration issues.

        Args:
            path: File or directory to scan

        Returns:
            List of scan results
        """
        results = []
        config_files = self._find_config_files(path)

        for config_file in config_files:
            result = self._scan_config_file(config_file)
            if result:
                results.append(result)

        return results

    def _find_config_files(self, path: Path) -> List[Path]:
        """Find configuration files to scan."""
        if path.is_file():
            if self._is_config_file(path):
                return [path]
            return []

        config_files = []

        # Look for known config file names
        for filename in self.config_filenames:
            config_path = path / filename
            if config_path.exists():
                config_files.append(config_path)

        # Also scan for config files in subdirectories
        for yaml_file in path.rglob('*.yaml'):
            if self._is_config_file(yaml_file):
                config_files.append(yaml_file)

        for yml_file in path.rglob('*.yml'):
            if self._is_config_file(yml_file):
                config_files.append(yml_file)

        for json_file in path.rglob('*.json'):
            if self._is_config_file(json_file):
                config_files.append(json_file)

        # Deduplicate
        return list(set(config_files))

    def _is_config_file(self, file_path: Path) -> bool:
        """Check if a file looks like a configuration file."""
        # Check filename
        if file_path.name in self.config_filenames:
            return True

        # Check for config-like names
        name_lower = file_path.name.lower()
        config_indicators = ['config', 'settings', 'agent', 'app']
        if any(ind in name_lower for ind in config_indicators):
            return True

        # Skip excluded paths
        rel_path = str(file_path)
        if any(excl in rel_path for excl in self.exclude_paths):
            return False

        # Skip common non-config directories
        skip_dirs = {'node_modules', 'venv', '.venv', '__pycache__',
                    'dist', 'build', '.git', 'test', 'tests'}
        if any(part in skip_dirs for part in file_path.parts):
            return False

        return False

    def _scan_config_file(self, file_path: Path) -> Optional[ConfigScanResult]:
        """Scan a single configuration file."""
        try:
            content = file_path.read_text(encoding='utf-8')

            if file_path.suffix == '.json':
                data = json.loads(content)
            elif file_path.suffix in {'.yaml', '.yml'}:
                data = yaml.safe_load(content)
            else:
                return None

            if not isinstance(data, dict):
                return None

            issues = self._analyze_config(data)

            return ConfigScanResult(
                source_file=str(file_path),
                issues=issues,
                config_data=data
            )

        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error in {file_path}: {e}")
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
        except Exception as e:
            logger.warning(f"Error scanning {file_path}: {e}")

        return None

    def _analyze_config(
        self,
        data: Dict[str, Any],
        prefix: str = ""
    ) -> List[ConfigIssue]:
        """Analyze configuration for issues."""
        issues = []

        # Check for dangerous patterns
        issues.extend(self._check_dangerous_patterns(data, prefix))

        # Check for missing required settings
        issues.extend(self._check_required_settings(data))

        # Recursively check nested configs
        for key, value in data.items():
            if isinstance(value, dict):
                nested_prefix = f"{prefix}.{key}" if prefix else key
                issues.extend(self._analyze_config(value, nested_prefix))

        return issues

    def _check_dangerous_patterns(
        self,
        data: Dict[str, Any],
        prefix: str = ""
    ) -> List[ConfigIssue]:
        """Check for dangerous configuration patterns."""
        issues = []

        for key, value in data.items():
            key_lower = key.lower()
            full_path = f"{prefix}.{key}" if prefix else key

            # Check against known dangerous patterns
            for pattern_key, pattern_info in self.DANGEROUS_PATTERNS.items():
                if pattern_key.lower() == key_lower or pattern_key in key_lower:
                    if value in pattern_info['dangerous_values']:
                        issue = ConfigIssue(
                            issue_type='dangerous_setting',
                            description=pattern_info['description'],
                            key_path=full_path,
                            current_value=value,
                            severity=pattern_info['severity']
                        )
                        issues.append(issue)

            # Check for permission-related settings
            if 'permission' in key_lower or 'access' in key_lower:
                if value in ['*', 'all', 'any', True]:
                    issue = ConfigIssue(
                        issue_type='overly_permissive',
                        description='Overly permissive access setting detected',
                        key_path=full_path,
                        current_value=value,
                        severity='medium'
                    )
                    issues.append(issue)

            # Check for localhost binding (should be configurable)
            if 'host' in key_lower or 'bind' in key_lower:
                if value == '0.0.0.0':
                    issue = ConfigIssue(
                        issue_type='network_exposure',
                        description='Service binds to all interfaces',
                        key_path=full_path,
                        current_value=value,
                        recommended_value='127.0.0.1',
                        severity='medium'
                    )
                    issues.append(issue)

        return issues

    def _check_required_settings(
        self,
        data: Dict[str, Any]
    ) -> List[ConfigIssue]:
        """Check for missing required security settings."""
        issues = []

        # Flatten keys for checking
        all_keys = self._flatten_keys(data)
        all_keys_lower = {k.lower() for k in all_keys}

        for setting, description in self.REQUIRED_SETTINGS.items():
            setting_lower = setting.lower()
            if not any(setting_lower in k for k in all_keys_lower):
                # Only flag as missing if this looks like a server/service config
                if self._looks_like_service_config(data):
                    issue = ConfigIssue(
                        issue_type='missing_setting',
                        description=description,
                        key_path=setting,
                        current_value=None,
                        severity='low'
                    )
                    issues.append(issue)

        return issues

    def _flatten_keys(
        self,
        data: Dict[str, Any],
        prefix: str = ""
    ) -> Set[str]:
        """Flatten nested dictionary keys."""
        keys = set()

        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            keys.add(full_key)

            if isinstance(value, dict):
                keys.update(self._flatten_keys(value, full_key))

        return keys

    def _looks_like_service_config(self, data: Dict[str, Any]) -> bool:
        """Check if config looks like a service configuration."""
        service_indicators = [
            'server', 'host', 'port', 'bind', 'listen',
            'api', 'endpoint', 'service'
        ]

        all_keys_lower = {k.lower() for k in self._flatten_keys(data)}
        return any(ind in ' '.join(all_keys_lower) for ind in service_indicators)
