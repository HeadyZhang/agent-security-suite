"""YAML rule loader for Agent Security Suite."""

import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml

logger = logging.getLogger(__name__)


class RuleLoader:
    """
    Loader for YAML rule files.

    Discovers and parses .yaml files from a rules directory.
    """

    def __init__(self, rules_dirs: Optional[List[Path]] = None):
        """
        Initialize the rule loader.

        Args:
            rules_dirs: List of directories to search for rules.
                        If None, uses default builtin rules directory.
        """
        self.rules_dirs = rules_dirs or []
        self._rules_cache: Dict[str, Dict[str, Any]] = {}

    def add_rules_directory(self, path: Path):
        """Add a directory to search for rules."""
        if path.exists() and path.is_dir():
            self.rules_dirs.append(path)

    def load_all_rules(self) -> Dict[str, Dict[str, Any]]:
        """
        Load all rules from configured directories.

        Returns:
            Dictionary mapping rule_id to rule definition.
        """
        all_rules: Dict[str, Dict[str, Any]] = {}

        for rules_dir in self.rules_dirs:
            rules = self._load_rules_from_directory(rules_dir)
            all_rules.update(rules)

        self._rules_cache = all_rules
        return all_rules

    def load_rule_file(self, file_path: Path) -> Dict[str, Dict[str, Any]]:
        """
        Load rules from a single YAML file.

        Args:
            file_path: Path to the YAML rule file

        Returns:
            Dictionary mapping rule_id to rule definition
        """
        rules: Dict[str, Dict[str, Any]] = {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'rules' not in data:
                logger.warning(f"No rules found in {file_path}")
                return rules

            for rule in data['rules']:
                rule_id = rule.get('id')
                if not rule_id:
                    logger.warning(f"Rule without id in {file_path}")
                    continue

                # Validate required fields
                if not self._validate_rule(rule, file_path):
                    continue

                # Add source file reference
                rule['_source_file'] = str(file_path)
                rules[rule_id] = rule

        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")

        return rules

    def _load_rules_from_directory(self, rules_dir: Path) -> Dict[str, Dict[str, Any]]:
        """Load all rules from a directory."""
        rules: Dict[str, Dict[str, Any]] = {}

        if not rules_dir.exists():
            logger.warning(f"Rules directory does not exist: {rules_dir}")
            return rules

        for yaml_file in rules_dir.glob("**/*.yaml"):
            file_rules = self.load_rule_file(yaml_file)
            rules.update(file_rules)

        for yml_file in rules_dir.glob("**/*.yml"):
            file_rules = self.load_rule_file(yml_file)
            rules.update(file_rules)

        return rules

    def _validate_rule(self, rule: Dict[str, Any], source_file: Path) -> bool:
        """
        Validate a rule definition has required fields.

        Returns True if valid, False otherwise.
        """
        required_fields = ['id', 'title', 'severity', 'category']

        for field in required_fields:
            if field not in rule:
                logger.warning(
                    f"Rule missing required field '{field}' in {source_file}"
                )
                return False

        # Validate severity
        valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
        if rule.get('severity', '').lower() not in valid_severities:
            logger.warning(
                f"Invalid severity '{rule.get('severity')}' in rule {rule['id']}"
            )
            return False

        return True

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a rule by its ID."""
        if not self._rules_cache:
            self.load_all_rules()
        return self._rules_cache.get(rule_id)

    def get_rules_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get all rules in a category."""
        if not self._rules_cache:
            self.load_all_rules()
        return [
            rule for rule in self._rules_cache.values()
            if rule.get('category') == category
        ]

    def get_rules_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get all rules at or above a severity level."""
        if not self._rules_cache:
            self.load_all_rules()

        severity_order = ['info', 'low', 'medium', 'high', 'critical']
        min_index = severity_order.index(severity.lower())

        return [
            rule for rule in self._rules_cache.values()
            if severity_order.index(rule.get('severity', 'info').lower()) >= min_index
        ]
