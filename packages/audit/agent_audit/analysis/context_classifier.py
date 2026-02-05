"""
File context classifier — the upstream foundation for all confidence adjustments.

This module provides deterministic file context classification for improved
false positive reduction. Different file contexts (test, fixture, infrastructure)
have dramatically different likelihoods of containing real vulnerabilities.

Design Principles:
1. Classifier only classifies, does not make decisions (decisions in confidence engine)
2. Classification is deterministic: same path always returns same classification
3. Priority order: VENDOR > TEST > FIXTURE > INFRASTRUCTURE > DOCUMENTATION > EXAMPLE > TEMPLATE > PRODUCTION

v0.8.0: Initial implementation for aggressive test code FP suppression
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class FileContext(Enum):
    """File context classification for confidence adjustment."""
    PRODUCTION = "production"           # Production source code
    TEST = "test"                       # Test files and directories
    FIXTURE = "fixture"                 # Test fixtures and mock data
    DOCUMENTATION = "documentation"     # Documentation files
    EXAMPLE = "example"                 # Example/sample code
    TEMPLATE = "template"               # Template/sample configuration
    INFRASTRUCTURE = "infrastructure"   # Dockerfile, CI, sandbox builders
    VENDOR = "vendor"                   # node_modules, third-party code


class ContextClassifier:
    """
    File context classifier — all confidence adjustments' upstream foundation.

    This classifier analyzes file paths to determine the context category,
    which is then used by the confidence engine to apply appropriate
    per-rule multipliers.

    Usage:
        classifier = ContextClassifier()
        context = classifier.classify("tests/test_auth.py")
        # Returns FileContext.TEST
    """

    # Priority order for classification (higher priority patterns checked first)
    # Format: (compiled_pattern, FileContext)

    # === VENDOR patterns (highest priority) ===
    VENDOR_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(^|/)node_modules/", re.IGNORECASE), "node_modules directory"),
        (re.compile(r"(^|/)vendor/", re.IGNORECASE), "vendor directory"),
        (re.compile(r"(^|/)third[_-]?party/", re.IGNORECASE), "third-party directory"),
        (re.compile(r"(^|/)external/", re.IGNORECASE), "external directory"),
        (re.compile(r"(^|/)deps/", re.IGNORECASE), "deps directory"),
        (re.compile(r"(^|/)lib/python\d", re.IGNORECASE), "Python stdlib"),
        (re.compile(r"(^|/)site-packages/", re.IGNORECASE), "site-packages"),
    ]

    # === TEST patterns (high priority) ===
    # Test directories - use (^|/) to match both start of path and mid-path
    TEST_PATH_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(^|/)tests?/", re.IGNORECASE), "test directory"),
        (re.compile(r"(^|/)__tests__/", re.IGNORECASE), "__tests__ directory"),
        (re.compile(r"(^|/)spec/", re.IGNORECASE), "spec directory"),
        (re.compile(r"(^|/)testing/", re.IGNORECASE), "testing directory"),
        (re.compile(r"(^|/)e2e/", re.IGNORECASE), "e2e directory"),
        (re.compile(r"(^|/)integration/", re.IGNORECASE), "integration tests"),
        (re.compile(r"(^|/)unit/", re.IGNORECASE), "unit tests"),
        # Test file naming patterns
        (re.compile(r"_test\.(py|ts|js|tsx|jsx)$", re.IGNORECASE), "test file suffix"),
        (re.compile(r"\.test\.(ts|tsx|js|jsx)$", re.IGNORECASE), ".test.* file"),
        (re.compile(r"\.spec\.(ts|tsx|js|jsx|py)$", re.IGNORECASE), ".spec.* file"),
        (re.compile(r"(^|/)test_[^/]+\.(py|ts|js)$", re.IGNORECASE), "test_ prefix file"),
        (re.compile(r"(^|/)conftest\.py$", re.IGNORECASE), "pytest conftest"),
        (re.compile(r"_spec\.(py|rb)$", re.IGNORECASE), "_spec file"),
    ]

    # === FIXTURE patterns ===
    FIXTURE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"/fixtures?/", re.IGNORECASE), "fixtures directory"),
        (re.compile(r"/mocks?/", re.IGNORECASE), "mocks directory"),
        (re.compile(r"/__mocks__/", re.IGNORECASE), "__mocks__ directory"),
        (re.compile(r"/stubs?/", re.IGNORECASE), "stubs directory"),
        (re.compile(r"/fakes?/", re.IGNORECASE), "fakes directory"),
        (re.compile(r"/testdata/", re.IGNORECASE), "testdata directory"),
        (re.compile(r"/test_?data/", re.IGNORECASE), "test data directory"),
    ]

    # === INFRASTRUCTURE patterns ===
    INFRASTRUCTURE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(^|/)Dockerfile", re.IGNORECASE), "Dockerfile"),
        (re.compile(r"(^|/)docker-compose", re.IGNORECASE), "docker-compose"),
        (re.compile(r"(^|/)\.github/", re.IGNORECASE), ".github directory"),
        (re.compile(r"(^|/)\.gitlab/", re.IGNORECASE), ".gitlab directory"),
        (re.compile(r"(^|/)\.circleci/", re.IGNORECASE), ".circleci directory"),
        (re.compile(r"(^|/)ci/", re.IGNORECASE), "ci directory"),
        (re.compile(r"(^|/)\.ci/", re.IGNORECASE), ".ci directory"),
        (re.compile(r"(^|/)Makefile$", re.IGNORECASE), "Makefile"),
        (re.compile(r"(^|/)scripts/", re.IGNORECASE), "scripts directory"),
        (re.compile(r"(^|/)deploy/", re.IGNORECASE), "deploy directory"),
        (re.compile(r"(^|/)infra/", re.IGNORECASE), "infra directory"),
        (re.compile(r"(^|/)infrastructure/", re.IGNORECASE), "infrastructure directory"),
        (re.compile(r"(^|/)terraform/", re.IGNORECASE), "terraform directory"),
        (re.compile(r"(^|/)ansible/", re.IGNORECASE), "ansible directory"),
        (re.compile(r"(^|/)k8s/", re.IGNORECASE), "k8s directory"),
        (re.compile(r"(^|/)kubernetes/", re.IGNORECASE), "kubernetes directory"),
        (re.compile(r"(^|/)helm/", re.IGNORECASE), "helm directory"),
        (re.compile(r"\.ya?ml$", re.IGNORECASE), "YAML file"),  # Lower priority
    ]

    # === DOCUMENTATION patterns ===
    DOCUMENTATION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"\.(md|rst|txt|adoc)$", re.IGNORECASE), "doc file extension"),
        (re.compile(r"/docs?/", re.IGNORECASE), "docs directory"),
        (re.compile(r"/documentation/", re.IGNORECASE), "documentation directory"),
        (re.compile(r"README", re.IGNORECASE), "README file"),
        (re.compile(r"CHANGELOG", re.IGNORECASE), "CHANGELOG file"),
        (re.compile(r"CONTRIBUTING", re.IGNORECASE), "CONTRIBUTING file"),
        (re.compile(r"LICENSE", re.IGNORECASE), "LICENSE file"),
    ]

    # === EXAMPLE patterns ===
    EXAMPLE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(^|/)examples?/", re.IGNORECASE), "examples directory"),
        (re.compile(r"(^|/)demos?/", re.IGNORECASE), "demos directory"),
        (re.compile(r"(^|/)samples?/", re.IGNORECASE), "samples directory"),
        (re.compile(r"(^|/)tutorials?/", re.IGNORECASE), "tutorials directory"),
        (re.compile(r"(^|/)quickstart/", re.IGNORECASE), "quickstart directory"),
        (re.compile(r"(^|/)playground/", re.IGNORECASE), "playground directory"),
    ]

    # === TEMPLATE patterns ===
    TEMPLATE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"\.example$", re.IGNORECASE), ".example file"),
        (re.compile(r"\.template$", re.IGNORECASE), ".template file"),
        (re.compile(r"\.sample$", re.IGNORECASE), ".sample file"),
        (re.compile(r"\.dist$", re.IGNORECASE), ".dist file"),
        (re.compile(r"\.default$", re.IGNORECASE), ".default file"),
        (re.compile(r"(^|/)templates?/", re.IGNORECASE), "templates directory"),
        (re.compile(r"(^|/)boilerplate/", re.IGNORECASE), "boilerplate directory"),
        (re.compile(r"(^|/)skeleton/", re.IGNORECASE), "skeleton directory"),
    ]

    def __init__(self) -> None:
        """Initialize the context classifier."""
        # Pre-compile the ordered pattern groups
        self._pattern_groups: List[Tuple[FileContext, List[Tuple[re.Pattern, str]]]] = [
            (FileContext.VENDOR, self.VENDOR_PATTERNS),
            (FileContext.FIXTURE, self.FIXTURE_PATTERNS),  # Check fixture before test
            (FileContext.TEST, self.TEST_PATH_PATTERNS),
            (FileContext.INFRASTRUCTURE, self.INFRASTRUCTURE_PATTERNS),
            (FileContext.DOCUMENTATION, self.DOCUMENTATION_PATTERNS),
            (FileContext.EXAMPLE, self.EXAMPLE_PATTERNS),
            (FileContext.TEMPLATE, self.TEMPLATE_PATTERNS),
        ]

    # Patterns that indicate intentionally vulnerable code (should NOT be suppressed)
    VULNERABLE_EXEMPT_PATTERNS: List[re.Pattern] = [
        re.compile(r"/vulnerable[_-]?", re.IGNORECASE),  # vulnerable_agents, vulnerable-code
        re.compile(r"/vuln[_-]?", re.IGNORECASE),        # vuln_examples
        re.compile(r"/insecure[_-]?", re.IGNORECASE),    # insecure_code
        re.compile(r"/bad[_-]?examples?/", re.IGNORECASE),  # bad_examples
    ]

    def classify(self, file_path: str) -> FileContext:
        """
        Classify a file path into a context category.

        Args:
            file_path: Path to the file (absolute or relative)

        Returns:
            FileContext enum value
        """
        # Normalize path separators
        normalized_path = file_path.replace("\\", "/")

        # v0.8.0: Exempt paths containing "vulnerable" from fixture/test suppression
        # These are intentionally vulnerable code samples for testing the scanner
        for exempt_pattern in self.VULNERABLE_EXEMPT_PATTERNS:
            if exempt_pattern.search(normalized_path):
                return FileContext.PRODUCTION

        # Check each pattern group in priority order
        for context, patterns in self._pattern_groups:
            for pattern, _ in patterns:
                if pattern.search(normalized_path):
                    return context

        # Default to production
        return FileContext.PRODUCTION

    def classify_with_reason(self, file_path: str) -> Tuple[FileContext, str]:
        """
        Classify a file path and return the reason for classification.

        Args:
            file_path: Path to the file

        Returns:
            Tuple of (FileContext, reason_string)
        """
        normalized_path = file_path.replace("\\", "/")

        for context, patterns in self._pattern_groups:
            for pattern, reason in patterns:
                if pattern.search(normalized_path):
                    return (context, reason)

        return (FileContext.PRODUCTION, "no special pattern matched")

    def is_test_context(self, file_path: str) -> bool:
        """Quick check if file is in a test-related context."""
        context = self.classify(file_path)
        return context in (FileContext.TEST, FileContext.FIXTURE)

    def is_non_production(self, file_path: str) -> bool:
        """Quick check if file is in any non-production context."""
        context = self.classify(file_path)
        return context != FileContext.PRODUCTION


# Module-level singleton for convenience
_classifier: Optional[ContextClassifier] = None


def get_classifier() -> ContextClassifier:
    """Get or create the context classifier singleton."""
    global _classifier
    if _classifier is None:
        _classifier = ContextClassifier()
    return _classifier


def classify_file_context(file_path: str) -> FileContext:
    """
    Convenience function to classify a file's context.

    This is the main API for integrating with the confidence engine.
    """
    return get_classifier().classify(file_path)


# ============================================================================
# v0.8.0: Content-Based Infrastructure Detection
# ============================================================================


class InfrastructureDetector:
    """
    Content-based infrastructure code deep detection.

    This detector analyzes both file path and content to identify sandbox/container/
    infrastructure code that is architecturally designed to run subprocess calls.
    Such code should not be flagged as security vulnerabilities.

    Design Principles:
    - Path patterns provide initial signal (low confidence)
    - Content signals stack to increase confidence
    - Requires at least 2 independent signals to classify as infrastructure
    - Does not directly exclude findings, but reduces confidence + adds annotation

    v0.8.0: Initial implementation for AGENT-001/047 false positive reduction.
    """

    # File path signals (each +0.30, only one counts)
    PATH_SIGNALS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)docker"), "docker in path"),
        (re.compile(r"(?i)container"), "container in path"),
        (re.compile(r"(?i)sandbox"), "sandbox in path"),
        (re.compile(r"(?i)runtime[_-]?init"), "runtime init in path"),
        (re.compile(r"(?i)bootstrap"), "bootstrap in path"),
        (re.compile(r"(?i)/deploy/"), "deploy directory"),
        (re.compile(r"(?i)/infra/"), "infra directory"),
        (re.compile(r"(?i)/scripts/setup"), "setup script"),
        (re.compile(r"(?i)/scripts/init"), "init script"),
        (re.compile(r"(?i)orchestrat"), "orchestration in path"),
    ]

    # File content signals (each +0.15, max +0.45)
    CONTENT_SIGNALS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)docker\s+(build|run|exec|compose|pull|push)"), "docker command"),
        (re.compile(r"(?i)container"), "container keyword"),
        (re.compile(r"(?i)sandbox"), "sandbox keyword"),
        (re.compile(r"(?i)isolation"), "isolation keyword"),
        (re.compile(r"(?i)chroot"), "chroot keyword"),
        (re.compile(r"(?i)namespace"), "namespace keyword"),
        (re.compile(r"(?i)cgroup"), "cgroup keyword"),
        (re.compile(r"(?i)seccomp"), "seccomp keyword"),
        (re.compile(r"(?i)capability"), "capability keyword"),
        (re.compile(r"(?i)apparmor"), "AppArmor keyword"),
        (re.compile(r"(?i)podman"), "podman keyword"),
        (re.compile(r"(?i)kubernetes|k8s"), "kubernetes keyword"),
        # v0.8.0: User/permission setup in sandbox context
        (re.compile(r"(?i)useradd|adduser"), "user creation"),
        (re.compile(r"(?i)sudoers?"), "sudoers config"),
        (re.compile(r"(?i)init_user|create_user|setup_user"), "user setup function"),
    ]

    # Identifier signals (class/function names, +0.15, only one counts)
    IDENTIFIER_SIGNALS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)(class|def|function)\s+\w*(sandbox|container|docker|runtime|bootstrap)\w*"), "infrastructure class/function"),
        (re.compile(r"(?i)(class|def|function)\s+\w*orchestrat\w*"), "orchestration class/function"),
        (re.compile(r"(?i)(class|def|function)\s+\w*init\w*runtime\w*"), "runtime init class/function"),
    ]

    def detect(self, file_path: str, content: str) -> Tuple[bool, float, str]:
        """
        Detect if file is infrastructure/sandbox code based on path and content.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Tuple of (is_infrastructure, confidence, reason)
            - is_infrastructure: True if confidence >= 0.50
            - confidence: Score from 0.0 to 1.0
            - reason: Description of detection signals
        """
        score = 0.0
        reasons: List[str] = []

        # Path signal (only one counts, +0.30)
        for pattern, reason in self.PATH_SIGNALS:
            if pattern.search(file_path):
                score += 0.30
                reasons.append(reason)
                break  # Only count one path signal

        # Content signals (stack up to +0.45)
        content_hits = 0
        for pattern, reason in self.CONTENT_SIGNALS:
            if pattern.search(content):
                content_hits += 1
                reasons.append(reason)
                if content_hits >= 3:
                    break  # Cap at 3 content signals
        score += min(content_hits * 0.15, 0.45)

        # Identifier signal (only one counts, +0.15)
        for pattern, reason in self.IDENTIFIER_SIGNALS:
            if pattern.search(content):
                score += 0.15
                reasons.append(reason)
                break

        is_infra = score >= 0.50
        confidence = min(score, 1.0)
        reason_str = "; ".join(reasons) if reasons else "no infrastructure signals"

        return (is_infra, confidence, reason_str)


# Module-level singleton for InfrastructureDetector
_infra_detector: Optional[InfrastructureDetector] = None


def get_infrastructure_detector() -> InfrastructureDetector:
    """Get or create the infrastructure detector singleton."""
    global _infra_detector
    if _infra_detector is None:
        _infra_detector = InfrastructureDetector()
    return _infra_detector


def detect_infrastructure_context(file_path: str, content: str) -> Tuple[bool, float, str]:
    """
    Convenience function to detect infrastructure context.

    Returns:
        Tuple of (is_infrastructure, confidence, reason)
    """
    return get_infrastructure_detector().detect(file_path, content)
