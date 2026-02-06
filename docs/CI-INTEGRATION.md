# CI/CD Integration Guide

This guide explains how to integrate agent-audit into your CI/CD pipeline across different platforms.

## Table of Contents

- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins Pipeline](#jenkins-pipeline)
- [Azure DevOps](#azure-devops)
- [CircleCI](#circleci)
- [Pre-commit Hook](#pre-commit-hook)
- [Baseline Workflow](#baseline-workflow)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

---

## GitHub Actions

### Basic Scan

```yaml
name: Agent Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install agent-audit
        run: pip install agent-audit

      - name: Run Security Scan
        run: agent-audit scan . --fail-on high
```

### Using Official GitHub Action (Recommended)

```yaml
name: Agent Security Scan

on:
  push:
    branches: [main, master]
  pull_request:

permissions:
  contents: read
  security-events: write  # Required for SARIF upload

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Agent Audit
        uses: agent-audit/agent-audit-action@v1
        with:
          path: '.'
          format: 'sarif'
          output: 'results.sarif'
          severity: 'low'
          fail-on: 'high'

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()  # Upload even if scan finds issues
        with:
          sarif_file: results.sarif
```

### With Baseline (Incremental Scanning)

Only fail on *new* findings, not existing ones:

```yaml
name: Agent Security Scan (Incremental)

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install agent-audit
        run: pip install agent-audit

      - name: Run Incremental Scan
        run: |
          agent-audit scan . \
            --baseline .agent-audit-baseline.json \
            --format sarif \
            --output results.sarif \
            --fail-on high
```

### Multiple Output Formats

```yaml
      - name: Run Security Scan
        run: |
          # Terminal output for logs
          agent-audit scan . --format terminal

          # SARIF for GitHub Security tab
          agent-audit scan . --format sarif --output results.sarif

          # JSON for downstream processing
          agent-audit scan . --format json --output results.json

          # Markdown for PR comments
          agent-audit scan . --format markdown --output results.md
```

---

## GitLab CI

### Basic Configuration

```yaml
# .gitlab-ci.yml
stages:
  - test

agent-audit:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install agent-audit
  script:
    - agent-audit scan . --fail-on high --format terminal
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

### With SAST Report Integration

```yaml
agent-audit:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install agent-audit
  script:
    - agent-audit scan . --format json --output gl-sast-report.json --fail-on high
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    when: always
```

### With Baseline

```yaml
agent-audit:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install agent-audit
  script:
    - |
      if [ -f ".agent-audit-baseline.json" ]; then
        agent-audit scan . --baseline .agent-audit-baseline.json --fail-on high
      else
        agent-audit scan . --fail-on high
      fi
  artifacts:
    paths:
      - gl-sast-report.json
    when: always
```

---

## Jenkins Pipeline

### Declarative Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    pip install agent-audit
                    agent-audit scan . \
                        --format sarif \
                        --output results.sarif \
                        --fail-on high
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.sarif', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        failure {
            echo 'Security scan found critical or high severity issues!'
        }
    }
}
```

### Scripted Pipeline with Docker

```groovy
// Jenkinsfile
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Security Scan') {
        docker.image('python:3.11-slim').inside {
            sh 'pip install agent-audit'
            sh 'agent-audit scan . --format json --output results.json --fail-on high'
        }
        archiveArtifacts artifacts: 'results.json'
    }
}
```

### With Quality Gate

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh 'pip install agent-audit'
                    def exitCode = sh(
                        script: 'agent-audit scan . --format json --output results.json --fail-on critical',
                        returnStatus: true
                    )

                    if (exitCode != 0) {
                        def results = readJSON file: 'results.json'
                        def criticalCount = results.findings.count { it.severity == 'critical' }

                        if (criticalCount > 0) {
                            error "Found ${criticalCount} critical security issues. Blocking deployment."
                        }
                    }
                }
            }
        }
    }
}
```

---

## Azure DevOps

### Basic Pipeline

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
      addToPath: true

  - script: pip install agent-audit
    displayName: 'Install agent-audit'

  - script: agent-audit scan . --format sarif --output $(Build.ArtifactStagingDirectory)/results.sarif --fail-on high
    displayName: 'Run Security Scan'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)/results.sarif'
      artifactName: 'SecurityScanResults'
    condition: always()
```

### With Baseline from Previous Build

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'

  - task: DownloadBuildArtifacts@0
    inputs:
      buildType: 'specific'
      project: '$(System.TeamProjectId)'
      pipeline: '$(System.DefinitionId)'
      buildVersionToDownload: 'latest'
      downloadType: 'single'
      artifactName: 'baseline'
      downloadPath: '$(System.DefaultWorkingDirectory)'
    continueOnError: true

  - script: |
      pip install agent-audit
      if [ -f "$(System.DefaultWorkingDirectory)/baseline/.agent-audit-baseline.json" ]; then
        agent-audit scan . --baseline $(System.DefaultWorkingDirectory)/baseline/.agent-audit-baseline.json --fail-on high
      else
        agent-audit scan . --fail-on high
      fi
    displayName: 'Run Incremental Security Scan'
```

---

## CircleCI

### Basic Configuration

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install agent-audit
          command: pip install agent-audit
      - run:
          name: Run Security Scan
          command: agent-audit scan . --format sarif --output results.sarif --fail-on high
      - store_artifacts:
          path: results.sarif
          destination: security-results

workflows:
  main:
    jobs:
      - security-scan
```

### With Orb (if available)

```yaml
version: 2.1

orbs:
  agent-audit: agent-audit/scanner@1.0

workflows:
  main:
    jobs:
      - agent-audit/scan:
          fail-on: high
          upload-sarif: true
```

---

## Pre-commit Hook

### Installation

```bash
pip install pre-commit
```

### Configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: agent-audit
        name: Agent Audit Security Scan
        entry: agent-audit scan
        args: ['--fail-on', 'high', '--format', 'terminal', '.']
        language: system
        pass_filenames: false
        always_run: true
        stages: [commit]
```

### Setup

```bash
pre-commit install
```

### Running Manually

```bash
pre-commit run agent-audit --all-files
```

### Skip Hook (When Needed)

```bash
git commit --no-verify -m "WIP: Known security issue, will fix in follow-up"
```

---

## Baseline Workflow

Baselines allow you to track and suppress existing findings while alerting on new ones.

### Initial Baseline Creation

Create a baseline of current findings:

```bash
agent-audit scan . --save-baseline .agent-audit-baseline.json
```

Commit the baseline to your repository:

```bash
git add .agent-audit-baseline.json
git commit -m "chore: add security scan baseline"
```

### Incremental Scanning

Scan for only *new* findings since the baseline:

```bash
agent-audit scan . --baseline .agent-audit-baseline.json --fail-on high
```

### Updating the Baseline

After fixing issues or accepting certain findings:

```bash
# Re-generate baseline with current findings
agent-audit scan . --save-baseline .agent-audit-baseline.json

# Commit updated baseline
git add .agent-audit-baseline.json
git commit -m "chore: update security baseline after fixes"
```

### Baseline Best Practices

1. **Store baseline in version control** - Ensures consistent results across environments
2. **Update baseline on main branch only** - Prevents PRs from modifying the baseline
3. **Review baseline changes** - Ensure no legitimate issues are being suppressed
4. **Periodic baseline refresh** - Remove fixed issues from baseline regularly

---

## Configuration Reference

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--format` | Output format: terminal, json, sarif, markdown | terminal |
| `--output` / `-o` | Output file path | stdout |
| `--severity` | Minimum severity to report: info, low, medium, high, critical | low |
| `--fail-on` | Severity that causes non-zero exit: info, low, medium, high, critical | high |
| `--baseline` | Path to baseline file for incremental scanning | - |
| `--save-baseline` | Save current findings as baseline | - |
| `--rules-dir` | Additional rules directory | - |
| `--verbose` / `-v` | Verbose output | false |
| `--quiet` / `-q` | Only show errors | false |
| `--no-color` | Disable colored output | false |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above `--fail-on` severity |
| 1 | Findings found at or above `--fail-on` severity |
| 2 | Error during scan (invalid path, config error, etc.) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENT_AUDIT_CONFIG` | Path to `.agent-audit.yaml` config file |
| `NO_COLOR` | Disable colored output when set |

---

## Troubleshooting

### "Scan found 0 files"

**Cause**: Path doesn't contain scannable files or all files are excluded.

**Fix**:
```bash
# Check what files would be scanned
agent-audit scan . --verbose

# Check .agent-audit.yaml for exclude patterns
cat .agent-audit.yaml
```

### "Rule not found: AGENT-XXX"

**Cause**: Using a custom rules directory without built-in rules.

**Fix**:
```bash
# Use built-in rules plus custom
agent-audit scan . --rules-dir ./my-rules
```

### "SARIF upload failed" (GitHub Actions)

**Cause**: Missing permissions or incorrect file path.

**Fix**:
```yaml
permissions:
  contents: read
  security-events: write  # Required!

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif  # Must match --output path
```

### "Module not found: agent_audit"

**Cause**: agent-audit not installed in the current environment.

**Fix**:
```bash
# Ensure installation in correct environment
pip install agent-audit

# Or with pipx for isolated installation
pipx install agent-audit
```

### High Memory Usage on Large Codebases

**Cause**: Scanning many files simultaneously.

**Fix**:
```bash
# Exclude unnecessary directories
agent-audit scan . --exclude "node_modules/**" --exclude "venv/**"

# Or configure in .agent-audit.yaml
echo "scan:
  exclude:
    - 'node_modules/**'
    - 'venv/**'
    - '.git/**'
" > .agent-audit.yaml
```

### False Positives

**Fix**:
```bash
# Suppress specific line with inline comment
api_key = "test-key"  # noaudit - Test key

# Or configure in .agent-audit.yaml
echo "ignore:
  - rule_id: AGENT-004
    paths:
      - 'tests/**'
    reason: 'Test fixtures'
" >> .agent-audit.yaml
```

---

## Platform-Specific Notes

### Docker

Run agent-audit in a container:

```bash
docker run --rm -v $(pwd):/workspace agent-audit/agent-audit scan /workspace --fail-on high
```

### Kubernetes (Tekton)

```yaml
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: agent-audit-scan
spec:
  steps:
    - name: scan
      image: python:3.11-slim
      script: |
        pip install agent-audit
        agent-audit scan /workspace --fail-on high
```

### GitHub Codespaces / Gitpod

Pre-configure in devcontainer:

```json
// .devcontainer/devcontainer.json
{
  "postCreateCommand": "pip install agent-audit",
  "customizations": {
    "vscode": {
      "extensions": ["agent-audit.vscode-agent-audit"]
    }
  }
}
```

---

## Support

- [GitHub Issues](https://github.com/agent-audit/agent-audit/issues)
- [Rule Reference](RULES.md)
- [API Stability](STABILITY.md)

---

*Last updated: v0.16.0*
