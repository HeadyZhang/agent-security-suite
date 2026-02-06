---
name: Feature Request
about: Suggest a new feature or improvement for agent-audit
title: "[Feature] "
labels: enhancement
assignees: ''
---

## Feature Summary

A clear and concise description of the feature you'd like.

## Problem / Motivation

What problem does this feature solve? Why is it needed?

Example: "I'm always frustrated when [...]" or "Currently there's no way to [...]"

## Proposed Solution

Describe your proposed solution or implementation approach.

### For New Rules

If requesting a new detection rule:

- **Rule ID suggestion**: AGENT-XXX
- **OWASP Agentic category**: ASI-XX (see [OWASP Agentic Top 10](https://genai.owasp.org/))
- **Severity**: critical / high / medium / low / info
- **CWE ID**: (if applicable, see [CWE](https://cwe.mitre.org/))

**Vulnerable code example:**
```python
# Code that should trigger the rule
```

**Safe code example:**
```python
# Code that should NOT trigger the rule
```

### For CLI Improvements

If requesting CLI changes:
- Proposed command/option: `agent-audit scan --new-option`
- Example usage: `agent-audit scan . --new-option value`

### For Output Format Changes

If requesting output format changes:
- Which format: terminal / json / sarif / markdown
- Example of desired output

## Alternatives Considered

Describe any alternative solutions or features you've considered.

## Additional Context

Add any other context, mockups, or examples about the feature request here.

## Checklist

- [ ] I have searched existing issues to ensure this is not a duplicate
- [ ] I have clearly described the problem this feature would solve
- [ ] I have provided examples where applicable
- [ ] This feature aligns with agent-audit's focus on AI agent security
