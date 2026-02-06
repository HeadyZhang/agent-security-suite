---
name: False Positive / False Negative Report
about: Report a rule that triggers incorrectly (FP) or misses a real vulnerability (FN)
title: "[FP/FN] AGENT-XXX: "
labels: accuracy
assignees: ''
---

## Report Type

- [ ] **False Positive (FP)** - Rule triggered on safe/benign code
- [ ] **False Negative (FN)** - Rule missed an actual vulnerability

## Rule Information

- **Rule ID**: AGENT-XXX
- **Rule Title**: (e.g., "Tool Function Without Input Validation")
- **agent-audit version**: (run `agent-audit --version`)

## Code Sample

Provide a **minimal** code sample that demonstrates the issue:

```python
# your_code.py
# Minimal code that reproduces the FP/FN

# For FP: This code is safe but triggers AGENT-XXX
# For FN: This code is vulnerable but AGENT-XXX doesn't trigger
```

## Scan Command & Output

```bash
# Command you ran
agent-audit scan your_code.py -v

# Output (or lack thereof)
```

## Analysis

### For False Positives

**Why is this code safe?**
Explain why the flagged code should not be considered a vulnerability:
- [ ] The input is validated/sanitized elsewhere
- [ ] The code is in a test/mock context
- [ ] The pattern is a false match (explain why)
- [ ] Other: (explain)

**Expected behavior:**
- Should not report AGENT-XXX
- OR should report with lower confidence/tier

### For False Negatives

**Why is this code vulnerable?**
Explain why this code should trigger the rule:
- What attack is possible?
- What is the impact?
- Link to relevant CWE/OWASP if applicable

**Expected behavior:**
- Should report AGENT-XXX with severity: [critical/high/medium/low]

## Confidence Level

How confident are you in this assessment?

- [ ] **High** - I'm very sure this is a FP/FN
- [ ] **Medium** - I'm fairly confident but could be wrong
- [ ] **Low** - I'm unsure, seeking clarification

## Workaround

If you have a workaround, please describe it:

```python
# For FP: How you're suppressing it
# noaudit comment
# or .agent-audit.yaml ignore rule
```

## Additional Context

- Related rules that may be affected
- Links to similar issues
- Any other relevant information

## Checklist

- [ ] I have searched existing issues to ensure this is not a duplicate
- [ ] I have provided a minimal reproducible code sample
- [ ] I have included the agent-audit version
- [ ] I have explained why I believe this is a FP/FN
- [ ] I have indicated my confidence level
