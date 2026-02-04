"""Test fixture: Agent Goal Hijack vulnerabilities (ASI-01)

This file contains patterns that should trigger AGENT-010 findings.
Do NOT add real imports - use function signatures for pattern matching.
"""


def SystemMessage(content: str) -> dict:
    """Mock SystemMessage for testing."""
    return {"role": "system", "content": content}


def HumanMessage(content: str) -> dict:
    """Mock HumanMessage for testing."""
    return {"role": "user", "content": content}


# =============================================================================
# VULNERABLE PATTERNS - Should trigger AGENT-010
# =============================================================================

def create_agent_bad_1(user_input: str):
    """AGENT-010: f-string in system prompt variable"""
    system_prompt = f"You are a helpful agent. The user wants: {user_input}"
    return SystemMessage(content=system_prompt)


def create_agent_bad_2(user_goal: str):
    """AGENT-010: .format() in prompt template"""
    template = "You are an agent with goal: {}".format(user_goal)
    return SystemMessage(content=template)


def create_agent_bad_3(instructions: str):
    """AGENT-010: f-string directly in SystemMessage"""
    return SystemMessage(content=f"Follow these instructions: {instructions}")


def create_agent_bad_4(user_input: str):
    """AGENT-010: string concatenation in system_prompt"""
    system_prompt = "You are an agent. " + user_input
    return system_prompt


def create_agent_bad_5(task: str):
    """AGENT-010: f-string in agent_prompt variable"""
    agent_prompt = f"Complete this task: {task}"
    return agent_prompt


# =============================================================================
# SAFE PATTERNS - Should NOT trigger findings
# =============================================================================

def create_agent_good_1():
    """SAFE: hardcoded system prompt"""
    return SystemMessage(content="You are a helpful agent.")


def create_agent_good_2(user_input: str):
    """SAFE: structured separation of system and user messages"""
    messages = [
        SystemMessage(content="You are a helpful agent."),
        HumanMessage(content=user_input),
    ]
    return messages


def create_agent_good_3():
    """SAFE: static instructions variable"""
    instructions = "Be helpful, harmless, and honest."
    return SystemMessage(content=instructions)
