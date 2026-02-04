"""
Comprehensive test fixture covering all OWASP Agentic Top 10 (ASI-01 ~ ASI-10).
Each function is labeled with the expected ASI category and rule ID.

NOTE: This file uses mock classes/functions. Do NOT add real imports
like 'from langchain.agents import AgentExecutor' as CI has no langchain.
"""

# =============================================================================
# Mock classes for testing (no real imports needed)
# =============================================================================

def tool(func):
    """Mock @tool decorator for testing."""
    func._is_tool = True
    return func


class AgentExecutor:
    """Mock AgentExecutor for testing."""
    def __init__(self, **kwargs):
        self.config = kwargs


def initialize_agent(**kwargs):
    """Mock initialize_agent for testing."""
    return AgentExecutor(**kwargs)


def SystemMessage(content: str) -> dict:
    """Mock SystemMessage."""
    return {"role": "system", "content": content}


def HumanMessage(content: str) -> dict:
    """Mock HumanMessage."""
    return {"role": "user", "content": content}


class ConversationBufferMemory:
    """Mock ConversationBufferMemory for testing."""
    def __init__(self, **kwargs):
        self.config = kwargs


class Vectorstore:
    """Mock vectorstore for testing."""
    def add_texts(self, texts):
        pass

    def add_documents(self, docs):
        pass


# =============================================================================
# ASI-01: Agent Goal Hijack
# =============================================================================

def asi01_vulnerable_prompt_concat(user_input: str):
    """AGENT-010: f-string in system prompt"""
    system_prompt = f"You are an agent. User says: {user_input}"
    return SystemMessage(content=system_prompt)


def asi01_vulnerable_format(user_goal: str):
    """AGENT-010: .format() in system_prompt variable"""
    system_prompt = "Agent goal: {}".format(user_goal)
    return SystemMessage(content=system_prompt)


def asi01_vulnerable_fstring_direct(instructions: str):
    """AGENT-010: f-string directly in SystemMessage"""
    return SystemMessage(content=f"Instructions: {instructions}")


# =============================================================================
# ASI-02: Tool Misuse (existing AGENT-001)
# =============================================================================

@tool
def asi02_shell_tool(command: str):
    """AGENT-001: shell=True with user input"""
    import subprocess
    return subprocess.run(command, shell=True, capture_output=True)


# =============================================================================
# ASI-03: Identity & Privilege Abuse
# =============================================================================

def asi03_hardcoded_key():
    """AGENT-013: Hardcoded credential"""
    api_key = "sk-prod-hardcoded-key-12345"
    return initialize_agent(tools=[], llm=None, api_key=api_key)


def asi03_excessive_tools():
    """AGENT-014: Too many tools (>10)"""
    tools = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    return AgentExecutor(agent=None, tools=tools)


def asi03_auto_approve():
    """AGENT-014: Auto-approval mode"""
    return AgentExecutor(agent=None, tools=[], trust_all_tools=True)


# =============================================================================
# ASI-05: Unexpected Code Execution
# =============================================================================

@tool
def asi05_eval_in_tool(code: str):
    """AGENT-017: eval() inside @tool"""
    return eval(code)


@tool
def asi05_exec_in_tool(script: str):
    """AGENT-017: exec() inside @tool"""
    exec(script)
    return "executed"


# =============================================================================
# ASI-06: Memory & Context Poisoning
# =============================================================================

def asi06_unsanitized_memory(user_input: str):
    """AGENT-018: Direct user input to vector store"""
    vectorstore = Vectorstore()
    vectorstore.add_texts([user_input])


def asi06_unbounded_memory():
    """AGENT-019: ConversationBufferMemory without limit"""
    memory = ConversationBufferMemory()
    return memory


# =============================================================================
# ASI-08: Cascading Failures
# =============================================================================

def asi08_no_max_iterations():
    """AGENT-021: AgentExecutor without max_iterations"""
    return AgentExecutor(agent=None, tools=[])


# =============================================================================
# ASI-10: Rogue Agents
# =============================================================================

def asi10_no_kill_switch():
    """AGENT-024: Agent without any execution limits"""
    return AgentExecutor(agent=None, tools=[])


def asi10_no_observability():
    """AGENT-025: Agent without callbacks or logging"""
    return AgentExecutor(
        agent=None,
        tools=[],
        max_iterations=10,  # has limit but no observability
    )


# =============================================================================
# ASI-07: Insecure Inter-Agent Communication
# =============================================================================

class GroupChat:
    """Mock GroupChat for testing (autogen)."""
    def __init__(self, **kwargs):
        self.config = kwargs


class ConversableAgent:
    """Mock ConversableAgent for testing (autogen)."""
    def __init__(self, **kwargs):
        self.config = kwargs


def asi07_multi_agent_no_auth():
    """AGENT-020: GroupChat without authentication"""
    chat = GroupChat(agents=[], messages=[])
    return chat


def asi07_http_agent_comm():
    """AGENT-020: Agent communication over plain HTTP"""
    agent_url = "http://insecure-agent-server:8080/api"
    agent = ConversableAgent(name="worker", endpoint=agent_url)
    return agent


# =============================================================================
# ASI-09: Human-Agent Trust Exploitation
# =============================================================================

def asi09_opaque_output():
    """AGENT-023: AgentExecutor without transparency"""
    agent = AgentExecutor(
        agent=None,
        tools=[],
        max_iterations=10,
        max_execution_time=300,
    )
    return agent


# =============================================================================
# ASI-08: Tool without error handling
# =============================================================================

@tool
def asi08_tool_no_try_except(url: str):
    """AGENT-022: Tool calling external API without error handling"""
    import requests
    response = requests.get(url)
    return response.json()


# =============================================================================
# SAFE EXAMPLES (should NOT trigger new rule findings)
# =============================================================================

def safe_structured_prompt(user_input: str):
    """SAFE: Proper prompt separation"""
    messages = [
        SystemMessage(content="You are a helpful agent."),
        HumanMessage(content=user_input),
    ]
    return messages


def safe_bounded_agent():
    """SAFE: Agent with all protections"""
    return AgentExecutor(
        agent=None,
        tools=[],
        max_iterations=15,
        max_execution_time=300,
        verbose=True,
        callbacks=[],
        return_intermediate_steps=True,
    )


def safe_bounded_memory():
    """SAFE: Memory with window limit"""
    memory = ConversationBufferMemory(k=10)
    return memory
