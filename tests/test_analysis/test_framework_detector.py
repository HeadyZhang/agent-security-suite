"""Tests for framework detector."""

import pytest
from agent_audit.analysis.framework_detector import (
    analyze_framework_context,
    is_credential_schema_definition,
    is_framework_internal_path,
    get_framework_confidence_multiplier,
    FrameworkContext,
)


class TestSchemaDefinitionDetection:
    """Test Pydantic schema definition detection."""

    @pytest.mark.parametrize("line,expected", [
        # Should detect as schema
        ("api_key: Optional[str] = Field(default=None)", True),
        ("secret: SecretStr = Field(...)", True),
        ("api_key: str = Field(description='API key')", True),
        ("password: Optional[str] = None", True),
        ("token: str = None", True),
        ("openai_key: str = Field(default=None)", True),
        ("api_secret: Optional[str] = Field()", True),
        # Should NOT detect as schema
        ("api_key = 'sk-1234567890abcdef'", False),
        ("secret = get_secret()", False),
        ("password = os.environ['PASSWORD']", False),
        ("token = 'hardcoded_value'", False),
        ("# api_key: str", False),  # Comment
    ])
    def test_schema_definition_detection(self, line: str, expected: bool):
        """Test that schema definitions are correctly identified."""
        assert is_credential_schema_definition(line) == expected


class TestFrameworkInternalPaths:
    """Test framework internal path detection."""

    @pytest.mark.parametrize("path,expected_internal,expected_framework", [
        # CrewAI paths
        ("lib/crewai/utilities/config.py", True, "crewai"),
        ("crewai/tools/base.py", True, "crewai"),
        ("crewai/agents/cache.py", True, "crewai"),
        ("site-packages/crewai/memory/memory.py", True, "crewai"),
        # LangChain paths
        ("langchain_core/tools/base.py", True, "langchain"),
        ("langchain/agents/agent.py", True, "langchain"),
        ("site-packages/langchain/memory/chat.py", True, "langchain"),
        # AutoGen paths
        ("autogen/agentchat/agent.py", True, "autogen"),
        ("autogen/oai/client.py", True, "autogen"),
        # NOT framework internal
        ("my_project/tools/custom_tool.py", False, ""),
        ("src/agents/my_agent.py", False, ""),
        ("app/models/config.py", False, ""),
    ])
    def test_framework_internal_paths(
        self, path: str, expected_internal: bool, expected_framework: str
    ):
        """Test that framework internal paths are correctly identified."""
        is_internal, framework = is_framework_internal_path(path)
        assert is_internal == expected_internal
        assert framework == expected_framework


class TestFrameworkContextAnalysis:
    """Test full framework context analysis."""

    def test_crewai_internal_path(self):
        """CrewAI internal paths should be detected."""
        result = analyze_framework_context(
            file_path="lib/crewai/utilities/config.py",
            content="",
            line=10,
            raw_line="api_key: str"
        )
        assert result.is_framework_internal is True
        assert result.framework_name == 'crewai'
        assert result.pattern_type == 'internal_path'

    def test_pydantic_field_definition(self):
        """Pydantic Field definitions should be detected."""
        result = analyze_framework_context(
            file_path="my_project/models.py",
            content="class Config(BaseModel):\n    api_key: str = Field(...)",
            line=2,
            raw_line="api_key: str = Field(default=None, description='API key')"
        )
        assert result.is_framework_internal is True
        assert result.pattern_type == 'config_schema'

    def test_pydantic_secretstr(self):
        """SecretStr type should be detected."""
        result = analyze_framework_context(
            file_path="config.py",
            content="",
            line=5,
            raw_line="password: SecretStr"
        )
        assert result.is_framework_internal is True
        assert result.reason == 'Pydantic SecretStr type'

    def test_regular_code_not_flagged(self):
        """Regular code should not be flagged as framework internal."""
        result = analyze_framework_context(
            file_path="my_project/main.py",
            content="def main():\n    api_key = get_key()",
            line=2,
            raw_line="api_key = 'sk-real-key-12345'"
        )
        assert result.is_framework_internal is False

    def test_langchain_base_class(self):
        """LangChain base class context should be detected."""
        content = '''
from langchain.tools import BaseTool

class MyTool(BaseTool):
    name = "my_tool"

    def _run(self, query: str) -> str:
        return query
'''
        result = analyze_framework_context(
            file_path="my_tools.py",
            content=content,
            line=5,
            raw_line='name = "my_tool"'
        )
        assert result.is_framework_internal is True
        assert result.pattern_type == 'framework_class'

    def test_pydantic_basemodel(self):
        """Pydantic BaseModel context should be detected."""
        content = '''
from pydantic import BaseModel

class Config(BaseModel):
    name: str = "config"
'''
        result = analyze_framework_context(
            file_path="config.py",
            content=content,
            line=5,
            raw_line='name: str = "config"'
        )
        assert result.is_framework_internal is True
        assert 'BaseModel' in result.reason

    def test_pydantic_basesettings(self):
        """Pydantic BaseSettings context should be detected."""
        content = '''
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    secret_key: str
'''
        result = analyze_framework_context(
            file_path="settings.py",
            content=content,
            line=5,
            raw_line="secret_key: str"
        )
        assert result.is_framework_internal is True

    def test_type_annotation_only(self):
        """Type annotation without value should be detected."""
        result = analyze_framework_context(
            file_path="models.py",
            content="class Model:\n    api_key: str",
            line=2,
            raw_line="    api_key: Optional[str]"
        )
        assert result.is_framework_internal is True
        assert result.pattern_type == 'config_schema'


class TestConfidenceMultiplier:
    """Test confidence multiplier calculation."""

    def test_schema_definition_multiplier(self):
        """Schema definitions should have very low multiplier."""
        ctx = FrameworkContext(
            is_framework_internal=True,
            framework_name='pydantic',
            pattern_type='config_schema',
            confidence=0.95,
            reason='Pydantic Field definition'
        )
        multiplier = get_framework_confidence_multiplier(ctx)
        assert multiplier == 0.05

    def test_internal_path_multiplier(self):
        """Internal paths should have low multiplier."""
        ctx = FrameworkContext(
            is_framework_internal=True,
            framework_name='crewai',
            pattern_type='internal_path',
            confidence=0.85,
            reason='Framework internal path'
        )
        multiplier = get_framework_confidence_multiplier(ctx)
        assert multiplier == 0.15

    def test_framework_class_multiplier(self):
        """Framework class context should have moderate multiplier."""
        ctx = FrameworkContext(
            is_framework_internal=True,
            framework_name='langchain',
            pattern_type='framework_class',
            confidence=0.85,
            reason='LangChain BaseTool'
        )
        multiplier = get_framework_confidence_multiplier(ctx)
        assert multiplier == 0.20

    def test_non_framework_multiplier(self):
        """Non-framework context should have no multiplier effect."""
        ctx = FrameworkContext(
            is_framework_internal=False,
            framework_name='',
            pattern_type='',
            confidence=0.0,
            reason='Not framework internal'
        )
        multiplier = get_framework_confidence_multiplier(ctx)
        assert multiplier == 1.0
