#!/usr/bin/env python3
"""
CTF Toolkit 交互式设置向导

这个脚本会引导你完成 CTF Toolkit 的完整设置过程。
"""

import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path
from typing import Optional

class SetupWizard:
    """交互式设置向导"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.python_version = self.check_python_version()
        self.has_docker = self.check_docker()
        self.config = {}
        
    def check_python_version(self) -> Optional[str]:
        """检查 Python 版本"""
        try:
            version = sys.version_info
            if version.major == 3 and version.minor >= 10:
                return f"{version.major}.{version.minor}.{version.micro}"
            return None
        except:
            return None
    
    def check_docker(self) -> bool:
        """检查 Docker 是否可用"""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def print_header(self, text: str):
        """打印标题"""
        print("\n" + "="*60)
        print(f"  {text}")
        print("="*60)
    
    def print_step(self, step_num: int, text: str):
        """打印步骤"""
        print(f"\n[{step_num}] {text}")
        print("-" * 40)
    
    def ask_question(self, question: str, default: str = "", options: list = None) -> str:
        """提问并获取用户输入"""
        if options:
            print(f"选项: {', '.join(options)}")
        
        if default:
            user_input = input(f"{question} [{default}]: ").strip()
            return user_input if user_input else default
        else:
            return input(f"{question}: ").strip()
    
    def run_command(self, command: str, description: str, check: bool = True) -> bool:
        """运行命令并显示进度"""
        print(f"  执行: {description}")
        print(f"  命令: {command}")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print("  ✅ 成功")
                return True
            else:
                print(f"  ❌ 失败: {result.stderr[:200]}")
                if check:
                    return False
                return True
        except subprocess.TimeoutExpired:
            print("  ❌ 超时")
            return False
        except Exception as e:
            print(f"  ❌ 错误: {str(e)}")
            return False
    
    def setup_virtual_environment(self) -> bool:
        """设置虚拟环境"""
        self.print_step(1, "设置虚拟环境")
        
        venv_path = self.project_root / ".venv"
        
        if venv_path.exists():
            use_existing = self.ask_question(
                "虚拟环境已存在，是否使用现有的？",
                default="y",
                options=["y", "n"]
            )
            if use_existing.lower() != "y":
                print("  删除现有虚拟环境...")
                shutil.rmtree(venv_path)
            else:
                print("  ✅ 使用现有虚拟环境")
                return True
        
        print("  创建虚拟环境...")
        return self.run_command(
            f"{sys.executable} -m venv .venv",
            "创建虚拟环境"
        )
    
    def install_dependencies(self) -> bool:
        """安装依赖"""
        self.print_step(2, "安装 Python 依赖")
        
        # 确定 pip 路径
        if platform.system() == "Windows":
            pip_path = self.project_root / ".venv" / "Scripts" / "pip.exe"
        else:
            pip_path = self.project_root / ".venv" / "bin" / "pip"
        
        # 升级 pip
        self.run_command(
            f'"{pip_path}" install --upgrade pip',
            "升级 pip",
            check=False
        )
        
        # 安装依赖
        return self.run_command(
            f'"{pip_path}" install -r requirements.txt',
            "安装项目依赖"
        )
    
    def initialize_database(self) -> bool:
        """初始化数据库"""
        self.print_step(3, "初始化数据库")
        
        # 使用虚拟环境的 Python
        if platform.system() == "Windows":
            python_path = self.project_root / ".venv" / "Scripts" / "python.exe"
        else:
            python_path = self.project_root / ".venv" / "bin" / "python"
        
        return self.run_command(
            f'"{python_path}" -c "from src.ctf_core.db import init_database; import asyncio; asyncio.run(init_database())"',
            "初始化 SQLite 数据库"
        )
    
    def run_tests(self) -> bool:
        """运行测试验证安装"""
        self.print_step(4, "运行测试验证")
        
        # 使用虚拟环境的 pytest
        if platform.system() == "Windows":
            pytest_path = self.project_root / ".venv" / "Scripts" / "pytest.exe"
        else:
            pytest_path = self.project_root / ".venv" / "bin" / "pytest"
        
        return self.run_command(
            f'"{pytest_path}" tests/ -v -k "test_resource_level_classification or test_cache_set_get" --tb=short',
            "运行基本测试",
            check=False
        )
    
    def configure_environment(self) -> bool:
        """配置环境变量"""
        self.print_step(5, "配置环境变量")
        
        env_file = self.project_root / ".env"
        
        if env_file.exists():
            use_existing = self.ask_question(
                ".env 文件已存在，是否使用现有配置？",
                default="y",
                options=["y", "n"]
            )
            if use_existing.lower() == "y":
                print("  ✅ 使用现有配置")
                return True
        
        # 创建配置
        config_content = """# CTF Toolkit 配置文件
# 由设置向导自动生成

# 基础配置
CTFTOOLKIT_DB_PATH=./ctf_state.db
CTFTOOLKIT_WORKSPACE=./workspace
CTFTOOLKIT_LOG_DIR=./logs

# 安全配置
CTFTOOLKIT_SECURITY_LEVEL=medium
CTFTOOLKIT_AUDIT_ENABLED=true
CTFTOOLKIT_AUDIT_RETENTION_DAYS=30

# 性能配置
CTFTOOLKIT_MAX_CONCURRENCY=5
CTFTOOLKIT_DEFAULT_CONCURRENCY=3
CTFTOOLKIT_CACHE_TTL=300
CTFTOOLKIT_CACHE_MAX_SIZE=1000

# Docker 配置
CTFTOOLKIT_DOCKER_ENABLED=""" + ("true" if self.has_docker else "false") + """
CTFTOOLKIT_DOCKER_NETWORK=bridge

# 可观测性配置
CTFTOOLKIT_TRACING_ENABLED=true
CTFTOOLKIT_METRICS_ENABLED=true
"""
        
        with open(env_file, "w") as f:
            f.write(config_content)
        
        print("  ✅ 配置文件已创建")
        return True
    
    def show_summary(self):
        """显示设置摘要"""
        self.print_header("设置完成摘要")
        
        print("""
✅ CTF Toolkit 已成功安装和配置！

接下来你可以：

1. 激活虚拟环境：
   Windows: .venv\\Scripts\\activate
   Linux/macOS: source .venv/bin/activate

2. 查看文档：
   - 快速入门: docs/GETTING_STARTED.md
   - 详细安装: docs/INSTALLATION.md
   - 配置指南: docs/CONFIGURATION.md
   - 使用示例: docs/EXAMPLES.md

3. 运行第一个扫描：
   python -c "from src.ctf_core.server import run_nmap; import asyncio; print(asyncio.run(run_nmap('127.0.0.1', '-sV')))"

4. 启动 MCP 服务器：
   python -m src.ctf_core.server

5. 运行健康检查：
   python -c "from src.ctf_core.debug.debugger import get_health_checker; import asyncio; checker = get_health_checker(); print(asyncio.run(checker.run_checks()))"

如有问题，请查看：
- FAQ: docs/FAQ.md
- GitHub Issues: https://github.com/your-org/ctftoolkit/issues
""")
    
    def run(self):
        """运行完整的设置向导"""
        self.print_header("CTF Toolkit 设置向导")
        
        # 检查前置条件
        if not self.python_version:
            print("❌ 错误: 需要 Python 3.10 或更高版本")
            print(f"   当前版本: {sys.version}")
            print("   请安装 Python 3.10+: https://www.python.org/downloads/")
            return False
        
        print(f"✅ Python 版本: {self.python_version}")
        print(f"{'✅' if self.has_docker else '⚠️'} Docker: {'可用' if self.has_docker else '不可用（可选）'}")
        
        # 运行设置步骤
        steps = [
            (self.setup_virtual_environment, "设置虚拟环境"),
            (self.install_dependencies, "安装依赖"),
            (self.initialize_database, "初始化数据库"),
            (self.run_tests, "运行测试"),
            (self.configure_environment, "配置环境"),
        ]
        
        for i, (step_func, description) in enumerate(steps, 1):
            if not step_func():
                print(f"\n❌ 步骤 {i} 失败: {description}")
                print("请检查错误信息并重试。")
                return False
        
        # 显示摘要
        self.show_summary()
        return True


def main():
    """主函数"""
    wizard = SetupWizard()
    success = wizard.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
