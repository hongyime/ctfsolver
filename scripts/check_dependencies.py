#!/usr/bin/env python3
"""
CTF Toolkit 依赖检查工具

检查系统是否满足 CTF Toolkit 的运行要求。
"""

import sys
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Optional

class DependencyChecker:
    """依赖检查器"""
    
    def __init__(self):
        self.results = []
        self.python_min = (3, 10)
    
    def check_python_version(self) -> Tuple[bool, str]:
        """检查 Python 版本"""
        version = sys.version_info
        if version.major >= self.python_min[0] and version.minor >= self.python_min[1]:
            return True, f"Python {version.major}.{version.minor}.{version.micro}"
        return False, f"Python {version.major}.{version.minor} (需要 {self.python_min[0]}.{self.python_min[1]}+)"
    
    def check_pip(self) -> Tuple[bool, str]:
        """检查 pip"""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return True, "pip 可用"
            return False, "pip 不可用"
        except:
            return False, "pip 检查失败"
    
    def check_git(self) -> Tuple[bool, str]:
        """检查 Git"""
        if shutil.which("git"):
            try:
                result = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=5)
                return True, result.stdout.strip()
            except:
                return True, "Git 可用"
        return False, "Git 未安装"
    
    def check_sqlite(self) -> Tuple[bool, str]:
        """检查 SQLite"""
        try:
            import sqlite3
            version = sqlite3.sqlite_version
            return True, f"SQLite {version}"
        except ImportError:
            return False, "SQLite3 模块未安装"
    
    def check_docker(self) -> Tuple[bool, str]:
        """检查 Docker"""
        if shutil.which("docker"):
            try:
                result = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
                return True, result.stdout.strip()
            except:
                return True, "Docker 可用"
        return False, "Docker 未安装（可选）"
    
    def check_virtualenv(self) -> Tuple[bool, str]:
        """检查虚拟环境"""
        venv_path = Path(__file__).parent.parent / ".venv"
        if venv_path.exists():
            return True, f"虚拟环境已存在: {venv_path}"
        return False, "虚拟环境未创建"
    
    def check_requirements(self) -> Tuple[bool, str]:
        """检查 requirements.txt"""
        req_file = Path(__file__).parent.parent / "requirements.txt"
        if req_file.exists():
            return True, "requirements.txt 存在"
        return False, "requirements.txt 不存在"
    
    def check_database(self) -> Tuple[bool, str]:
        """检查数据库"""
        db_path = Path(__file__).parent.parent / "ctf_state.db"
        if db_path.exists():
            return True, f"数据库存在: {db_path}"
        return False, "数据库未初始化"
    
    def check_disk_space(self) -> Tuple[bool, str]:
        """检查磁盘空间"""
        try:
            import psutil
            project_path = Path(__file__).parent.parent
            usage = psutil.disk_usage(str(project_path))
            free_gb = usage.free / (1024**3)
            
            if free_gb >= 10:
                return True, f"可用磁盘空间: {free_gb:.1f} GB"
            return False, f"磁盘空间不足: {free_gb:.1f} GB (需要至少 10 GB)"
        except:
            return True, "磁盘空间检查跳过"
    
    def check_memory(self) -> Tuple[bool, str]:
        """检查内存"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            total_gb = memory.total / (1024**3)
            
            if total_gb >= 4:
                return True, f"总内存: {total_gb:.1f} GB"
            return False, f"内存不足: {total_gb:.1f} GB (需要至少 4 GB)"
        except:
            return True, "内存检查跳过"
    
    def run_all_checks(self):
        """运行所有检查"""
        checks = [
            ("Python 版本", self.check_python_version),
            ("pip", self.check_pip),
            ("Git", self.check_git),
            ("SQLite", self.check_sqlite),
            ("Docker (可选)", self.check_docker),
            ("虚拟环境", self.check_virtualenv),
            ("requirements.txt", self.check_requirements),
            ("数据库", self.check_database),
            ("磁盘空间", self.check_disk_space),
            ("内存", self.check_memory),
        ]
        
        print("="*60)
        print("  CTF Toolkit 依赖检查")
        print("="*60)
        print()
        
        all_passed = True
        for name, check_func in checks:
            passed, message = check_func()
            status = "✅" if passed else "❌"
            print(f"{status} {name}: {message}")
            
            if not passed:
                all_passed = False
        
        print()
        print("="*60)
        
        if all_passed:
            print("✅ 所有检查通过！系统满足运行要求。")
        else:
            print("❌ 部分检查未通过，请先解决这些问题。")
            print()
            print("建议操作:")
            print("  1. 运行设置向导: python scripts/setup_wizard.py")
            print("  2. 查看安装指南: docs/INSTALLATION.md")
        
        print("="*60)
        
        return all_passed


def main():
    """主函数"""
    checker = DependencyChecker()
    success = checker.run_all_checks()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
