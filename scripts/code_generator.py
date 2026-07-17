#!/usr/bin/env python3
"""
CTF Toolkit 代码生成辅助工具

帮助开发者快速生成工具解析器、MCP 工具函数等。
"""

import sys
from pathlib import Path
from typing import Optional

class CodeGenerator:
    """代码生成器"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
    
    def generate_parser(self, tool_name: str, output_format: str = "xml") -> str:
        """生成工具解析器代码"""
        
        parser_code = f'''"""{tool_name} 输出解析器。

由 CTF Toolkit 代码生成器自动生成。
"""

import xml.etree.ElementTree as ET
import json
import re
from typing import Dict, List, Any, Optional


def parse_{tool_name}_xml(xml_output: str) -> Dict[str, Any]:
    """
    解析 {tool_name} XML 输出。
    
    Args:
        xml_output: {tool_name} 的 XML 格式输出
        
    Returns:
        解析后的数据字典
    """
    try:
        root = ET.fromstring(xml_output)
        
        # TODO: 根据实际 {tool_name} XML 格式实现解析逻辑
        result = {{
            "tool": "{tool_name}",
            "raw_output": xml_output[:1000],
            "parsed_data": [],
        }}
        
        return result
        
    except ET.ParseError as e:
        return {{"error": f"XML 解析错误: {{str(e)}}", "raw_output": xml_output[:1000]}}


def parse_{tool_name}_jsonl(jsonl_output: str) -> List[Dict[str, Any]]:
    """
    解析 {tool_name} JSONL 输出。
    
    Args:
        jsonl_output: {tool_name} 的 JSONL 格式输出
        
    Returns:
        解析后的数据列表
    """
    results = []
    
    for line in jsonl_output.strip().split("\\n"):
        if line:
            try:
                data = json.loads(line)
                results.append(data)
            except json.JSONDecodeError:
                continue
    
    return results


def format_for_database(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    将解析的数据格式化为数据库插入格式。
    
    Args:
        parsed_data: 解析后的数据
        
    Returns:
        数据库插入格式的数据列表
    """
    # TODO: 根据实际数据结构实现格式化逻辑
    formatted = []
    
    return formatted


def generate_summary(parsed_data: Dict[str, Any]) -> str:
    """
    生成解析结果的摘要。
    
    Args:
        parsed_data: 解析后的数据
        
    Returns:
        摘要字符串
    """
    # TODO: 实现摘要生成逻辑
    return f"{{tool_name}} 解析完成"
'''
        
        return parser_code
    
    def generate_mcp_tool(self, tool_name: str, binary: str, description: str) -> str:
        """生成 MCP 工具函数代码"""
        
        mcp_code = f'''@mcp.tool()
async def run_{tool_name}(target: str, flags: str = "") -> str:
    """
    {description}
    
    Args:
        target: 目标地址（IP、域名或 URL）
        flags: {tool_name} 的命令行标志
        
    Returns:
        格式化输出结果
    """
    global db, docker_runner
    
    if docker_runner is None:
        docker_runner = DockerRunner()
    
    # 构建命令
    args = flags.split() + [target]
    
    try:
        # 执行工具
        result = await docker_runner.run_tool("{binary}", args)
        
        if result.get("error"):
            return f"执行 {tool_name} 时出错: {{result['stderr']}}"
        
        # 解析输出（如果解析器存在）
        try:
            from .parsers.{tool_name}_parser import parse_{tool_name}_xml, generate_summary
            parsed = parse_{tool_name}_xml(result["stdout"])
            summary = generate_summary(parsed)
            
            # 存储到数据库
            if db is None:
                db = await get_database()
            
            # TODO: 根据实际解析结果存储数据
            # target_id = await db.insert_target(target)
            # for item in parsed["parsed_data"]:
            #     await db.insert_service(target_id, ...)
            
            return summary
            
        except ImportError:
            # 解析器不存在，返回原始输出
            return result["stdout"]
            
    except Exception as e:
        logger.error(f"{{tool_name}} 执行失败: {{e}}")
        return f"{{tool_name}} 执行失败: {{str(e)}}"
'''
        
        return mcp_code
    
    def save_file(self, content: str, filepath: Path) -> bool:
        """保存文件"""
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content)
            return True
        except Exception as e:
            print(f"保存文件失败: {e}")
            return False
    
    def generate_all(self, tool_name: str, binary: str, description: str, output_format: str = "xml"):
        """生成所有相关代码"""
        print(f"为工具 '{tool_name}' 生成代码...")
        
        # 生成解析器
        parser_code = self.generate_parser(tool_name, output_format)
        parser_path = self.project_root / "src" / "ctf_core" / "parsers" / f"{tool_name}_parser.py"
        
        if self.save_file(parser_code, parser_path):
            print(f"✅ 解析器已生成: {parser_path}")
        else:
            print(f"❌ 解析器生成失败")
        
        # 生成 MCP 工具函数（需要手动添加到 server.py）
        mcp_code = self.generate_mcp_tool(tool_name, binary, description)
        print(f"\n✅ MCP 工具函数已生成，请手动添加到 server.py：\n")
        print(mcp_code)
        
        # 生成更新说明
        print("\n" + "="*60)
        print("下一步操作：")
        print("="*60)
        print(f"1. 在 src/ctf_core/utils/command_whitelist.py 的 ALLOWED_BINARIES 中添加 '{binary}'")
        print(f"2. 在 src/ctf_core/server.py 中添加生成的 MCP 工具函数")
        print(f"3. 根据需要修改解析器逻辑以匹配 {tool_name} 的实际输出格式")
        print(f"4. 运行测试验证: pytest tests/ -v -k '{tool_name}'")


def main():
    """主函数 - 交互式代码生成"""
    print("="*60)
    print("  CTF Toolkit 代码生成辅助工具")
    print("="*60)
    print()
    
    generator = CodeGenerator()
    
    # 获取用户输入
    tool_name = input("工具名称（如 nmap, sqlmap）: ").strip().lower()
    binary = input("二进制文件名（如 nmap, sqlmap）: ").strip().lower()
    description = input("工具描述: ").strip()
    output_format = input("输出格式（xml/json/text，默认 xml）: ").strip().lower() or "xml"
    
    print()
    generator.generate_all(tool_name, binary, description, output_format)


if __name__ == "__main__":
    main()
