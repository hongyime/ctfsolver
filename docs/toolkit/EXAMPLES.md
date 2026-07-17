# CTF Toolkit 使用示例

本页面提供各种使用场景的完整代码示例，帮助你快速上手 CTF Toolkit。

## 📋 目录

- [基础示例](#基础示例)
- [网络侦察示例](#网络侦察示例)
- [Web 测试示例](#web-测试示例)
- [密码破解示例](#密码破解示例)
- [漏洞利用示例](#漏洞利用示例)
- [取证分析示例](#取证分析示例)
- [高级示例](#高级示例)

## 🔰 基础示例

### 示例 1：简单的端口扫描

```python
import asyncio
from src.ctf_core.server import run_nmap

async def simple_scan():
    """对单个目标进行基本端口扫描"""
    target = "192.168.1.1"
    result = await run_nmap(target, "-sS -p 1-1000")
    print(f"扫描 {target} 的结果:")
    print(result[:1000])  # 只显示前 1000 个字符

asyncio.run(simple_scan())
```

### 示例 2：解析扫描结果

```python
from src.ctf_core.parsers.nmap_parser import parse_nmap_xml, generate_summary

def parse_scan_result(xml_output):
    """解析 Nmap XML 输出"""
    parsed = parse_nmap_xml(xml_output)
    summary = generate_summary(parsed)
    
    print("=== 扫描摘要 ===")
    print(f"发现主机: {len(parsed['hosts'])}")
    print(f"开放端口: {summary['open_ports']}")
    print(f"服务版本: {summary['service_versions']}")
    
    # 提取详细信息
    for host in parsed['hosts']:
        print(f"\n主机: {host['ip']}")
        for port in host.get('ports', []):
            print(f"  端口 {port['port']}: {port['service']} ({port['state']})")

# 使用示例
# parse_scan_result(nmap_xml_output)
```

### 示例 3：存储扫描结果到数据库

```python
import asyncio
from src.ctf_core.db import get_database

async def store_scan_results():
    """将扫描结果存储到数据库"""
    db = await get_database()
    
    # 插入目标
    target_id = await db.insert_target(
        ip_address="192.168.1.1",
        hostname="router.local",
        os_type="Linux"
    )
    
    # 插入服务
    await db.insert_service(target_id, 80, "tcp", "http", "Apache httpd 2.4.41")
    await db.insert_service(target_id, 443, "tcp", "https", "Apache httpd 2.4.41")
    await db.insert_service(target_id, 22, "tcp", "ssh", "OpenSSH 8.2")
    
    print(f"已存储 {target_id} 号目标的扫描结果")

asyncio.run(store_scan_results())
```

## 🌐 网络侦察示例

### 示例 4：全面网络发现

```python
import asyncio
from src.ctf_core.server import run_nmap, run_masscan

async def network_discovery():
    """执行全面的网络发现"""
    network = "192.168.1.0/24"
    
    # 快速端口扫描
    print("=== 快速端口扫描 ===")
    fast_scan = await run_nmap(network, "-sn -T4")
    print(fast_scan[:500])
    
    # 详细服务扫描
    print("\n=== 详细服务扫描 ===")
    detailed_scan = await run_nmap(network, "-sV -sC -O -T4")
    print(detailed_scan[:1000])
    
    # 大规模端口扫描
    print("\n=== 全端口扫描 ===")
    masscan_result = await run_masscan(network, "-p1-65535 --rate=1000")
    print(masscan_result[:500])

asyncio.run(network_discovery())
```

### 示例 5：Web 目录枚举

```python
import asyncio
from src.ctf_core.server import run_feroxbuster

async def web_enumeration():
    """枚举 Web 目录和文件"""
    url = "http://192.168.1.100"
    
    result = await run_feroxbuster(
        url,
        "-w /usr/share/wordlists/dirb/common.txt -x php,txt,html -t 50"
    )
    
    print("=== 发现的目录和文件 ===")
    print(result)

asyncio.run(web_enumeration())
```

## 🌐 Web 测试示例

### 示例 6：SQL 注入测试

```python
import asyncio
from src.ctf_core.server import run_sqlmap

async def sql_injection_test():
    """测试 SQL 注入漏洞"""
    url = "http://192.168.1.100/vulnerable.php?id=1"
    
    # 基本检测
    result = await run_sqlmap(url, "--batch --dbs")
    print("=== 数据库列表 ===")
    print(result[:1000])
    
    # 提取表
    result = await run_sqlmap(url, "--batch -D database_name --tables")
    print("\n=== 表列表 ===")
    print(result[:1000])

asyncio.run(sql_injection_test())
```

### 示例 7：Web 漏洞扫描

```python
import asyncio
from src.ctf_core.server import run_nikto

async def web_vulnerability_scan():
    """执行 Web 漏洞扫描"""
    url = "http://192.168.1.100"
    
    result = await run_nikto(url, "-h http://192.168.1.100 -C all")
    print("=== Nikto 扫描结果 ===")
    print(result)

asyncio.run(web_vulnerability_scan())
```

## 🔑 密码破解示例

### 示例 8：暴力破解登录

```python
import asyncio
from src.ctf_core.server import run_hydra

async def brute_force_attack():
    """暴力破解 SSH 登录"""
    target = "192.168.1.100"
    
    result = await run_hydra(
        target,
        "-l admin -P /usr/share/wordlists/rockyou.txt ssh -t 4 -f"
    )
    print("=== Hydra 结果 ===")
    print(result)

asyncio.run(brute_force_attack())
```

### 示例 9：密码哈希破解

```python
import asyncio
from src.ctf_core.server import run_hashcat

async def hash_cracking():
    """破解密码哈希"""
    hash_file = "hashes.txt"
    wordlist = "/usr/share/wordlists/rockyou.txt"
    
    result = await run_hashcat(
        hash_file,
        f"-a 0 -m 0 {wordlist} --force"
    )
    print("=== Hashcat 结果 ===")
    print(result)

asyncio.run(hash_cracking())
```

## 💥 漏洞利用示例

### 示例 10：搜索漏洞利用

```python
import asyncio
from src.ctf_core.server import run_searchsploit

async def exploit_search():
    """搜索相关漏洞利用"""
    # 搜索 Apache 漏洞
    result = await run_searchsploit("Apache 2.4.49")
    print("=== 相关漏洞利用 ===")
    print(result)
    
    # 搜索 CVE
    result = await run_searchsploit("CVE-2021-41773")
    print("\n=== CVE-2021-41773 利用 ===")
    print(result)

asyncio.run(exploit_search())
```

## 🔍 取证分析示例

### 示例 11：内存分析

```python
import asyncio
from src.ctf_core.server import run_volatility

async def memory_analysis():
    """分析内存转储"""
    memory_dump = "memory.raw"
    
    # 获取进程列表
    result = await run_volatility(
        memory_dump,
        "-f memory.raw linux_pslist"
    )
    print("=== 进程列表 ===")
    print(result[:1000])
    
    # 获取网络连接
    result = await run_volatility(
        memory_dump,
        "-f memory.raw linux_netstat"
    )
    print("\n=== 网络连接 ===")
    print(result[:1000])

asyncio.run(memory_analysis())
```

### 示例 12：文件分析

```python
import asyncio
from src.ctf_core.server import run_exiftool

async def file_analysis():
    """分析文件元数据"""
    files = ["image.jpg", "document.pdf"]
    
    for file in files:
        result = await run_exiftool(file)
        print(f"\n=== {file} 的元数据 ===")
        print(result[:500])

asyncio.run(file_analysis())
```

## 🚀 高级示例

### 示例 13：自动化侦察流程

```python
import asyncio
from src.ctf_core.server import run_nmap, run_feroxbuster, run_sqlmap
from src.ctf_core.db import get_database
from src.ctf_core.utils.resource_manager import get_resource_manager

async def automated_recon(target):
    """自动化侦察流程"""
    # 初始化资源管理器
    manager = get_resource_manager()
    await manager.start_monitoring()
    
    # 初始化数据库
    db = await get_database()
    target_id = await db.insert_target(ip_address=target)
    
    print(f"=== 开始对 {target} 的侦察 ===")
    
    # 1. 端口扫描
    print("\n1. 执行端口扫描...")
    nmap_result = await run_nmap(target, "-sV -sC -oX -")
    
    # 2. 解析结果
    from src.ctf_core.parsers.nmap_parser import parse_nmap_xml
    parsed = parse_nmap_xml(nmap_result)
    
    # 3. 存储服务
    for host in parsed['hosts']:
        for port in host.get('ports', []):
            if port['state'] == 'open':
                await db.insert_service(
                    target_id,
                    port['port'],
                    port['protocol'],
                    port.get('service', ''),
                    port.get('banner', '')
                )
    
    # 4. Web 目录枚举（如果有 HTTP 服务）
    http_ports = [p for h in parsed['hosts'] for p in h.get('ports', []) 
                  if p['state'] == 'open' and p.get('service') in ['http', 'https']]
    
    if http_ports:
        print(f"\n2. 发现 {len(http_ports)} 个 Web 服务，执行目录枚举...")
        for port in http_ports[:3]:  # 限制前 3 个
            protocol = "https" if port['service'] == 'https' else "http"
            url = f"{protocol}://{target}:{port['port']}"
            await run_feroxbuster(url, "-w common.txt -t 20")
    
    # 5. 生成报告
    print("\n=== 侦察完成 ===")
    services = await db.get_services(target_id)
    print(f"发现 {len(services)} 个服务")
    
    for service in services[:10]:
        print(f"  - 端口 {service['port']}: {service['service_name']}")

# 使用示例
# asyncio.run(automated_recon("192.168.1.100"))
```

### 示例 14：使用追踪和监控

```python
import asyncio
from src.ctf_core.observability.tracing import get_tracer, SpanStatus
from src.ctf_core.debug.debugger import get_profiler

async def monitored_scan():
    """带追踪和监控的扫描"""
    tracer = get_tracer()
    profiler = get_profiler()
    
    # 开始追踪
    trace_span = tracer.start_span("automated_scan")
    tracer.set_attribute(trace_span, "target", "192.168.1.100")
    
    try:
        # 开始性能分析
        profiler.start_profiling("scan_session")
        
        # 执行扫描
        from src.ctf_core.server import run_nmap
        result = await run_nmap("192.168.1.100", "-sV -sC")
        
        # 记录事件
        tracer.add_event(trace_span, "scan_completed", {
            "output_length": len(result),
            "timestamp": asyncio.get_event_loop().time()
        })
        
        # 停止性能分析
        profile_results = profiler.stop_profiling("scan_session")
        
        # 显示性能结果
        print("=== 性能分析 ===")
        for r in profile_results[:5]:
            print(f"{r.function_name}: {r.cumulative_time:.3f}s")
        
        # 结束追踪
        tracer.end_span(trace_span, status=SpanStatus.OK)
        
        return result
        
    except Exception as e:
        tracer.end_span(trace_span, status=SpanStatus.ERROR, error=str(e))
        raise

asyncio.run(monitored_scan())
```

### 示例 15：安全审计和合规性

```python
import asyncio
from src.ctf_core.utils.audit_logger import get_audit_logger
from src.ctf_core.utils.network_isolation import NetworkIsolator, NetworkPolicy, NetworkZone

async def security_audit():
    """执行安全审计"""
    audit_logger = get_audit_logger()
    isolator = NetworkIsolator()
    
    # 配置严格的安全策略
    strict_policy = NetworkPolicy(
        zone=NetworkZone.CONTROLLED,
        allowed_targets={"192.168.1.0/24"},
        blocked_ports={22, 23, 3389},
        rate_limit_per_second=10
    )
    isolator.set_tool_policy("audit_scanner", strict_policy)
    
    # 记录所有操作
    await audit_logger.log_security_event(
        event_type="security_audit_start",
        threat_level="low",
        description="开始安全审计扫描",
        details={"target_network": "192.168.1.0/24"}
    )
    
    try:
        # 执行扫描
        from src.ctf_core.server import run_nmap
        result = await run_nmap("192.168.1.100", "-sV")
        
        # 记录成功
        await audit_logger.log_security_event(
            event_type="security_audit_complete",
            threat_level="low",
            description="安全审计完成",
            details={"output_length": len(result)}
        )
        
        # 生成审计报告
        report = await audit_logger.generate_audit_report()
        print("=== 安全审计报告 ===")
        print(f"总事件数: {report['security_events']['total']}")
        print(f"严重事件: {report['security_events']['critical']}")
        
    except Exception as e:
        await audit_logger.log_security_event(
            event_type="security_audit_error",
            threat_level="medium",
            description=f"审计过程中出错: {str(e)}",
            action_taken="logged"
        )
        raise

asyncio.run(security_audit())
```

---

## 📝 提示和最佳实践

1. **始终使用异步 API** - CTF Toolkit 设计为异步执行，使用 `async/await` 获得最佳性能
2. **合理设置并发限制** - 根据系统资源调整 `CTFTOOLKIT_MAX_CONCURRENCY`
3. **启用审计日志** - 在生产环境中始终启用审计以满足合规要求
4. **使用资源管理器** - 批量执行任务时使用资源管理器防止资源耗尽
5. **定期备份数据库** - 使用备份脚本保护扫描数据
6. **监控健康状态** - 定期运行健康检查确保系统正常运行

## 🆘 需要帮助？

如果这些示例不能解决你的问题：
- 📖 查看 [完整文档](./)
- ❓ 查看 [FAQ](./FAQ.md)
- 💬 在 [GitHub Discussions](https://github.com/your-org/ctftoolkit/discussions) 中提问
- 🐛 在 [GitHub Issues](https://github.com/your-org/ctftoolkit/issues) 中报告问题
