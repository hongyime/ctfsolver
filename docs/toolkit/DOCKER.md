# CTF Toolkit Docker 设置指南

本指南详细说明如何在 Docker 中部署和运行 CTF Toolkit。

## 📋 目录

- [前置要求](#前置要求)
- [快速开始](#快速开始)
- [Docker Compose 部署](#docker-compose-部署)
- [自定义配置](#自定义配置)
- [数据持久化](#数据持久化)
- [网络配置](#网络配置)
- [故障排除](#故障排除)

## 🖥️ 前置要求

- **Docker** 20.10+
- **Docker Compose** 2.0+（可选，用于编排）
- **磁盘空间** 至少 20GB

## 🚀 快速开始

### 方法 1：使用预构建镜像

```bash
# 拉取镜像
docker pull bryan-ctf/ctftoolkit:latest

# 运行容器
docker run -it --rm \
  -v $(pwd)/workspace:/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -p 8000:8000 \
  -e CTFTOOLKIT_SECURITY_LEVEL=medium \
  your-org/ctftoolkit:latest
```

### 方法 2：从源代码构建

```bash
# 克隆仓库
git clone https://github.com/bryan-ctf/ctftoolkit.git
cd ctftoolkit

# 构建镜像
docker build -t ctftoolkit:latest .

# 运行容器
docker run -it --rm \
  -v $(pwd)/workspace:/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -p 8000:8000 \
  ctftoolkit:latest
```

## 🐳 Docker Compose 部署

### 创建 docker-compose.yml

```yaml
version: '3.8'

services:
  ctftoolkit:
    build:
      context: .
      dockerfile: Dockerfile
    image: ctftoolkit:latest
    container_name: ctftoolkit
    restart: unless-stopped
    
    ports:
      - "8000:8000"
    
    volumes:
      # 工作目录
      - ./workspace:/workspace
      # Docker Socket（用于运行子容器）
      - /var/run/docker.sock:/var/run/docker.sock
      # 数据库持久化
      - ctftoolkit_db:/var/lib/ctftoolkit
      # 日志
      - ./logs:/var/log/ctftoolkit
    
    environment:
      # 基础配置
      - CTFTOOLKIT_DB_PATH=/var/lib/ctftoolkit/ctf_state.db
      - CTFTOOLKIT_WORKSPACE=/workspace
      - CTFTOOLKIT_LOG_DIR=/var/log/ctftoolkit
      
      # 安全配置
      - CTFTOOLKIT_SECURITY_LEVEL=medium
      - CTFTOOLKIT_AUDIT_ENABLED=true
      
      # 性能配置
      - CTFTOOLKIT_MAX_CONCURRENCY=5
      - CTFTOOLKIT_DEFAULT_CONCURRENCY=3
      
      # Docker 配置
      - CTFTOOLKIT_DOCKER_ENABLED=true
      - CTFTOOLKIT_DOCKER_NETWORK=bridge
    
    # 资源限制
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 1G
    
    # 健康检查
    healthcheck:
      test: ["CMD", "python", "-c", "from src.ctf_core.debug.debugger import get_health_checker; import asyncio; asyncio.run(get_health_checker().run_checks())"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

# 数据卷
volumes:
  ctftoolkit_db:
    driver: local
```

### 启动服务

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f ctftoolkit

# 停止服务
docker-compose down

# 停止并删除数据卷
docker-compose down -v
```

## 🔧 自定义配置

### 环境变量

在 `docker-compose.yml` 或 `docker run` 中设置：

```bash
# 安全级别
CTFTOOLKIT_SECURITY_LEVEL=medium  # low, medium, high

# 并发配置
CTFTOOLKIT_MAX_CONCURRENCY=5
CTFTOOLKIT_DEFAULT_CONCURRENCY=3

# 审计配置
CTFTOOLKIT_AUDIT_ENABLED=true
CTFTOOLKIT_AUDIT_RETENTION_DAYS=30

# Docker 配置
CTFTOOLKIT_DOCKER_ENABLED=true
CTFTOOLKIT_DOCKER_NETWORK=bridge
```

### 自定义 Dockerfile

如果需要自定义工具，创建 `Dockerfile.custom`：

```dockerfile
FROM your-org/ctftoolkit:latest

# 安装额外的工具
RUN apt-get update && apt-get install -y \
    your-custom-tool \
    && rm -rf /var/lib/apt/lists/*

# 复制自定义配置
COPY your-config.conf /etc/ctftoolkit/
```

## 💾 数据持久化

### 数据库备份

```bash
# 备份数据库
docker exec ctftoolkit cp /var/lib/ctftoolkit/ctf_state.db /tmp/backup.db
docker cp ctftoolkit:/tmp/backup.db ./ctf_state_backup.db

# 恢复数据库
docker cp ./ctf_state_backup.db ctftoolkit:/tmp/restore.db
docker exec ctftoolkit cp /tmp/restore.db /var/lib/ctftoolkit/ctf_state.db
```

### 工作目录备份

```bash
# 备份工作目录
tar -czf workspace_backup.tar.gz ./workspace

# 恢复工作目录
tar -xzf workspace_backup.tar.gz -C ./
```

## 🌐 网络配置

### 创建自定义网络

```yaml
# docker-compose.yml 添加
networks:
  ctf-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:
  ctftoolkit:
    networks:
      - ctf-network
```

### 网络隔离配置

```bash
# 限制 CTF Toolkit 只能访问特定网络
docker run --network=ctf-network \
  --sysctl net.ipv4.conf.all.route_localnet=0 \
  ctftoolkit:latest
```

## 🐛 故障排除

### 容器无法启动

```bash
# 查看日志
docker logs ctftoolkit

# 进入容器调试
docker run -it --entrypoint /bin/bash ctftoolkit:latest

# 检查 Docker Socket 权限
ls -la /var/run/docker.sock
```

### 权限问题

```bash
# Linux: 确保用户有 Docker 权限
sudo usermod -aG docker $USER
# 注销并重新登录
```

### 数据库锁定

```bash
# 删除 WAL 文件
docker exec ctftoolkit rm -f /var/lib/ctftoolkit/ctf_state.db-wal
docker exec ctftoolkit rm -f /var/lib/ctftoolkit/ctf_state.db-shm
```

### 性能问题

```bash
# 增加资源限制
docker-compose up -d --scale ctftoolkit=2

# 或调整并发配置
docker run -e CTFTOOLKIT_MAX_CONCURRENCY=10 ctftoolkit:latest
```

## 📊 监控

### 查看容器状态

```bash
# 查看运行状态
docker stats ctftoolkit

# 查看进程
docker top ctftoolkit

# 查看详细信息
docker inspect ctftoolkit
```

### 日志分析

```bash
# 查看最近 100 行日志
docker logs --tail 100 ctftoolkit

# 实时查看日志
docker logs -f ctftoolkit

# 导出日志
docker logs ctftoolkit > ctftoolkit.log
```

## 🔄 更新

### 更新镜像

```bash
# 拉取最新镜像
docker pull your-org/ctftoolkit:latest

# 停止现有容器
docker-compose down

# 使用新镜像重新启动
docker-compose up -d
```

### 滚动更新

```bash
# 使用 Docker Compose 滚动更新
docker-compose up -d --no-deps --force-recreate ctftoolkit
```

---

**下一步**: 查看 [使用指南](./USAGE_GUIDE.md) 学习如何使用 CTF Toolkit
