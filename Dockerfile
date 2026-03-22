# 使用 Python 3.10 官方镜像
FROM python:3.10-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖 (如果需要编译某些包，如 gcc, build-essential)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目代码
COPY . .

# 暴露端口 (假设你的 api.py 运行在 8000)
EXPOSE 8000

# 设置环境变量 (可选，默认值)
ENV PYTHONUNBUFFERED=1

# 启动命令
CMD ["python", "api.py"]
