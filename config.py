import os
from dotenv import load_dotenv

# 加载 .env 文件
load_dotenv()

class Config:
    # ================= 阿里云百炼配置 =================
    DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
    if not DASHSCOPE_API_KEY:
        raise ValueError("❌ 错误: 未在 .env 中找到 DASHSCOPE_API_KEY")
        
    DASHSCOPE_BASE_URL = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    
    # LLM 模型 (用于生成回答)
    LLM_MODEL = os.getenv("MODEL_NAME", "qwen-max")
    
    # Embedding 模型 (用于向量化，阿里云推荐 text-embedding-v3)
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-v3")
    
    # ================= ChromaDB 配置 =================
    # 向量数据库持久化目录 (会在当前目录下创建 chroma_db 文件夹)
    CHROMA_PERSIST_DIR = "./chroma_db"
    COLLECTION_NAME = "log_analytics"
    
    # ================= RAG 策略配置 =================
    # 每次检索返回最相关的 K 条日志片段
    TOP_K_RESULTS = 5
    
    # 分块策略 (字符数)
    # 日志通常一行一条，建议按行分割，但这里先按字符粗略分块，后续可优化
    CHUNK_SIZE = 800   
    CHUNK_OVERLAP = 100 # 重叠部分，防止切断关键上下文 (如堆栈跟踪)
    
    # 超时设置 (秒)
    REQUEST_TIMEOUT = 60
