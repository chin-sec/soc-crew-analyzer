import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    # ================= 阿里云百炼配置 =================
    DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
    if not DASHSCOPE_API_KEY:
        raise ValueError("❌ 错误: 未在 .env 中找到 DASHSCOPE_API_KEY")
    
    DASHSCOPE_BASE_URL = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    
    # LLM 模型
    LLM_MODEL = os.getenv("MODEL_NAME", "qwen-max")
    TEMPERATURE = float(os.getenv("TEMPERATURE", "0.1"))
    MAX_TOKENS = int(os.getenv("MAX_TOKENS", "2048"))

    # ================= 核心分析策略配置 =================
    CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "2000"))
    CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "200"))
    MAX_THREADS = int(os.getenv("MAX_THREADS", "2"))
    REQUEST_TIMEOUT = 60

    # ================= RAG 配置  =================
    CHROMA_PERSIST_DIR = "./chroma_db"
    COLLECTION_NAME = "security_logs"
    EMBEDDING_MODEL = "text-embedding-v3"
    TOP_K_RESULTS = 5

# --- 全局变量 (为了兼容旧代码，可以保留，但主要用上面的类) ---
LLM_MODEL = Config.LLM_MODEL
TEMPERATURE = Config.TEMPERATURE
MAX_TOKENS = Config.MAX_TOKENS
CHUNK_SIZE = Config.CHUNK_SIZE
MAX_THREADS = Config.MAX_THREADS
CHUNK_OVERLAP = Config.CHUNK_OVERLAP
REQUEST_TIMEOUT = Config.REQUEST_TIMEOUT
DASHSCOPE_API_KEY = Config.DASHSCOPE_API_KEY
DASHSCOPE_BASE_URL = Config.DASHSCOPE_BASE_URL
