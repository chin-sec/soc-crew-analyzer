import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    QWEN_API_KEY = os.getenv("QWEN_API_KEY")
    if not QWEN_API_KEY:
        raise ValueError("❌ 错误: 未在 .env 中找到 QWEN_API_KEY")

    DASHSCOPE_BASE_URL = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")

    # LLM 模型参数
    LLM_MODEL = os.getenv("MODEL_NAME", "qwen-plus")
    TEMPERATURE = float(os.getenv("TEMPERATURE", "0.1"))
    MAX_TOKENS = int(os.getenv("MAX_TOKENS", "2048"))

    # 分析策略
    CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "4000"))
    CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "200"))
    MAX_THREADS = int(os.getenv("MAX_THREADS", "2"))
    REQUEST_TIMEOUT = 60

    # RAG 配置
    CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
    COLLECTION_NAME = os.getenv("COLLECTION_NAME", "security_logs")
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-v3")
    TOP_K_RESULTS = int(os.getenv("TOP_K_RESULTS", "5"))
    RAG_CONTEXT_MAX_CHARS = int(os.getenv("RAG_CONTEXT_MAX_CHARS", "1500"))
    EVENT_TIME_WINDOW_SEC = int(os.getenv("EVENT_TIME_WINDOW_SEC", "300"))

    # 文件上传限制
    MAX_LOG_SIZE_MB = int(os.getenv("MAX_LOG_SIZE_MB", "200"))


LLM_MODEL = Config.LLM_MODEL
TEMPERATURE = Config.TEMPERATURE
MAX_TOKENS = Config.MAX_TOKENS
CHUNK_SIZE = Config.CHUNK_SIZE
MAX_THREADS = Config.MAX_THREADS
CHUNK_OVERLAP = Config.CHUNK_OVERLAP
REQUEST_TIMEOUT = Config.REQUEST_TIMEOUT
DASHSCOPE_API_KEY = Config.QWEN_API_KEY
DASHSCOPE_BASE_URL = Config.DASHSCOPE_BASE_URL
