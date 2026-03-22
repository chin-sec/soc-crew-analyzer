import logging
logger = logging.getLogger(__name__)

def analyze_large_log(log_content: str, custom_prompt: str = None) -> str:
    """
    简单的分块分析占位符。
    真实项目中这里会实现 Map-Reduce 逻辑。
    目前策略：只分析前 15000 字符，避免超时。
    """
    logger.warning("Using simple fallback for large log analysis.")
    truncated_content = log_content[:15000]
    
    # 调用简单的分析函数 (需要从外部传入，这里为了演示直接返回提示)
    # 实际逻辑会在 api.py 中处理，这里只是防止 ImportError
    return f"[系统提示]: 文件过大 ({len(log_content)} 字符)，当前简易模式仅分析前 15000 字符。\n\n分析结果如下:\n(此处应接入具体 AI 分析逻辑，目前由 simple_analyzer 处理截断后的内容)"
