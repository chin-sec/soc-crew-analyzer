import os 
import logging 
from openai import OpenAI 
from .config import Config

logger = logging.getLogger(__name__)

_client = None

def get_client():
    """懒加载 OpenAI 客户端（DashScope 兼容模式）"""
    global _client
    if _client is None:
        cfg = Config()
        _client = OpenAI(
            api_key=cfg.QWEN_API_KEY,
            base_url=cfg.DASHSCOPE_BASE_URL,
            timeout=cfg.REQUEST_TIMEOUT,
        )
    return _client

def call_llm(prompt: str, response_format: str = None) -> str:
    """
    同步调用 LLM，返回文本内容。
    可选的 response_format 参数（如 "json_object"）会被传递。
    """
    client = get_client()
    cfg = Config()
    params = {
        "model": cfg.LLM_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": cfg.TEMPERATURE,
        "max_tokens": cfg.MAX_TOKENS,
    }
    if response_format:
        params["response_format"] = {"type": response_format}

    try:
        response = client.chat.completions.create(**params)
        content = response.choices[0].message.content or ""
        logger.debug(f"LLM 调用成功，tokens: {response.usage}")
        return content
    except Exception as e:
        logger.error(f"LLM 调用失败: {e}", exc_info=True)
        return f"Error: {str(e)}"

class _DummyLLMClient:
    def chat(self, prompt: str) -> str:
        return call_llm(prompt)

llm_client = _DummyLLMClient()
