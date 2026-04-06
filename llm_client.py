import os
from dotenv import load_dotenv
from openai import OpenAI
from config import LLM_MODEL, TEMPERATURE, MAX_TOKENS, DASHSCOPE_API_KEY, DASHSCOPE_BASE_URL

load_dotenv()

# 全局客户端实例
_client = None

def get_client():
    global _client
    if _client is None:
        api_key = DASHSCOPE_API_KEY  # 使用 config 中的值
        base_url = DASHSCOPE_BASE_URL
        if not api_key:
            raise ValueError("DASHSCOPE_API_KEY 环境变量未设置")
        _client = OpenAI(api_key=api_key, base_url=base_url)
    return _client

def call_llm(prompt: str, response_format: str = None) -> str:
    """
    通用的 LLM 调用函数
    所有模型参数均从 config 统一获取，方便切换模型
    """
    try:
        client = get_client()
        
        # 构建参数，使用 config 中的模型、温度、最大 token
        call_params = {
            "model": LLM_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
        }
        
        # 如果指定了 response_format (如 "json_object")，则尝试添加
        # 注意：qwen-max 等模型可能不支持，但不影响调用
        if response_format:
            call_params["response_format"] = {"type": response_format}

        response = client.chat.completions.create(**call_params)
        
        content = response.choices[0].message.content or "No content"
        
        # 可选：打印 token 消耗（调试用）
        print(f"Token Usage: {response.usage}")
        
        return content
        
    except Exception as e:
        print(f"LLM 调用错误: {e}")
        return f"Error: {str(e)}"
