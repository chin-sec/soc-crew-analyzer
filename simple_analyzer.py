import os
import logging
from dotenv import load_dotenv

# 加载 .env 变量
load_dotenv()

# 配置日志
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# 从环境变量获取配置
API_KEY = os.getenv("DASHSCOPE_API_KEY")
BASE_URL = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen-plus")

if not API_KEY:
    raise ValueError("❌ 错误：未在 .env 文件中找到 DASHSCOPE_API_KEY，请检查配置。")

def call_llm(prompt: str, system_prompt: str = "你是一个专业的网络安全日志分析专家。") -> str:
    api_key = os.getenv("DASHSCOPE_API_KEY")
    base_url = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    model_name = os.getenv("MODEL_NAME", "qwen-max")
    
    if not api_key:
        raise ValueError("❌ 错误: 未找到 DASHSCOPE_API_KEY 环境变量。请检查 .env 文件。")

    try:
        from openai import OpenAI
    except ImportError:
        logger.error("❌ 未安装 openai 库，请运行: pip install openai")
        raise

    client = OpenAI(
        api_key=api_key, 
    	base_url=base_url,
    	timeout=600.0,  
    	max_retries=2
    )

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            stream=False
        )
        return response.choices[0].message.content
    except Exception as e:
        raise Exception(f"LLM 调用失败: {str(e)}")

def analyze_log_text(text: str) -> str:
    """
    简单分析模式：适用于小文件 (<1MB)
    直接调用 LLM 进行一次性分析。
    """
    logger.info("📄 启动简单分析模式...")
    
    prompt = f"""
    请分析以下网络安全日志，识别潜在的攻击行为（如 SQL 注入、XSS、暴力破解、异常扫描等）。
    如果未发现威胁，请明确说明。
    
    日志内容：
    {text[:15000]} 
    (注：简单模式仅截取前 15000 字符以防超时，大文件请使用高级模式)
    """
    
    system_prompt = "你是一个资深的安全运营中心 (SOC) 分析师。请输出结构清晰的 Markdown 报告。"
    
    return call_llm(prompt, system_prompt)

if __name__ == "__main__":
    # 本地测试
    print("正在测试 LLM 连接...")
    try:
        res = call_llm("你好，请回复'连接成功'以测试阿里云百炼接口。")
        print(f"✅ 测试结果: {res}")
    except Exception as e:
        print(f"❌ 测试失败: {e}")
