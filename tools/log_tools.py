import os
import logging

logger = logging.getLogger(__name__)

def read_log_file(file_path: str) -> str:
    """
    读取日志文件内容。
    参数 file_path 是相对路径，例如 'uploads/test.log'
    """
    # 获取项目根目录 (假设 api.py 在上上级或同级，这里根据实际结构调整)
    # 简单起见，我们假设调用者已经传入了正确的绝对路径，或者我们在 api.py 里拼接好
    # 但为了兼容 LangChain Tool 风格，这里尝试直接读取
    if not os.path.isabs(file_path):
        # 如果是相对路径，尝试在当前工作目录查找
        # 注意：api.py 中通常会拼接好绝对路径再传进来，或者这里需要知道 PROJECT_ROOT
        # 为了简单，如果文件不存在，直接抛出异常让 api.py 处理
        pass
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        logger.info(f"Successfully read file: {file_path} ({len(content)} chars)")
        return content
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise
