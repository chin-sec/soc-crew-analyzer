import os
import sys
from typing import Type, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# --- 路径修复逻辑 ---
# 获取当前文件所在目录
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取父目录 (假设 advanced_analyzer.py 在上一级目录)
parent_dir = os.path.dirname(current_dir)

# 将父目录添加到 sys.path 中，确保能导入 advanced_analyzer
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# 现在尝试导入
try:
    from advanced_analyzer import analyze_logs as advanced_analyze_func
except ImportError as e:
    print(f"Import Error: Cannot import from advanced_analyzer. {e}")
    # 如果报错，你可以尝试打印 sys.path 看看路径对不对
    # print(sys.path)
    # 为了不让程序崩溃，定义一个假函数
    def advanced_analyze_func(log_content, log_source):
        return "Error: advanced_analyzer module not found."

class DeepLogAnalysisInput(BaseModel):
    log_content: str = Field(..., description="完整的原始日志内容字符串。工具会自动处理分片和过滤。")
    log_source: str = Field("unknown", description="日志来源标识，例如文件名或IP地址。")

class DeepLogAnalysisTool(BaseTool):
    name: str = "Deep Log Analysis Engine (Hybrid)"
    description: str = """ 
    高性能混合分析引擎。
    1. Split: 按行智能切片。
    2. Map: 正则预检 + 并行 LLM 分析。
    3. Reduce: 层级化汇总。
    仅返回威胁摘要。
    """
    args_schema: Type[BaseModel] = DeepLogAnalysisInput

    def _run(self, log_content: str, log_source: str = "unknown") -> str:
        try:
            print(f"🚀 [DeepLogAnalysisTool] 开始分析来源: {log_source}, 长度: {len(log_content)}")
            # 调用我们新优化的核心函数
            result = advanced_analyze_func(log_content, log_source)
            print(f"✅ [DeepLogAnalysisTool] 完成。")
            return result
        except Exception as e:
            import traceback
            error_msg = f"Error during deep log analysis: {str(e)}\n{traceback.format_exc()}"
            print(error_msg)
            return error_msg
