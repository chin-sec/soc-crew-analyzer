import os
import re
import logging
from typing import Optional, Type
from pydantic import BaseModel, Field

try:
    from crewai.tools import BaseTool
except ImportError:
    try:
        from crewai_tools import BaseTool
    except ImportError:
        # 如果都找不到，尝试旧版路径
        from crewai import BaseTool

from langchain_core.tools import Tool as LangChainTool

# 尝试导入 RAG 引擎
try:
    from rag_engine import rag_engine
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    rag_engine = None

logger = logging.getLogger(__name__)

# ================= 定义输入参数模型 =================

class LogPreprocessorInput(BaseModel):
    log_content: str = Field(..., description="原始安全日志内容字符串。如果内容过长，建议截取关键部分。")

class RagSearchInput(BaseModel):
    query: str = Field(..., description="自然语言查询关键词，例如 'IP 1.2.3.4 的攻击行为'")
    file_id: str = Field(..., description="当前分析的任务 ID 或文件 ID，用于限定检索范围。")

# ================= 定义工具类  =================

class LogPreprocessorTool(BaseTool):
    name: str = "Log Preprocessor & IOC Extractor"
    description: str = """
    用于预处理安全日志，提取关键统计信息和 IOC (Indicators of Compromise)。
    输入应为日志内容字符串。返回 Markdown 格式的统计摘要。
    """
    args_schema: Type[BaseModel] = LogPreprocessorInput

    def _run(self, log_content: str) -> str:
        try:
            if not isinstance(log_content, str):
                log_content = str(log_content)
            
            log_content = log_content.replace('\x00', '') 
            lines = log_content.strip().split('\n')
            total_lines = len(lines)
            
            ips = set()
            users = set()
            suspicious_keywords = ["failed", "error", "denied", "attack", "injection", "shell", "unauthorized", "invalid"]
            suspicious_count = 0
            suspicious_samples = []
            
            for line in lines:
                line_lower = line.lower()
                ip_matches = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                ips.update(ip_matches)
                user_matches = re.findall(r'(?:user|for\s+user)[=\s]+([a-zA-Z0-9_\-\.\@]+)', line, re.IGNORECASE)
                users.update(user_matches)
                
                if any(kw in line_lower for kw in suspicious_keywords):
                    suspicious_count += 1
                    if len(suspicious_samples) < 3:
                        suspicious_samples.append(line.strip()[:200])

            ip_list_str = ', '.join(list(ips)[:20])
            if len(ips) > 20: ip_list_str += f"... (共 {len(ips)} 个)"
                
            user_list_str = ', '.join(list(users)[:10])
            if len(users) > 10: user_list_str += f"... (共 {len(users)} 个)"
                
            samples_str = "\n".join([f"- `{s}`" for s in suspicious_samples]) if suspicious_samples else "- 无典型样本"

            report = f"""
### 📊 日志预处理摘要
- **总行数**: {total_lines}
- **唯一 IP 数量**: {len(ips)}
- **涉及用户**: {user_list_str}
- **可疑日志条目数**: {suspicious_count}

### 🎯 提取到的 IOC
- **Top IP 地址**: {ip_list_str}
- **可疑特征**: 包含 'failed', 'error', 'denied' 等关键词。

### 🔍 可疑日志样本
{samples_str}
"""
            return report.strip()
            
        except Exception as e:
            logger.error(f"日志预处理工具执行失败: {e}", exc_info=True)
            return f"❌ 工具执行错误: {str(e)}"

class RagSearchTool(BaseTool):
    name: str = "Log RAG Search"
    description: str = """
    在已索引的日志库中检索相关信息。
    必须提供 query (搜索词) 和 file_id (任务ID)。
    """
    args_schema: Type[BaseModel] = RagSearchInput

    def _run(self, query: str, file_id: str) -> str:
        if not RAG_AVAILABLE or not rag_engine:
            return "❌ 错误：RAG 引擎未初始化。请检查 rag_engine.py 是否正确加载。"
        
        if not file_id:
            return "❌ 错误：缺少 file_id 参数。无法确定检索范围。"
            
        try:
            logger.info(f"🔍 [RAG Tool] 检索: '{query[:50]}...' in FileID: {file_id}")
            results = rag_engine.query(file_id=file_id, user_question=query, top_k=5)
            
            if not results:
                return f"⚠️ 未在文件 ID `{file_id}` 中找到与 '{query}' 相关的信息。"
                
            formatted_results = []
            for i, r in enumerate(results):
                content = r.get('content', 'No content')
                score = r.get('similarity_score', 0.0)
                meta = r.get('metadata', {})
                chunk_idx = meta.get('chunk_index', 'N/A')
                formatted_results.append(
                    f"**[证据片段 {i+1}]** (相似度: {score:.3f}, 位置: {chunk_idx})\n"
                    f"> {content}\n"
                )
                
            return "\n---\n".join(formatted_results)
            
        except Exception as e:
            logger.error(f"RAG 检索工具执行失败: {e}", exc_info=True)
            return f"❌ RAG 检索错误: {str(e)}"

# ================= 实例化工具 =================
# 这里创建的是真正的 BaseTool 实例，可以直接传给 Agent
log_preprocess_tool = LogPreprocessorTool()
rag_search_tool = RagSearchTool()
