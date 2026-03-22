import os
import re
import time
import logging
from typing import List, Dict, Any, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

try:
    import tiktoken
    TOKEN_ENCODER = tiktoken.get_encoding("cl100k_base")
    USE_TIKTOKEN = True
except ImportError:
    USE_TIKTOKEN = False
    logging.warning("⚠️ tiktoken 未安装")

from simple_analyzer import call_llm
try:
    from rag_engine import rag_engine
    RAG_ENABLED = True
except ImportError:
    RAG_ENABLED = False

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

MAX_WORKERS = int(os.getenv("MAX_WORKERS", "8")) # 增加默认线程数
CHUNK_TOKENS = int(os.getenv("CHUNK_TOKENS", "2000"))

class AdvancedLogAnalyzer:
    def __init__(self):
        if USE_TIKTOKEN:
            logger.info(f"✅ Token 编码器已加载")
        logger.info(f"⚙️  配置：并行线程={MAX_WORKERS}, 切片大小={CHUNK_TOKENS}")

    def _count_tokens(self, text: str) -> int:
        if USE_TIKTOKEN:
            return len(TOKEN_ENCODER.encode(text))
        return len(text) // 4

    def hybrid_preprocess(self, text: str) -> Dict[str, Any]:
        lines = text.splitlines()
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        stats = {
            "total_lines": len(lines),
            "unique_ip_count": len(set(ip_pattern.findall(text))),
            "top_ips": list(set(ip_pattern.findall(text)))[:10],
            "ssh_fails": len(re.findall(r"Failed password|Invalid user", text, re.IGNORECASE)),
            "sql_attempts": len(re.findall(r"union\s+select|or\s+1\s*=\s*1", text, re.IGNORECASE)),
            "http_4xx": len(re.findall(r"\s4\d{2}\s", text)),
            "http_5xx": len(re.findall(r"\s5\d{2}\s", text)),
        }
        return stats

    def split_logs(self, text: str) -> List[Dict[str, Any]]:
        """
        【优化】返回带元数据的字典列表，方便后续直接使用
        """
        lines = text.splitlines()
        chunks = []
        current_chunk_lines = []
        current_tokens = 0
        
        for line in lines:
            line_tokens = self._count_tokens(line)
            if current_tokens + line_tokens > CHUNK_TOKENS and current_chunk_lines:
                chunk_text = "\n".join(current_chunk_lines)
                chunks.append({
                    "text": chunk_text,
                    "metadata": {"lines_count": len(current_chunk_lines)}
                })
                current_chunk_lines = [line]
                current_tokens = line_tokens
            else:
                current_chunk_lines.append(line)
                current_tokens += line_tokens
        
        if current_chunk_lines:
            chunks.append({
                "text": "\n".join(current_chunk_lines),
                "metadata": {"lines_count": len(current_chunk_lines)}
            })
        return chunks

    def _is_safe_chunk(self, chunk_text: str) -> bool:
        """
        【优化】轻量级预过滤
        如果 chunk 中没有任何潜在威胁特征，直接跳过 LLM 分析，节省 Token
        """
        # 定义一些明显的“安全”特征，如果只有这些，可以跳过
        # 注意：这里逻辑是反的，如果有“危险”特征才返回 False (需要分析)
        # 或者：如果全是“安全”特征且无“危险”特征，返回 True (跳过)
        
        danger_patterns = [
            r"Failed password", r"Invalid user", r"error", r"exception", 
            r"union\s+select", r"select\s+.*\s+from", r"../", r"<script>",
            r"4\d{2}", r"5\d{2}", r"POST.*\.php", r"cmd=", r"exec="
        ]
        
        for pattern in danger_patterns:
            if re.search(pattern, chunk_text, re.IGNORECASE):
                return False # 发现危险特征，需要分析
        
        # 如果没有危险特征，且主要是正常的 GET 200，可以跳过
        # 这里为了保险，只要没发现明显危险，我们也可以选择不跳过，或者只跳过纯静态资源访问
        # 激进优化：如果没有任何匹配，直接跳过
        return True

    def _analyze_single_chunk(self, idx: int, chunk_data: Dict, stats: Dict, skip_analysis: bool = False) -> Optional[str]:
        chunk_text = chunk_data['text']
        
        if skip_analysis:
            # 如果预过滤判定安全，直接返回空或简短标记，不消耗 Token
            return None 

        stats_summary = f"全局：{stats['unique_ip_count']} IPs, {stats['ssh_fails']} SSH fails"
        prompt = f"""
        【背景】{stats_summary}
        【片段 {idx+1}】
        {chunk_text}
        
        任务：识别具体攻击 (IP, 类型，证据)。若无威胁回复"无"。
        """
        
        try:
            res = call_llm(prompt, system_prompt="你是安全分析师，只输出关键威胁点。")
            if "无" in res and len(res) < 20: # 简单的后过滤
                return None
            return f"--- 片段 {idx+1} ---\n{res}"
        except Exception as e:
            logger.error(f"❌ 片段 {idx+1} 失败：{e}")
            return f"--- 片段 {idx+1} ---\nError: {str(e)}"

    def map_analyze(self, chunks: List[Dict], stats: Dict, progress_callback: Callable) -> List[str]:
        logger.info(f"🚀 开始并行分析 ({MAX_WORKERS} 线程)...")
        results = [None] * len(chunks)
        done = 0
        total = len(chunks)
        
        # 预计算哪些需要分析
        tasks = []
        for i, c in enumerate(chunks):
            skip = self._is_safe_chunk(c['text'])
            tasks.append((i, c, skip))
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._analyze_single_chunk, i, c, stats, skip): i 
                for i, c, skip in tasks
            }
            
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    logger.error(f"任务异常：{e}")
                
                done += 1
                if progress_callback:
                    # 更新 Map 进度
                    progress_callback("analyzing", done, total, f"分析片段: {done}/{total}")
                    
        return [r for r in results if r is not None]

    def reduce_reports(self, sub_reports: List[str]) -> str:
        if not sub_reports:
            return "✅ 经详细分析，未发现明显攻击行为 (或所有片段均被预过滤判定为安全)。"
            
        combined = "\n\n".join(sub_reports)
        prompt = f"""
        以下是多个日志片段的分析结果：
        {combined}
        
        任务: 去重、关联攻击链，生成 Markdown 报告 (🛑高危摘要，📊IP 黑名单，🛡️防御建议)。
        """
        return call_llm(prompt, system_prompt="你是首席安全官 (CSO)。")

    def analyze(self, full_text: str, file_id: str, progress_callback: Callable = None) -> str:
        start = datetime.now()
        logger.info("="*30 + "\n🚀 启动高级分析流水线\n" + "="*30)
        
        # 1. 预处理
        if progress_callback: progress_callback("preprocessing", 0, 100, "正在预处理统计...")
        stats = self.hybrid_preprocess(full_text)
        
        # 2. 分块
        if progress_callback: progress_callback("splitting", 0, 100, "正在智能分块...")
        chunks = self.split_logs(full_text)
        logger.info(f"✅ 切分完成：{len(chunks)} 个块")
        
        # 3. RAG 索引 (并发优化版)
        if RAG_ENABLED and chunks:
            if progress_callback: progress_callback("indexing", 0, len(chunks), "正在建立向量索引 (并发中)...")
            
            def rag_progress_cb(current, total, msg):
                if progress_callback:
                    progress_callback("indexing", current, total, f"{msg} {current}/{total}")
            
            try:
                rag_engine.ingest_chunks(file_id, chunks, progress_callback=rag_progress_cb)
                logger.info(f"✅ [RAG] 索引完成")
            except Exception as e:
                logger.error(f"❌ [RAG] 索引失败：{e}")
        
        # 4. Map (带预过滤)
        if progress_callback: progress_callback("analyzing", 0, len(chunks), "正在并行分析 (预过滤中)...")
        
        if len(chunks) == 1:
            sub_reports = [self._analyze_single_chunk(0, chunks[0], stats)]
        else:
            sub_reports = self.map_analyze(chunks, stats, progress_callback)
            
        # 5. Reduce
        if progress_callback: progress_callback("reducing", 0, 100, "正在汇总生成报告...")
        report = self.reduce_reports(sub_reports)
        
        duration = (datetime.now() - start).total_seconds()
        logger.info(f"🎉 完成！耗时：{duration:.2f}s")
        if progress_callback: progress_callback("completed", 100, 100, f"分析完成! 耗时 {duration:.1f}s")
        
        return report

def analyze_large_log(log_text: str, file_id: str, progress_callback: Callable = None) -> str:
    analyzer = AdvancedLogAnalyzer()
    return analyzer.analyze(log_text, file_id, progress_callback)
