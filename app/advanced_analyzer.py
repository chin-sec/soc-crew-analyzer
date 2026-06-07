import json
import re
import logging
import hashlib
from typing import List, Dict, Any, Optional
from collections import defaultdict
from app.config import Config
from app.llm_client import call_llm
from app.rag_engine import RAGEngine
from app.log_stats import extract_iocs, get_ioc_summary

logger = logging.getLogger(__name__)


class AdvancedLogAnalyzer:
    """生产级日志分析器 - 三层漏斗架构（全同步版本）"""

    _JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL)
    _TRAILING_COMMA_PATTERN = re.compile(r",\s*([}\]])")

    def __init__(self, config: Optional[Config] = None, rag_engine: Optional[RAGEngine] = None):
        self.config = config or Config()
        self.rag_engine = rag_engine

        self.rag_context_max_chars = int(getattr(self.config, "RAG_CONTEXT_MAX_CHARS", 1500))
        self.event_time_window_sec = int(getattr(self.config, "EVENT_TIME_WINDOW_SEC", 300))

    @staticmethod
    def _rule_based_filter(log_chunk: str) -> Dict[str, Any]:
        """纯规则匹配，返回可疑标记+基础特征（不调用LLM）"""
        iocs = extract_iocs(log_chunk)
        suspicious_keywords = [
            "union select", "<script>", "eval(", "exec(",
            "cmd.exe", "powershell", "webshell", "../..",
            "reverse_shell", "mimikatz", "cobaltstrike"
        ]
        keyword_hits = [kw for kw in suspicious_keywords if kw.lower() in log_chunk.lower()]

        is_suspicious = bool(iocs) or bool(keyword_hits)
        return {
            "is_suspicious": is_suspicious,
            "iocs": iocs,
            "keyword_hits": keyword_hits,
            "raw_chunk": log_chunk
        }

    @staticmethod
    def _cluster_events(suspicious_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """按 src_ip + attack_signature 聚类"""
        clusters: Dict[str, List[Dict]] = defaultdict(list)

        for item in suspicious_items:
            ip_list = [i["value"] for i in item["iocs"] if i["type"] == "ipv4"]
            src_ip = ip_list[0] if ip_list else "unknown"
            sig = "|".join(sorted(item["keyword_hits"])) if item["keyword_hits"] else "ioc_only"
            cluster_key = hashlib.md5(f"{src_ip}:{sig}".encode()).hexdigest()[:12]
            clusters[cluster_key].append(item)

        events = []
        for cluster_id, items in clusters.items():
            all_iocs = []
            seen = set()
            for it in items:
                for ioc in it["iocs"]:
                    key = f"{ioc['type']}:{ioc['value']}"
                    if key not in seen:
                        all_iocs.append(ioc)
                        seen.add(key)

            events.append({
                "cluster_id": cluster_id,
                "sample_count": len(items),
                "representative_chunk": items[0]["raw_chunk"],
                "all_keyword_hits": list({kw for it in items for kw in it["keyword_hits"]}),
                "merged_iocs": all_iocs,
            })

        logger.info(f"[Funnel] 聚类完成: {len(suspicious_items)}条可疑 → {len(events)}个独立事件")
        return events

    @classmethod
    def _safe_parse_json(cls, raw_text: str) -> Optional[dict]:
        """多层防御JSON解析"""
        if not raw_text:
            return None
        text = raw_text.strip()
        for attempt_text in [
            text,
            cls._JSON_BLOCK_PATTERN.search(text).group(1).strip() if cls._JSON_BLOCK_PATTERN.search(text) else "",
            cls._TRAILING_COMMA_PATTERN.sub(r"\1", text),
        ]:
            if not attempt_text:
                continue
            try:
                return json.loads(attempt_text)
            except json.JSONDecodeError:
                continue
        first, last = text.find("{"), text.rfind("}")
        if first != -1 and last > first:
            try:
                return json.loads(cls._TRAILING_COMMA_PATTERN.sub(r"\1", text[first:last+1]))
            except json.JSONDecodeError:
                pass
        logger.warning(f"[LLM] JSON解析失败: {text[:200]}")
        return None

    def _analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """对单个聚类事件做 LLM+RAG+MITRE 分析（同步版本）"""
        ioc_summary = get_ioc_summary(event["merged_iocs"])

        # RAG检索
        rag_context = ""
        if self.rag_engine:
            query_parts = list(ioc_summary.get("sha256", [])[:1]) + \
                          list(ioc_summary.get("domain", [])[:1]) + \
                          event["all_keyword_hits"][:2]
            query = " ".join(query_parts) if query_parts else event["representative_chunk"][:200]
            try:
                results = self.rag_engine.query(user_question=query, top_k=3)
                docs = results.get("documents", [])
                if docs:
                    rag_context = "\n---\n".join(d["content"] for d in docs)
                    if len(rag_context) > self.rag_context_max_chars:
                        rag_context = rag_context[:self.rag_context_max_chars] + "\n...[截断]"
            except Exception as e:
                logger.warning(f"[RAG] 事件分析检索降级: {e}")

        prompt = f"""你是SOC高级分析师。请基于以下信息分析安全事件，并严格映射到MITRE ATT&CK框架。

## 事件摘要
- 样本数量: {event['sample_count']}
- 关键词命中: {json.dumps(event['all_keyword_hits'], ensure_ascii=False)}
- IOC汇总: {json.dumps(ioc_summary, ensure_ascii=False)}

## 代表性日志样本
{event['representative_chunk'][:3000]}

## 内部知识库参考
{rag_context or "无"}

请以严格JSON格式返回（不要包含任何其他文字）：
{{
  "is_threat": true/false,
  "attack_type": "攻击类型中文描述",
  "mitre_id": "Txxxx (必须为有效ATT&CK Technique ID，不确定则填unmapped)",
  "tactic": "ATT&CK Tactic阶段",
  "technique_name": "ATT&CK Technique英文名称",
  "confidence": 0.0-1.0,
  "evidence": "判断依据",
  "recommendation": "处置建议"
}}"""

        try:
            raw = call_llm(prompt)
            result = self._safe_parse_json(raw)
            if result is None:
                return {"error": "llm_json_parse_failed", "cluster_id": event["cluster_id"]}
            result["cluster_id"] = event["cluster_id"]
            result["sample_count"] = event["sample_count"]
            result["iocs"] = event["merged_iocs"]
            return result
        except Exception as e:
            logger.error(f"[LLM] 事件分析异常: {e}")
            return {"error": str(e), "cluster_id": event["cluster_id"]}

    def analyze_logs(self, log_content: str) -> Dict[str, Any]:
        """
        三层漏斗主流程（同步）
        返回严格JSON，可直接被Hunter Agent消费
        """
        chunk_size = 4000
        suspicious_items = []
        for i in range(0, len(log_content), chunk_size):
            chunk = log_content[i:i + chunk_size]
            result = self._rule_based_filter(chunk)
            if result["is_suspicious"]:
                suspicious_items.append(result)

        if not suspicious_items:
            return {
                "summary": "未发现安全威胁",
                "events": [],
                "total_chunks_processed": (len(log_content) + chunk_size - 1) // chunk_size,
                "suspicious_chunks": 0
            }

        events = self._cluster_events(suspicious_items)

        analyzed_events = []
        for event in events:
            analysis = self._analyze_event(event)
            analyzed_events.append(analysis)

        threat_events = [e for e in analyzed_events if e.get("is_threat") and "error" not in e]

        return {
            "summary": f"发现{len(threat_events)}个安全事件，共{len(suspicious_items)}条可疑日志聚类而成",
            "events": analyzed_events,
            "total_chunks_processed": (len(log_content) + chunk_size - 1) // chunk_size,
            "suspicious_chunks": len(suspicious_items),
            "clustered_events": len(events)
        }
