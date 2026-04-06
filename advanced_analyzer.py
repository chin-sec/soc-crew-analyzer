import os
import re
import json
import logging
from typing import List, Dict, Any, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import CHUNK_SIZE, MAX_THREADS, CHUNK_OVERLAP
from llm_client import call_llm
from log_stats import generate_log_stats, extract_iocs

logger = logging.getLogger(__name__)

# ---------- 正则预检（增强版）----------
def _is_suspicious_chunk(chunk_content: str) -> Tuple[bool, str]:
    """混合预检：返回 (是否可疑, 攻击类型)"""
    def safe_search(pattern, text):
        try:
            return re.search(pattern, text, re.IGNORECASE)
        except re.error:
            return None

    # SQL 注入特征
    sql_patterns = [
        r"(?i)(union\s+all\s+select|union\s+select)",
        r"(?i)(select\s+.*?\s+from\s+.*?information_schema)",
        r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\()",
        r"(?i)(\s+or\s+[\d\']+[=<>][\d\']+\s+)",
        r"(?i)(drop\s+table|delete\s+from|insert\s+into|xp_cmdshell)",
        r"(?i)(%27|')\s*.*\s*(%23|--|/\*)",
        r"(?i)(%60|`)\s*.*\s*(%23|--|/\*)",
    ]
    # XSS & 路径遍历
    xss_patterns = [
        r"<script[^>]*>", r"</script>", r"javascript\s*:",
        r"onload\s*=|onerror\s*=|onclick\s*=",
        r"(\.\./|\.\.%2f)+", r"\.git/config", r"etc/passwd",
    ]
    # RCE & 命令注入
    rce_patterns = [
        r";ls\s+\-la", r";cat\s+", r";id\s*",
        r"(%3B|;)(wget|curl|nc|netcat)",
        r"(%7C|\|)\s*(wget|curl)",
        r"(%24\{|\$\().*?(\$\)|\))",
        r"base64\s+\-\w*\s+\S+",
    ]
    scanner_patterns = [r"sqlmap", r"nikto", r"burp", r"acunetix", r"nessus"]
    webshell_patterns = [
        r"eval\s*\(\s*\$_(POST|GET|REQUEST)",
        r"assert\s*\(\s*\$_",
        r"system\s*\(\s*\$_",
        r"exec\s*\(\s*\$_",
        r"cmd\s*=\s*",
    ]

    for p in sql_patterns:
        if safe_search(p, chunk_content):
            return True, "SQL注入"
    for p in xss_patterns:
        if safe_search(p, chunk_content):
            return True, "XSS或路径遍历"
    for p in rce_patterns:
        if safe_search(p, chunk_content):
            return True, "命令注入/RCE"
    for p in scanner_patterns:
        if safe_search(p, chunk_content):
            return True, "扫描器行为"
    for p in webshell_patterns:
        if safe_search(p, chunk_content):
            return True, "WebShell特征"

    return False, "正常"

# ---------- 分块 ----------
def split_logs(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> List[Dict[str, Any]]:
    lines = text.split('\n')
    if not lines:
        return []
    chunks = []
    start = 0
    while start < len(lines):
        end = start
        current_length = 0
        while end < len(lines) and current_length < chunk_size:
            current_length += len(lines[end]) + 1
            end += 1
        chunk_content = "\n".join(lines[start:end])
        if len(chunk_content) > chunk_size * 10:
            chunk_content = chunk_content[:chunk_size]
        chunks.append({
            "id": len(chunks),
            "content": chunk_content,
            "start_line": start,
            "end_line": end,
        })
        start = end - overlap if end - overlap > start else end
    return chunks

# ---------- 核心分析函数（调用 LLM，返回结构化结果）----------
def analyze_chunk(chunk: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    返回结构化结果：{'attack_type': str, 'confidence': str, 'evidence': str, 'chunk_id': int}
    若无可疑或 LLM 失败，返回 None
    """
    is_suspicious, reason = _is_suspicious_chunk(chunk['content'])
    if not is_suspicious:
        return None

    # 重要：必须包含日志内容
    prompt = f"""你是一名网络安全专家。请判断以下日志片段是否为真实攻击，并按 JSON 格式输出。
正则预检提示：{reason}

日志片段（第 {chunk['start_line']}-{chunk['end_line']} 行）：

请严格输出以下 JSON 格式（不要输出其他内容）：
{{
    "attack_type": "攻击类型，如 SQL注入 / XSS / 命令注入 / 扫描器 / Webshell / 正常流量",
    "confidence": "高/中/低",
    "evidence": "简要证据描述"
}}
如果判断为正常流量，attack_type 写 "正常流量"，confidence 写 "无"，evidence 写 "无异常"。
"""
    try:
        # 使用 JSON Mode 提高解析成功率
        response = call_llm(prompt, response_format="json_object")
        response = response.strip()
        # 去除可能的 markdown 代码块标记
        if response.startswith("```json"):
            response = response[7:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]
        result = json.loads(response.strip())
        
        if result.get("attack_type") == "正常流量":
            return None
        
        return {
            "chunk_id": chunk['id'],
            "attack_type": result.get("attack_type", "未知"),
            "confidence": result.get("confidence", "中"),
            "evidence": result.get("evidence", "")[:200]
        }
    except Exception as e:
        logger.error(f"块 {chunk['id']} LLM 分析失败: {e}, 响应: {response if 'response' in locals() else '无'}")
        return None

# ---------- 汇总报告（生成专业 SOC 报告）----------
def reduce_reports(findings: List[Dict[str, Any]], log_stats: str, iocs: Dict[str, List[str]]) -> str:
    if not findings:
        return f"""# 🔒 安全日志分析报告

## 📋 概览
{log_stats}

## ✅ 分析结论
未发现明确的安全威胁。日志流量表现正常。

---
*报告生成时间：{__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
    
    attack_counter = {}
    for f in findings:
        atype = f['attack_type']
        attack_counter[atype] = attack_counter.get(atype, 0) + 1
    
    report_lines = []
    report_lines.append("# 🛡️ SOC 安全分析报告")
    report_lines.append("")
    report_lines.append(f"**生成时间**: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("")
    report_lines.append("## 📊 日志概览")
    report_lines.append(log_stats)
    report_lines.append("")
    
    report_lines.append("## 🔥 威胁摘要")
    report_lines.append(f"共检测到 **{len(findings)}** 个可疑事件，涉及 **{len(attack_counter)}** 种攻击类型。")
    report_lines.append("")
    report_lines.append("### 攻击类型分布")
    report_lines.append("| 攻击类型 | 发生次数 |")
    report_lines.append("|---------|---------|")
    for atype, count in sorted(attack_counter.items(), key=lambda x: x[1], reverse=True):
        report_lines.append(f"| {atype} | {count} |")
    report_lines.append("")
    
    report_lines.append("## 🧾 详细威胁事件")
    report_lines.append("| 块ID | 攻击类型 | 置信度 | 证据 |")
    report_lines.append("|------|---------|--------|------|")
    for f in findings[:20]:
        report_lines.append(f"| {f['chunk_id']} | {f['attack_type']} | {f['confidence']} | {f['evidence'][:60]} |")
    if len(findings) > 20:
        report_lines.append(f"| ... | 共 {len(findings)} 条，仅展示前20条 | ... | ... |")
    report_lines.append("")
    
    if iocs.get("ips") or iocs.get("urls"):
        report_lines.append("## 🌐 威胁情报指标 (IOC)")
        if iocs.get("ips"):
            report_lines.append("### 可疑 IP 地址")
            for ip in iocs["ips"][:10]:
                report_lines.append(f"- `{ip}`")
        if iocs.get("urls"):
            report_lines.append("### 可疑 URL")
            for url in iocs["urls"][:10]:
                report_lines.append(f"- `{url}`")
        report_lines.append("")
    
    report_lines.append("## 🛠️ 处置建议")
    if "SQL注入" in attack_counter:
        report_lines.append("- **SQL注入**: 建议部署 WAF 规则，对输入进行严格过滤，升级数据库访问权限。")
    if "XSS或路径遍历" in attack_counter:
        report_lines.append("- **XSS/路径遍历**: 对输出进行编码，限制目录访问权限，禁用危险函数。")
    if "命令注入/RCE" in attack_counter:
        report_lines.append("- **命令注入**: 避免使用系统命令调用，使用安全的 API 替代，严格校验输入。")
    if "扫描器行为" in attack_counter:
        report_lines.append("- **扫描器**: 建议启用 IDS/IPS，封锁恶意源 IP，加强访问控制。")
    if "WebShell特征" in attack_counter:
        report_lines.append("- **WebShell**: 立即隔离受影响主机，检查文件完整性，排查后门。")
    if not any(k in attack_counter for k in ["SQL注入", "XSS或路径遍历", "命令注入/RCE", "扫描器行为", "WebShell特征"]):
        report_lines.append("- 建议持续监控，确保日志记录完整，定期审计安全策略。")
    report_lines.append("")
    
    report_lines.append("---")
    report_lines.append("*本报告由 AI 安全日志分析系统自动生成，仅供参考。请结合人工研判确认。*")
    
    return "\n".join(report_lines)

# ---------- 主入口（支持进度回调）----------
def analyze_logs(log_content: str, log_source: str = "unknown", progress_callback: Optional[Callable] = None) -> str:
    if not log_content:
        return "日志内容为空。"

    total_steps = 5
    if progress_callback:
        progress_callback("Stats", 1, total_steps, "正在生成日志统计...")
    
    log_stats = generate_log_stats(log_content)
    iocs = extract_iocs(log_content)
    
    if progress_callback:
        progress_callback("Splitting", 2, total_steps, "正在切分日志...")
    chunks = split_logs(log_content)
    if not chunks:
        return "❌ 无法切分日志内容。"

    if progress_callback:
        progress_callback("Mapping", 3, total_steps, f"并行分析 {len(chunks)} 个块...")
    findings = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_chunk = {executor.submit(analyze_chunk, chunk): chunk for chunk in chunks}
        for future in as_completed(future_to_chunk):
            result = future.result()
            if result:
                findings.append(result)

    if progress_callback:
        progress_callback("Reducing", 4, total_steps, f"汇总 {len(findings)} 个结果...")
    final_report = reduce_reports(findings, log_stats, iocs)

    if progress_callback:
        progress_callback("Completed", 5, total_steps, "分析完成！")
    return final_report
