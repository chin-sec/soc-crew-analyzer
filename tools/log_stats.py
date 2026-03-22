import re
import logging
from collections import Counter

logger = logging.getLogger(__name__)

def generate_log_stats(log_content: str) -> str:
    """
    使用 Python 正则和统计库，快速提取日志的关键指标。
    这些指标将作为“上下文”提供给 LLM，提高分析准确性。
    """
    stats = []
    
    # 1. 统计总行数
    lines = log_content.splitlines()
    stats.append(f"📊 **日志概览**: 共 {len(lines)} 行")
    
    # 2. 提取状态码分布 (假设是 Access Log，匹配 " 200 ", " 404 " 等)
    status_codes = re.findall(r'" (\d{3}) ', log_content)
    if status_codes:
        counter = Counter(status_codes)
        top_codes = counter.most_common(5)
        codes_str = ", ".join([f"{code}: {count}次" for code, count in top_codes])
        stats.append(f"🔢 **HTTP 状态码 Top5**: {codes_str}")
        
        # 特别警告：如果有大量 4xx 或 5xx
        errors_4xx = sum(c for s, c in counter.items() if s.startswith('4'))
        errors_5xx = sum(c for s, c in counter.items() if s.startswith('5'))
        if errors_4xx > len(lines) * 0.1:
            stats.append("⚠️ **警告**: 4xx 错误率超过 10%，可能存在扫描行为。")
        if errors_5xx > 0:
            stats.append("🔴 **严重**: 检测到服务器内部错误 (5xx)。")

    # 3. 提取 Top IP (假设 IP 在行首或特定位置，这里用通用正则匹配 IPv4)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_content)
    if ips:
        top_ips = Counter(ips).most_common(3)
        ips_str = ", ".join([f"{ip} ({count}次)" for ip, count in top_ips])
        stats.append(f"🌐 **高频访问 IP Top3**: {ips_str}")

    # 4. 检测常见攻击特征 (简单正则预检)
    sql_patterns = re.findall(r"(union\s+select|or\s+1=1|drop\s+table)", log_content, re.IGNORECASE)
    if sql_patterns:
        stats.append(f"🚨 **疑似 SQL 注入**: 检测到 {len(sql_patterns)} 处可疑特征！")
        
    xss_patterns = re.findall(r"(<script|javascript:|onerror=)", log_content, re.IGNORECASE)
    if xss_patterns:
        stats.append(f"🚨 **疑似 XSS 攻击**: 检测到 {len(xss_patterns)} 处可疑特征！")

    return "\n".join(stats)
