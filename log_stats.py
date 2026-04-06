import re
import logging
from collections import Counter
from typing import Dict, List
logger = logging.getLogger(__name__)

def generate_log_stats(log_content: str) -> str:
    """使用 Python 正则和统计库，快速提取日志的关键指标。"""
    stats = []
    lines = log_content.splitlines()
    stats.append(f"📊 **日志概览**: 共 {len(lines)} 行")

    # 2. 提取状态码分布 (假设是 Access Log)
    status_codes = re.findall(r'" (\d{3}) ', log_content)
    if status_codes:
        counter = Counter(status_codes)
        top_codes = counter.most_common(5)
        codes_str = ", ".join([f"{code}: {count}次" for code, count in top_codes])
        stats.append(f"🔢 **HTTP 状态码 Top5**: {codes_str}")
        
        errors_4xx = sum(c for s, c in counter.items() if s.startswith('4'))
        errors_5xx = sum(c for s, c in counter.items() if s.startswith('5'))
        if errors_4xx > len(lines) * 0.1:
            stats.append("⚠️ **警告**: 4xx 错误率超过 10%，可能存在扫描行为。")
        if errors_5xx > 0:
            stats.append("🔴 **严重**: 检测到服务器内部错误 (5xx)。")

    # 3. 提取 Top IP
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_content)
    if ips:
        top_ips = Counter(ips).most_common(3)
        ips_str = ", ".join([f"{ip} ({count}次)" for ip, count in top_ips])
        stats.append(f"🌐 **高频访问 IP Top3**: {ips_str}")

    # 4. 检测常见攻击特征
    sql_patterns = re.findall(r"(union\s+select|or\s+1=1|drop\s+table)", log_content, re.IGNORECASE)
    if sql_patterns:
        stats.append(f"🚨 **疑似 SQL 注入**: 检测到 {len(sql_patterns)} 处可疑特征！")
    xss_patterns = re.findall(r"(<script|javascript:|onerror=)", log_content, re.IGNORECASE)
    if xss_patterns:
        stats.append(f"🚨 **疑似 XSS 攻击**: 检测到 {len(xss_patterns)} 处可疑特征！")
    
    return "\n".join(stats)

# 这是 advanced_analyzer.py 正在寻找的函数
def extract_iocs(log_content: str) -> Dict[str, List[str]]:
    """
    占位函数：提取威胁情报指标 (IP, URL, Domain)。
    先实现基础功能防止报错，后续可以优化正则。
    """
    # 简单的正则匹配 IP 和 URL
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    url_pattern = r'https?://[^\s]+'
    
    ips = re.findall(ipv4_pattern, log_content)
    urls = re.findall(url_pattern, log_content)
    
    # 去重
    return {
        "ips": list(set(ips)),
        "urls": list(set(urls)),
        "domains": []
    }
