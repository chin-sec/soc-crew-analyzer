import re
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import unquote
import base64
import html


# ==================== IOC正则定义====================
_IOC_PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:com|net|org|io|cn|ru|tk|xyz|top|info|biz|cc|me|co|dev|app|cloud)\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'https?://[^\s<>"\'\)\]\}]+', re.IGNORECASE
    ),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),
    "user_agent": re.compile(
        r'(?:User-Agent|user-agent):\s*(.{10,200})', re.IGNORECASE
    ),
    "process": re.compile(
        r'(?:[A-Z]:\\[^\s]*\.(?:exe|dll|bat|ps1|vbs|scr)|'
        r'/[a-zA-Z0-9_./\-]+\.(?:sh|py|pl|rb|elf))\b'
    ),
    "registry": re.compile(
        r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s"\']+', re.IGNORECASE
    ),
    "mutex": re.compile(
        r'\\BaseNamedObjects\\[^\s"\'\\]+', re.IGNORECASE
    ),
}

_FALSE_POSITIVE_DOMAINS = {
    "localhost", "example.com", "test.local", "internal.corp",
    "google.com", "microsoft.com", "apple.com", "amazonaws.com"
}


def _decode_payload(text: str) -> str:
    """递归解码：URL → HTML实体 → Base64（仅尝试一次）"""
    decoded = text
    for _ in range(3):
        new = unquote(decoded)
        if new == decoded:
            break
        decoded = new
    decoded = html.unescape(decoded)
    b64_match = re.search(r'[A-Za-z0-9+/]{20,}={0,2}', decoded)
    if b64_match:
        try:
            b64_decoded = base64.b64decode(b64_match.group()).decode("utf-8", errors="ignore")
            if b64_decoded.isprintable():
                decoded = decoded.replace(b64_match.group(), b64_decoded)
        except Exception:
            pass
    return decoded


def extract_iocs(text: str, context_window: int = 80) -> List[Dict[str, Any]]:
    """
    从文本中提取多维度IOC
    Args:
        text: 原始日志/文本
        context_window: IOC前后截取的上下文字符数
    Returns:
        结构化IOC列表，每项包含 type/value/confidence/context
    """
    if not text or not text.strip():
        return []

    decoded_text = _decode_payload(text)
    results: List[Dict[str, Any]] = []
    seen_values = set()

    for ioc_type, pattern in _IOC_PATTERNS.items():
        for match in pattern.finditer(decoded_text):
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip().rstrip(".,;:)")

            # 去重
            norm_value = value.lower()
            dedup_key = f"{ioc_type}:{norm_value}"
            if dedup_key in seen_values:
                continue

            # 域名误报过滤
            if ioc_type == "domain" and norm_value in _FALSE_POSITIVE_DOMAINS:
                continue

            # Hash长度二次校验（防止颜色码等误匹配）
            if ioc_type in ("md5", "sha1", "sha256"):
                expected_len = {"md5": 32, "sha1": 40, "sha256": 64}[ioc_type]
                if len(value) != expected_len:
                    continue

            # 提取上下文片段
            start = max(0, match.start() - context_window)
            end = min(len(decoded_text), match.end() + context_window)
            context_snippet = decoded_text[start:end].replace("\n", " ").strip()

            results.append({
                "type": ioc_type,
                "value": value,
                "confidence": 0.9 if ioc_type in ("sha256", "sha1", "md5") else 0.7,
                "context": context_snippet
            })
            seen_values.add(dedup_key)

    return results


def get_ioc_summary(iocs: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """将结构化IOC列表转为按类型分组的纯值字典（供Agent工具调用）"""
    summary: Dict[str, List[str]] = {}
    for ioc in iocs:
        t = ioc["type"]
        if t not in summary:
            summary[t] = []
        if ioc["value"] not in summary[t]:
            summary[t].append(ioc["value"])
    return summary
