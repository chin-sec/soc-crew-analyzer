import os
import time
import logging
import hashlib
from functools import lru_cache
from typing import Optional, Dict, Any

import requests
from crewai_tools import BaseTool
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ==================== 基础限流器 ====================

class TokenBucketRateLimiter:
    """
    线程安全的令牌桶限流器
    用于控制外部API调用频率，避免触发429或账号封禁
    """
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def acquire(self) -> None:
        """阻塞等待直到获取到令牌"""
        while True:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            sleep_time = (1.0 - self.tokens) / self.rate
            time.sleep(max(0.05, sleep_time))


# ==================== VirusTotal Tool ====================

class VirusTotalInput(BaseModel):
    """CrewAI工具输入Schema - 必须与_run参数名完全一致"""
    ioc_value: str = Field(description="待查询的IOC值，如IP地址、域名或文件哈希")
    ioc_type: str = Field(description="IOC类型，仅限: ip, domain, hash")


class VirusTotalTool(BaseTool):
    name: str = "virus_total_lookup"
    description: str = (
        "查询IP、域名或文件哈希的VirusTotal威胁情报。"
        "输入ioc_value(字符串)和ioc_type(ip/domain/hash)。"
        "返回包含检测率、社区评分、关联样本的精简字典。失败时返回含error键的字典。"
    )
    args_schema: type[BaseModel] = VirusTotalInput

    _rate_limiter: TokenBucketRateLimiter = TokenBucketRateLimiter(rate=0.066, capacity=4)
    _CACHE_MAX_SIZE: int = 512
    _CACHE_TTL_SEC: int = 3600

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not self._api_key:
            logger.warning("[VirusTotalTool] VIRUSTOTAL_API_KEY 未配置，所有查询将返回降级结果")
        self._cache: Dict[str, tuple] = {}

    def _get_cached(self, key: str) -> Optional[Dict]:
        entry = self._cache.get(key)
        if entry and (time.time() - entry[0]) < self._CACHE_TTL_SEC:
            return entry[1]
        return None

    def _set_cached(self, key: str, value: Dict) -> None:
        if len(self._cache) >= self._CACHE_MAX_SIZE:
            sorted_keys = sorted(self._cache, key=lambda k: self._cache[k][0])
            for k in sorted_keys[:len(sorted_keys)//2]:
                del self._cache[k]
        self._cache[key] = (time.time(), value)

    def _run(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """
        CrewAI工具执行入口
        参数名必须与VirusTotalInput中的Field名完全匹配
        """
        ioc_type = ioc_type.strip().lower()
        cache_key = f"vt:{ioc_type}:{ioc_value}"

        cached = self._get_cached(cache_key)
        if cached is not None:
            logger.debug(f"[VT] 缓存命中: {ioc_value}")
            return cached

        if not self._api_key:
            return {"error": "VIRUSTOTAL_API_KEY未配置", "ioc_value": ioc_value}

        valid_types = {"ip", "domain", "hash"}
        if ioc_type not in valid_types:
            return {"error": f"不支持的ioc_type: {ioc_type}，仅支持{valid_types}", "ioc_value": ioc_value}

        endpoint_map = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc_value}",
            "hash": f"https://www.virustotal.com/api/v3/files/{ioc_value}",
        }
        url = endpoint_map[ioc_type]
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}

        self._rate_limiter.acquire()
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                result = {
                    "ioc_value": ioc_value,
                    "ioc_type": ioc_type,
                    "malicious_count": data.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious_count": data.get("last_analysis_stats", {}).get("suspicious", 0),
                    "community_score": data.get("reputation", 0),
                    "first_seen": data.get("first_submission_date"),
                    "tags": data.get("tags", [])[:10],
                }
            elif resp.status_code == 404:
                result = {"ioc_value": ioc_value, "ioc_type": ioc_type, "found": False, "malicious_count": 0}
            elif resp.status_code == 429:
                result = {"error": "VT API速率限制(429)，请稍后重试", "ioc_value": ioc_value}
            else:
                result = {"error": f"VT API返回{resp.status_code}", "ioc_value": ioc_value}
        except requests.Timeout:
            result = {"error": "VT API请求超时(15s)", "ioc_value": ioc_value}
        except Exception as e:
            result = {"error": f"VT查询异常: {str(e)}", "ioc_value": ioc_value}

        self._set_cached(cache_key, result)
        return result


# ==================== WHOIS Tool ====================

class WhoisInput(BaseModel):
    """CrewAI工具输入Schema"""
    domain: str = Field(description="待查询WHOIS信息的域名，不含协议和路径")


class WhoisTool(BaseTool):
    name: str = "whois_lookup"
    description: str = (
        "查询域名的WHOIS注册信息。"
        "输入domain(纯域名字符串)。"
        "返回注册人、创建时间、过期时间、NS服务器等精简字典。失败时返回含error键的字典。"
    )
    args_schema: type[BaseModel] = WhoisInput

    _rate_limiter: TokenBucketRateLimiter = TokenBucketRateLimiter(rate=2.0, capacity=5)
    _CACHE_MAX_SIZE: int = 256
    _CACHE_TTL_SEC: int = 7200  # WHOIS变更低频，缓存2小时

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._cache: Dict[str, tuple] = {}

    def _get_cached(self, key: str) -> Optional[Dict]:
        entry = self._cache.get(key)
        if entry and (time.time() - entry[0]) < self._CACHE_TTL_SEC:
            return entry[1]
        return None

    def _set_cached(self, key: str, value: Dict) -> None:
        if len(self._cache) >= self._CACHE_MAX_SIZE:
            sorted_keys = sorted(self._cache, key=lambda k: self._cache[k][0])
            for k in sorted_keys[:len(sorted_keys)//2]:
                del self._cache[k]
        self._cache[key] = (time.time(), value)

    @staticmethod
    def _clean_domain(domain: str) -> str:
        """去除协议、路径、端口，提取纯域名"""
        d = domain.strip().lower()
        for prefix in ("https://", "http://", "ftp://"):
            if d.startswith(prefix):
                d = d[len(prefix):]
        d = d.split("/")[0].split(":")[0]
        return d

    def _run(self, domain: str) -> Dict[str, Any]:
        clean_domain = self._clean_domain(domain)
        cache_key = f"whois:{clean_domain}"

        cached = self._get_cached(cache_key)
        if cached is not None:
            logger.debug(f"[WHOIS] 缓存命中: {clean_domain}")
            return cached

        self._rate_limiter.acquire()
        try:
            try:
                import whois as python_whois
                w = python_whois.whois(clean_domain)
                result = {
                    "domain": clean_domain,
                    "registrar": str(w.registrar or ""),
                    "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date or ""),
                    "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date or ""),
                    "name_servers": [str(ns).lower() for ns in (w.name_servers or [])][:5],
                    "status": str(w.status or ""),
                }
            except ImportError:
                rdap_url = f"https://rdap.org/domain/{clean_domain}"
                resp = requests.get(rdap_url, timeout=10, headers={"Accept": "application/rdap+json"})
                if resp.status_code == 200:
                    data = resp.json()
                    events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
                    ns_list = [n["ldhName"] for n in data.get("nameservers", []) if "ldhName" in n]
                    entities = data.get("entities", [])
                    registrar = ""
                    for ent in entities:
                        if "registrar" in ent.get("roles", []):
                            vcard = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
                            for item in vcard:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break
                            break
                    result = {
                        "domain": clean_domain,
                        "registrar": registrar,
                        "creation_date": events.get("registration", ""),
                        "expiration_date": events.get("expiration", ""),
                        "name_servers": ns_list[:5],
                        "status": str(data.get("status", [])),
                    }
                else:
                    result = {"error": f"RDAP返回{resp.status_code}", "domain": clean_domain}

        except requests.Timeout:
            result = {"error": "WHOIS查询超时(10s)", "domain": clean_domain}
        except Exception as e:
            result = {"error": f"WHOIS查询异常: {str(e)}", "domain": clean_domain}

        self._set_cached(cache_key, result)
        return result
