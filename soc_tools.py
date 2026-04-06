import os
import requests
from typing import Optional, Dict, Any
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

# =================配置区域=================
# 如果你有 VirusTotal API Key，请在这里填写，否则将使用模拟模式
VIRUS_TOTAL_API_KEY = os.getenv("VT_API_KEY", "") 
# =========================================

def get_whois_info(target: str) -> str:
    """
    查询域名或IP的WHOIS注册信息。
    使用免费的 whoisxmlapi 或类似公共接口进行演示。
    注意：生产环境建议购买付费API或搭建本地Whois服务器。
    """
    if not target:
        return "目标不能为空"
    
    try:
        # 这里使用一个免费的演示接口 (whoisjs.com)，生产环境请替换为稳健的API
        # 如果 target 是 IP，whoisjs 也能处理
        url = f"https://api.whoisjs.com/?q={target}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            # 提取关键字段
            registrar = data.get('registrar', 'Unknown')
            creation_date = data.get('created', 'Unknown')
            expiry_date = data.get('expires', 'Unknown')
            name_servers = ", ".join(data.get('nameservers', []))
            
            return (f"WHOIS 查询结果 ({target}):\n"
                    f"- 注册商: {registrar}\n"
                    f"- 创建时间: {creation_date}\n"
                    f"- 过期时间: {expiry_date}\n"
                    f"-  Nameservers: {name_servers}")
        else:
            return f"WHOIS 查询失败: HTTP {response.status_code}"
            
    except Exception as e:
        return f"WHOIS 查询出错: {str(e)}"

def get_virus_total_info(target: str) -> str:
    """
    查询 VirusTotal 威胁情报。
    支持 IP、域名、URL 和 Hash。
    """
    if not target:
        return "目标不能为空"
    
    # 如果没有配置 API Key，返回模拟数据以便测试流程跑通
    if not VIRUS_TOTAL_API_KEY:
        return (f"[模拟模式 - 未配置 VT API Key] \n"
                f"目标: {target}\n"
                f"检测结果: 0/90 恶意 (模拟数据)\n"
                f"信誉评分: 未知\n"
                f"提示: 请在环境变量中设置 VT_API_KEY 以获取真实数据。")

    try:
        # 判断类型并选择端点 (简化版，主要支持 IP 和 Domain)
        # 实际生产中需要更复杂的类型检测
        endpoint = "https://www.virustotal.com/api/v3/ip_addresses" if "." in target and ":" not in target else "https://www.virustotal.com/api/v3/domains"
        
        headers = {
            "x-apikey": VIRUS_TOTAL_API_KEY
        }
        
        url = f"{endpoint}/{target}"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # 提取关键统计
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            
            reputation = attributes.get('reputation', 'N/A')
            
            return (f"VirusTotal 情报 ({target}):\n"
                    f"- 恶意检测数: {malicious}/90\n"
                    f"- 可疑检测数: {suspicious}\n"
                    f"- 安全检测数: {harmless}\n"
                    f"- 信誉评分: {reputation}\n"
                    f"- 结论: {'⚠️ 高危' if malicious > 2 else '✅ 相对安全'}")
        elif response.status_code == 404:
            return f"VirusTotal 未找到该记录 ({target})，可能是新出现的威胁或干净流量。"
        else:
            return f"VirusTotal 查询失败: HTTP {response.status_code}"
            
    except Exception as e:
        return f"VirusTotal 查询出错: {str(e)}"

# ================= CrewAI Tools 定义 =================

class WhoisSearchInput(BaseModel):
    target: str = Field(..., description="要查询的域名或IP地址，例如 'google.com' 或 '8.8.8.8'")

class WhoisSearchTool(BaseTool):
    name: str = "WHOIS Lookup"
    description: str = "查询域名或IP的注册信息、所有者和创建时间。用于判断域名的可信度。"
    args_schema: type[BaseModel] = WhoisSearchInput
    
    def _run(self, target: str) -> str:
        return get_whois_info(target)

class VirusTotalSearchInput(BaseModel):
    target: str = Field(..., description="要查询的 IP、域名、URL 或文件 Hash")

class VirusTotalSearchTool(BaseTool):
    name: str = "VirusTotal Threat Intelligence"
    description: str = "查询全球威胁情报数据库，判断 IP、域名或文件是否恶意。"
    args_schema: type[BaseModel] = VirusTotalSearchInput
    
    def _run(self, target: str) -> str:
        return get_virus_total_info(target)

# 导出函数供 soc_crew.py 直接导入使用
__all__ = ["get_whois_info", "get_virus_total_info", "WhoisSearchTool", "VirusTotalSearchTool"]
