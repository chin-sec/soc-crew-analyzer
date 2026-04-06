import os
from dotenv import load_dotenv
load_dotenv()
from crewai import Agent, Task, Crew, Process
from pydantic import BaseModel
from soc_tools import WhoisSearchTool, VirusTotalSearchTool
from tools.log_tools import DeepLogAnalysisTool

# ================= RAG 配置 =================
try:
    from rag_engine import RAGEngine
    
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-v3")
    
    # 初始化 RAG 引擎
    rag_engine = RAGEngine() # 注意：RAGEngine 在 rag_engine.py 中已设计为单例或处理配置
    
    from crewai.tools import BaseTool
    from typing import Type

    class RAGInput(BaseModel):
        """RAG 搜索工具的输入模型"""
        query: str

    class RAGSearchTool(BaseTool):
        name: str = "Security Knowledge Search"
        description: str = "搜索内部知识库（CVE, ATT&CK, 历史案例）。输入应为关键词。"
        args_schema: Type[RAGInput] = RAGInput
        
        def _run(self, query: str) -> str:
            return rag_engine.query(query) if hasattr(rag_engine, 'query') else "RAG 未初始化或无结果"

    rag_tool = RAGSearchTool()
    
except ImportError as e:
    print(f"❌ 导入错误: {e}")
    rag_tool = None
    print("⚠️ 警告: rag_engine 未找到，将不使用 RAG 功能。")
except Exception as e:
    print(f"❌ 初始化错误: {e}")
    rag_tool = None
    print("⚠️ 警告: RAG 引擎初始化失败，将不使用 RAG 功能。")

# 初始化工具
deep_log_tool = DeepLogAnalysisTool()
whois_tool = WhoisSearchTool()
vt_tool = VirusTotalSearchTool()

tools_list = [deep_log_tool, whois_tool, vt_tool]
if rag_tool:
    tools_list.append(rag_tool)

# 1. 定义 Agents
parser_agent = Agent(
    role='高级日志解析与预处理专家',
    goal='利用高性能引擎从原始日志中提取关键威胁摘要，过滤噪音。',
    backstory='你擅长处理海量日志数据。你拥有一个强大的并行分析引擎，能够快速识别并提取出真正的威胁，忽略90%的正常流量。',
    verbose=True,
    allow_delegation=False,
    tools=[deep_log_tool] # 只给日志分析工具
)

hunter_agent = Agent(
    role='资深威胁猎手',
    goal='结合解析出的威胁摘要和外部情报，进行深度关联分析，确认攻击性质。',
    backstory='你拥有多年的应急响应经验。你擅长利用知识库和外部情报（WHOIS, VirusTotal）来验证初级分析师的发现。',
    verbose=True,
    allow_delegation=True,
    tools=[whois_tool, vt_tool] + ([rag_tool] if rag_tool else [])
)

responder_agent = Agent(
    role='安全响应与报告专家',
    goal='基于确认的威胁，生成可执行的事件响应报告和修复建议。',
    backstory='你是团队最后的防线。你的报告将被直接发送给 CISO。',
    verbose=True,
    allow_delegation=False,
    tools=[]
)

# 2. 定义 Tasks
task_parse = Task(
    description="""
    分析用户提供的原始日志数据。
    步骤：
    1. 必须使用 'Deep Log Analysis Engine' 工具处理输入的日志内容。
    2. 不要尝试自己阅读所有日志，信任工具的过滤和分片能力。
    3. 输出工具返回的【结构化威胁摘要】。
    4. 如果工具返回"未发现威胁"，则直接汇报无异常。
    
    输入日志: {log_content} # 修改点：改为 log_content 以匹配 API 传参
    """,
    expected_output="一份精简的威胁摘要，包含攻击类型、源IP、时间点和证据片段。如果无威胁，输出'无异常'。",
    agent=parser_agent
)

task_hunt = Task(
    description="""
    基于【前置任务】提供的威胁摘要进行深度调查。
    步骤：
    1. 如果前置任务结果为'无异常'，本任务直接结束，输出'经复核确认为误报或无威胁'。
    2. 如果有威胁，提取其中的关键实体（如 CVE 编号、攻击手法、恶意 IP、域名）。
    3. 对提取出的 IP 或域名，务必使用 'WHOIS Lookup' 和 'VirusTotal Threat Intelligence' 工具进行查询。
    4. (可选) 如果有 CVE 编号，使用 'Security Knowledge Search' 查询详情。
    5. 综合信息，判断攻击的成功概率和潜在影响。
    """,
    expected_output="详细的威胁分析报告，包含情报关联结果（WHOIS/VT数据）、攻击置信度（高/中/低）和潜在影响评估。",
    agent=hunter_agent,
    context=[task_parse]
)

task_respond = Task(
    description="""
    根据【威胁调查报告】生成最终的事件响应文档。
    步骤：
    1. 总结事件经过。
    2. 列出受影响的资产和账户。
    3. 提供具体的修复建议（如防火墙规则、补丁更新、账号封禁）。
    4. 格式要专业，适合向管理层汇报。
    """,
    expected_output="Markdown 格式的最终事件响应报告。",
    agent=responder_agent,
    context=[task_parse, task_hunt]
)

# 3. 组建 Crew
def create_soc_crew():
    return Crew(
        agents=[parser_agent, hunter_agent, responder_agent],
        tasks=[task_parse, task_hunt, task_respond],
        process=Process.sequential,
        verbose=True,
        memory=True
    )

def run_soc_analysis(log_content: str): # 修改点：函数接收 log_content
    crew = create_soc_crew()
    inputs = {"log_content": log_content} # 修改点：传入 log_content
    result = crew.kickoff(inputs=inputs)
    return result
