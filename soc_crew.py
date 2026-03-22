import os
from crewai import Agent, Task, Crew, Process, LLM  
from dotenv import load_dotenv
from soc_tools import rag_search_tool, log_preprocess_tool

load_dotenv()

# 2. 获取配置
API_KEY = os.getenv("DASHSCOPE_API_KEY")
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1" 
MODEL_NAME = os.getenv("MODEL_NAME", "qwen-plus")

if not API_KEY:
    raise ValueError("❌ 致命错误：找不到 DASHSCOPE_API_KEY 环境变量")

print(f"✅ 正在初始化 CrewAI 原生 LLM: {MODEL_NAME} @ {BASE_URL}")

# 3. 配置 LLM
llm = LLM(
    model=MODEL_NAME,
    base_url=BASE_URL,
    api_key=API_KEY
)

def create_soc_crew():
    # ================= 1. 定义 Agent =================
    
    parser_agent = Agent(
        role="高级安全日志分析师 (Senior Security Log Analyst)",
        goal="清洗原始日志，提取关键统计数据和 IOC (指标)。",
        backstory="你拥有 10 年 SOC 经验，擅长从海量噪声中快速提取关键信息。",
        verbose=True,
        allow_delegation=False,
        tools=[log_preprocess_tool], 
        llm=llm
    )

    hunter_agent = Agent(
        role="高级威胁猎手 (Senior Threat Hunter)",
        goal="基于分析师提供的信息，利用 RAG 检索深度挖掘攻击证据。",
        backstory="你是网络威胁情报专家，擅长攻击链分析。",
        verbose=True,
        allow_delegation=False,
        tools=[rag_search_tool], 
        llm=llm
    )

    reporter_agent = Agent(
        role="高级安全报告专家 (Senior Security Report Specialist)",
        goal="汇总所有发现，生成一份符合生产环境标准的、专业的简体中文 SOC 分析报告。",
        backstory="""
        你是某大型互联网公司的首席安全官 (CSO) 核心助手。
        你拥有 15 年网络安全运营经验，撰写过数百份重大安全事件报告。
        
        【核心能力】：
        - 精通 MITRE ATT&CK 框架，能准确映射攻击技术。
        - 擅长用清晰、专业的**简体中文**撰写报告，严禁无意义的英文混用（IP、哈希、T-Code 除外）。
        - 熟悉企业安全合规要求，报告结构严谨、逻辑清晰。
        
        【工作原则】：
        - 数据驱动：所有结论必须基于日志证据。
        - 行动导向：建议必须具体、可执行。
        - 读者友好：高管摘要要简明扼要，技术分析要详实深入。
        """,
        verbose=True,
        allow_delegation=False,
        tools=[], 
        llm=llm
    )

    # ================= 2. 定义 Tasks =================
    
    task_preprocess = Task(
        description="""
        1. 接收任务输入的原始日志内容 (log_content)。
        2. **重要策略**: 
           - 如果日志内容非常长 (超过 10000 字符)，**不要**直接将全部内容传给工具。
           - 请先读取日志的**前 50 行**和**后 50 行**，以及中间包含 'error', 'failed', 'attack' 等关键词的片段，组合成一个新的字符串传给工具。
           - 你的目标是提取统计特征和 IOC，不需要逐行分析所有数据。
        3. 使用 'Log Preprocessor & IOC Extractor' 工具对筛选后的日志进行分析。
        4. 输出一份结构化的预处理摘要。
        """,
        expected_output="一份包含统计数字、IOC 列表和可疑片段的 Markdown 格式摘要。",
        agent=parser_agent,
        tools=[log_preprocess_tool]
    )

    task_hunt = Task(
        description="""
        1. 阅读 [高级安全日志分析师] 的输出结果，提取其中的高危 IP 和可疑特征。
        2. 针对每一个高危 IP，使用 'Log RAG Search' 工具进行深度检索。
           - **必须**使用上下文中的 `file_id` (即任务 ID) 作为检索范围。
           - 查询示例: "Show all activities for IP x.x.x.x", "Find failed login attempts for user admin"。
        3. 分析检索结果，判断攻击真实性，排除误报。
        4. 列出确认的攻击事件及其手法、时间线和证据。
        """,
        expected_output="一份详细的威胁分析报告，包含确认的攻击事件、IP、类型和证据。",
        agent=hunter_agent,
        context=[task_preprocess],
        tools=[rag_search_tool]
    )

    task_report = Task(
        description="""
        请综合 [高级安全日志分析师] 和 [高级威胁猎手] 的所有工作成果，撰写一份最终的《安全运营事件分析报告》。
        
        【至关重要要求】：
        1. **语言强制**：全文必须使用**简体中文**。除 IP 地址、哈希值、日志原文、MITRE T-Code 外，严禁出现英文句子。
        2. **格式要求**：输出标准 Markdown 格式，确保层级清晰。
        3. **内容结构**：必须严格包含以下六个章节：
        
        ---
        # 🛡️ 安全运营事件分析报告
        
        ## 1. 📋 事件概览 (Executive Summary)
        - **风险等级**: [🔴 高 / 🟠 中 / 🟢 低]
        - **事件简述**: 用 2-3 句话概括核心事件。
        - **关键结论**: 是否确认入侵？是否需要立即阻断？
        
        ## 2. 📊 统计数据分析
        - **日志概况**: 总行数、时间跨度。
        - **攻击源统计**: 唯一攻击 IP 数量、Top 5 活跃攻击 IP。
        - **受害资产**: 被攻击的目标 IP/主机数量、被尝试登录的用户名。
        - **攻击类型分布**: 主要攻击手法占比。
        
        ## 3. 🎯 详细攻击分析与时间线
        - **主要攻击源画像**: IP、归属地、行为特征。
        - **攻击时间线还原**: 按时间顺序描述攻击步骤 (T1, T2, T3...)。
        - **关键证据引用**: 摘录 2-3 条最具代表性的原始日志。
        
        ## 4. 🗺️ MITRE ATT&CK 映射
        | 战术阶段 (Tactic) | 技术名称 (Technique) | ID | 检测依据 |
        | :--- | :--- | :--- | :--- |
        | ... | ... | ... | ... |
        
        ## 5. 🛡️ 处置建议与防御措施
        - **🚨 立即行动**: 封禁 IP、重置密码、隔离主机。
        - **🔧 短期加固**: 优化 WAF 规则、关闭端口。
        - **🏗️ 长期建设**: 部署 EDR、常态化审计。
        
        ## 6. 📎 附录
        - 完整 IOC 列表。
        
        ---
        报告结束。
        """,
        expected_output="一份完整的、结构化的、专业级的简体中文 Markdown 安全分析报告。",
        agent=reporter_agent,
        context=[task_preprocess, task_hunt]
    )

    # ================= 3. 组建 Crew =================
    crew = Crew(
        agents=[parser_agent, hunter_agent, reporter_agent],
        tasks=[task_preprocess, task_hunt, task_report],
        process=Process.sequential,
        verbose=True,
        memory=False,
        cache=True
    )

    return crew
