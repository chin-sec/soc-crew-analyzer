import json
import logging
from typing import Optional, Dict, Any
from crewai import Crew, Agent, Task, Process
from config import Config
from advanced_analyzer import AdvancedLogAnalyzer
from rag_engine import RAGEngine
from soc_tools import VirusTotalTool, WhoisTool

logger = logging.getLogger(__name__)


class SOCCrew:
    """
    生产级SOC Agent编排
    核心变更：
    1. Parser Agent → 改为 LogAnalyzerAgent，直接消费AdvancedLogAnalyzer的严格JSON输出
    2. Hunter Agent → 仅接收结构化IOC字典，不再解析Markdown
    3. Reporter Agent → 唯一负责生成人类可读报告的节点
    4. 所有Agent间传递数据均为JSON Schema契约
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.rag_engine = RAGEngine(config=self.config)
        self.analyzer = AdvancedLogAnalyzer(config=self.config, rag_engine=self.rag_engine)

        self.vt_tool = VirusTotalTool()
        self.whois_tool = WhoisTool()

    def _build_agents(self) -> Dict[str, Agent]:
        """构建Agent实例，每个Agent有明确的角色边界和输出契约"""
        return {
            "log_analyzer": Agent(
                role="日志分析引擎适配器",
                goal=(
                    "调用AdvancedLogAnalyzer对原始日志执行三层漏斗分析，"
                    "将返回的严格JSON结果原样传递给下游Agent，不做任何格式转换或总结。"
                ),
                backstory=(
                    "你是SOC自动化流水线的第一环。你的唯一职责是确保分析引擎的"
                    "结构化输出完整、无损地流入威胁狩猎环节。你不生成自然语言报告。"
                ),
                verbose=False,
                allow_delegation=False,
            ),
            "hunter": Agent(
                role="威胁狩猎分析师",
                goal=(
                    "基于上游传入的结构化IOC列表，自动调用VirusTotal和WHOIS工具进行情报富化，"
                    "并将富化结果以JSON格式附加到每个事件上。"
                ),
                backstory=(
                    "你是SOC的威胁猎手。你只处理结构化数据，从不解析自由文本。"
                    "你的输出必须是包含情报富化结果的JSON，供报告Agent消费。"
                ),
                tools=[self.vt_tool, self.whois_tool],
                verbose=True,
                allow_delegation=False,
            ),
            "reporter": Agent(
                role="安全事件报告生成器",
                goal=(
                    "将带有情报富化的结构化事件JSON转换为符合SOC运营规范的中文Markdown报告，"
                    "包含MITRE ATT&CK映射、处置建议和风险评级。"
                ),
                backstory=(
                    "你是SOC的最终输出关口。你将机器可读的JSON转化为人类可读的专业报告。"
                    "报告中所有事实必须严格来源于输入JSON，不得编造IOC或MITRE ID。"
                ),
                verbose=False,
                allow_delegation=False,
            ),
        }

    def _build_tasks(self, agents: Dict[str, Agent], log_content: str) -> list[Task]:
        """
        构建任务链，每个Task的expected_output明确定义JSON Schema契约
        """
        return [
            Task(
                description=(
                    "对以下原始日志执行自动化分析，返回完整的分析结果JSON。\n\n"
                    f"原始日志（前5000字符预览）:\n{log_content[:5000]}...\n\n"
                    "注意：日志可能很长，分析引擎内部已做分块+聚类处理，你只需传入完整内容即可。"
                ),
                expected_output=(
                    "严格JSON对象，包含字段: summary(str), events(list), "
                    "total_chunks_processed(int), suspicious_chunks(int), clustered_events(int)。"
                    "events中每个元素必须包含: cluster_id, is_threat, attack_type, mitre_id, "
                    "tactic, technique_name, confidence, evidence, recommendation, iocs(list)。"
                    "不要包含任何Markdown标记或额外解释文字。"
                ),
                agent=agents["log_analyzer"],
                callback=lambda _: self._run_analysis(log_content),
            ),
            Task(
                description=(
                    "接收上游LogAnalyzerAgent输出的JSON，遍历events列表中is_threat=true的事件，"
                    "对其中的IP、Domain、Hash类IOC调用VirusTotal和WHOIS工具进行情报富化。"
                ),
                expected_output=(
                    "严格JSON对象，结构与上游输入相同，但每个threat事件的iocs列表中"
                    "每项IOC增加vt_result(dict)和whois_result(dict)字段（可为null）。"
                    "未查询到的IOC保留原始结构，不删除。不要包含Markdown。"
                ),
                agent=agents["hunter"],
                context=[],
            ),
            Task(
                description=(
                    "将带有情报富化的事件JSON转换为SOC标准中文Markdown报告。"
                    "报告须包含：事件概述、MITRE ATT&CK矩阵映射表、各事件详情（含IOC+情报）、"
                    "综合处置建议、风险评级。"
                ),
                expected_output="格式规范的中文Markdown安全事件分析报告",
                agent=agents["reporter"],
                context=[],
            ),
        ]

    def _run_analysis(self, log_content: str) -> str:
        """
        将AdvancedLogAnalyzer的Python返回值序列化为JSON字符串
        作为LogAnalyzerAgent Task的实际输出，LLM不参与分析过程
        """
        try:
            result = self.analyzer.analyze_logs(log_content)
            output = json.dumps(result, ensure_ascii=False, indent=2)
            logger.info(f"[SOCCrew] 分析完成: {result.get('summary', '')}")
            return output
        except Exception as e:
            logger.error(f"[SOCCrew] 分析引擎异常: {e}", exc_info=True)
            error_result = {
                "summary": f"分析引擎执行失败: {str(e)}",
                "events": [],
                "error": str(e)
            }
            return json.dumps(error_result, ensure_ascii=False)

    def run(self, log_content: str) -> str:
        """
        主入口：执行完整SOC分析流水线
        Returns: Markdown格式的安全事件报告
        """
        agents = self._build_agents()
        tasks = self._build_tasks(agents, log_content)

        tasks[1].context = [tasks[0]]
        tasks[2].context = [tasks[1]]

        crew = Crew(
            agents=list(agents.values()),
            tasks=tasks,
            process=Process.sequential,
            verbose=False,
        )

        try:
            final_report = crew.kickoff()
            return str(final_report)
        except Exception as e:
            logger.error(f"[SOCCrew] Crew执行失败: {e}", exc_info=True)
            return f"# ❌ SOC分析流水线执行失败\n\n**错误信息**: {str(e)}\n\n请检查日志获取详细堆栈。"
