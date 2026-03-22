# test_soc_local.py
import os
import sys
import logging
from dotenv import load_dotenv
import uuid

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

if not os.getenv("DASHSCOPE_API_KEY"):
    print("❌ 错误: 未找到 DASHSCOPE_API_KEY。请检查 .env 文件。")
    sys.exit(1)

print("🚀 开始本地 SOC 多智能体测试...")
log_file_path = "data/security_logs.log"

if not os.path.exists(log_file_path):
    print(f"❌ 错误: 找不到文件 {log_file_path}")
    sys.exit(1)

with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
    log_content = f.read()

print(f"✅ 成功读取日志，大小: {len(log_content)} 字符，行数: {len(log_content.splitlines())}")

# --- 核心修复：智能索引逻辑 ---
from rag_engine import rag_engine

temp_task_id = str(uuid.uuid4())
print(f"🔧 正在为测试文件建立临时向量索引 (Task ID: {temp_task_id[:8]}...) ...")

def index_for_test(task_id, text):
    """
    尝试多种方法建立索引，确保兼容性
    """
    # 方法 1: 尝试调用 rag_engine 暴露的标准方法
    if hasattr(rag_engine, 'index_data'):
        logger.info("使用方法 1: rag_engine.index_data")
        rag_engine.index_data(task_id, text)
        return True
    
    if hasattr(rag_engine, 'index'):
        logger.info("使用方法 2: rag_engine.index")
        rag_engine.index(task_id, text)
        return True

    # 方法 2: 尝试导入 langchain_text_splitters 并手动操作 (需要确保已安装)
    try:
        from langchain_text_splitters import RecursiveCharacterTextSplitter
        logger.info("使用方法 3: 手动分块 + 内部 API 调用")
        
        splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
        chunks = splitter.split_text(text)
        
        # 获取 collection
        # 注意：这里假设 rag_engine 内部有一个 _get_or_create_collection 或类似方法
        # 如果 rag_engine 是封装好的类，可能需要访问其内部属性
        if hasattr(rag_engine, '_get_or_create_collection'):
            collection = rag_engine._get_or_create_collection(task_id)
        elif hasattr(rag_engine, 'client'):
             # 兼容某些直接暴露 client 的情况
             collection = rag_engine.client.get_or_create_collection(name=task_id)
        else:
            raise AttributeError("无法访问 Chroma Collection 创建方法")

        documents = []
        embeddings = []
        ids = []
        
        logger.info(f"正在处理 {len(chunks)} 个文本块...")
        
        # 复用 rag_engine 内部的 embedding 客户端
        # 假设 rag_engine 有 embeddings_client 属性
        if not hasattr(rag_engine, 'embeddings_client'):
             # 如果没有，尝试从 config 重新初始化一个 (兜底方案)
             from openai import OpenAI
             client = OpenAI(
                 api_key=os.getenv("DASHSCOPE_API_KEY"),
                 base_url=os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
             )
             embed_client = client
        else:
             embed_client = rag_engine.embeddings_client

        for i, chunk in enumerate(chunks):
            try:
                resp = embed_client.embeddings.create(
                    model=os.getenv("EMBEDDING_MODEL", "text-embedding-v2"),
                    input=chunk
                )
                vector = resp.data[0].embedding
                
                documents.append(chunk)
                embeddings.append(vector)
                ids.append(f"{task_id}_chunk_{i}")
                
                if (i + 1) % 20 == 0:
                    logger.info(f"已处理 {i+1}/{len(chunks)} ...")
            except Exception as e:
                logger.error(f"Embedding 失败: {e}")
                continue
        
        if documents:
            collection.add(
                documents=documents,
                embeddings=embeddings,
                ids=ids,
                metadatas=[{"task_id": task_id} for _ in range(len(documents))]
            )
            logger.info(f"✅ 索引建立成功！共存入 {len(documents)} 个片段。")
            return True
        else:
            raise Exception("没有成功生成任何向量片段。")

    except ImportError:
        print("❌ 缺少依赖: langchain-text-splitters。请运行: pip install langchain-text-splitters")
        return False
    except Exception as e:
        logger.error(f"手动索引失败: {e}")
        return False

# 执行索引
if not index_for_test(temp_task_id, log_content):
    print("\n💡 建议：先运行 Web 服务 (`python api.py`)，上传一次该文件，让 Web 服务自动建立索引。")
    print("   然后修改此脚本，注释掉索引部分，直接使用已存在的 Task ID。")
    sys.exit(1)

# --- 启动 CrewAI ---
print("\n🤖 正在组建 SOC 团队...")
try:
    from soc_crew import create_soc_crew
except ImportError as e:
    print(f"❌ 无法导入 soc_crew: {e}")
    print("请确保 soc_crew.py, soc_tools.py 在当前目录且无语法错误。")
    sys.exit(1)

crew = create_soc_crew()

print("🎬 演出开始！CrewAI 开始协作...\n")
print("-" * 50)

inputs = {
    "log_content": log_content,
    "file_id": temp_task_id
}

try:
    result = crew.kickoff(inputs=inputs)
    
    print("-" * 50)
    print("\n🎉 分析完成！\n")
    print("📝 === 最终报告预览 (前 2000 字符) ===\n")
    print(result.raw[:2000])
    if len(result.raw) > 2000:
        print("\n... (内容过长，已省略，请查看保存的文件)")
    
    output_file = "data/soc_report_output.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(result.raw)
    print(f"\n💾 完整报告已保存至: {output_file}")

except Exception as e:
    print(f"\n❌ 执行过程中出错：{e}")
    import traceback
    traceback.print_exc()
