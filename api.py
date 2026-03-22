import os
import time
import uuid
import threading
import logging
from typing import Dict, Optional, Callable
from datetime import datetime
from soc_crew import create_soc_crew
from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Body
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# ================= 日志配置 =================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("__main__")

# ================= 导入分析模块 =================
try:
    from simple_analyzer import analyze_log_text as analyze_log_text_func
    logger.info("✅ 成功加载 [Simple Analyzer]")
except ImportError as e:
    logger.warning(f"⚠️ 无法加载 Simple Analyzer: {e}")
    analyze_log_text_func = None

try:
    from advanced_analyzer import analyze_large_log as analyze_large_log_func
    logger.info("✅ 成功加载 [Advanced Analyzer] (支持 RAG)")
except ImportError as e:
    logger.warning(f"⚠️ 无法加载 Advanced Analyzer: {e}")
    analyze_large_log_func = None

# ================= 导入 RAG 引擎 (用于问答) =================
try:
    from rag_engine import rag_engine
    RAG_ENABLED = True
    logger.info("✅ RAG 问答引擎已就绪")
except ImportError as e:
    RAG_ENABLED = False
    logger.warning(f"⚠️ RAG 问答引擎未加载：{e}")
    rag_engine = None

# ================= 初始化 FastAPI 应用 =================
app = FastAPI(title="AI Log Security Analyzer", version="2.1-RAG")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ 确保 reports 目录存在
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

@app.get("/", response_class=HTMLResponse)
async def read_root():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"detail": "index.html not found"})

# ================= 全局任务存储 =================
TASK_POOL: Dict[str, dict] = {}
TASK_LOCK = threading.Lock()

def make_progress_callback(task_id: str):
    """
    创建一个闭包函数，用于在分析过程中更新 TASK_POOL 的进度
    """
    def callback(stage: str, current: int, total: int, msg: str):
        with TASK_LOCK:
            if task_id in TASK_POOL:
                TASK_POOL[task_id]["stage"] = stage
                TASK_POOL[task_id]["progress_current"] = current
                TASK_POOL[task_id]["progress_total"] = total
                TASK_POOL[task_id]["progress_msg"] = msg
                if total > 0:
                    TASK_POOL[task_id]["progress_percent"] = round((current / total) * 100, 1)
                else:
                    TASK_POOL[task_id]["progress_percent"] = 0
    return callback

def run_analysis_task(task_id: str, file_content: str, filename: str, is_large: bool):
    logger.info(f"🚀 [Task {task_id[:8]}] 开始后台分析...")
    
    with TASK_LOCK:
        TASK_POOL[task_id]["stage"] = "initializing"
        TASK_POOL[task_id]["progress_percent"] = 0
        TASK_POOL[task_id]["progress_msg"] = "准备启动..."

    try:
        result = ""
        progress_cb = make_progress_callback(task_id)
        
        if is_large:
            if not analyze_large_log_func:
                raise Exception("Advanced analyzer not loaded.")
            logger.info(f"🔴 [Task {task_id[:8]}] 高级模式 (Split-Map-Reduce + RAG)")
            result = analyze_large_log_func(file_content, file_id=task_id, progress_callback=progress_cb)
        else:
            if not analyze_log_text_func:
                raise Exception("Simple analyzer not loaded.")
            logger.info(f"🟢 [Task {task_id[:8]}] 简单模式")
            progress_cb("processing", 50, 100, "正在分析...")
            result = analyze_log_text_func(file_content)
            progress_cb("completed", 100, 100, "完成")
            
        with TASK_LOCK:
            TASK_POOL[task_id]["status"] = "completed"
            TASK_POOL[task_id]["result"] = result
            TASK_POOL[task_id]["end_time"] = time.time()
            TASK_POOL[task_id]["rag_indexed"] = is_large and RAG_ENABLED
            TASK_POOL[task_id]["progress_msg"] = "分析完成!"
            logger.info(f"🎉 [Task {task_id[:8]}] 分析完成!")
            
    except Exception as e:
        logger.error(f"❌ [Task {task_id[:8]}] 分析失败：{str(e)}", exc_info=True)
        with TASK_LOCK:
            TASK_POOL[task_id]["status"] = "failed"
            TASK_POOL[task_id]["error"] = str(e)
            TASK_POOL[task_id]["progress_msg"] = f"错误：{str(e)}"

def run_soc_analysis_task(task_id: str, file_content: str, filename: str):
    logger.info(f"🤖 [SOC Task {task_id[:8]}] 启动多智能体协作分析...")
    
    with TASK_LOCK:
        TASK_POOL[task_id]["stage"] = "initializing"
        TASK_POOL[task_id]["progress_msg"] = "正在组建 SOC 团队..."
        TASK_POOL[task_id]["progress_percent"] = 10

    try:
        if 'create_soc_crew' not in globals():
            raise ImportError("SOC Crew 模块未加载，无法执行多智能体分析。")

        crew = create_soc_crew()
        
        with TASK_LOCK:
            TASK_POOL[task_id]["stage"] = "analyzing"
            TASK_POOL[task_id]["progress_msg"] = "智能体正在协作分析中 (此过程可能较慢)..."
            TASK_POOL[task_id]["progress_percent"] = 30

        inputs = {
            "log_content": file_content,
            "file_id": task_id
        }
        
        result = crew.kickoff(inputs=inputs)
        final_report = result.raw
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"SOC_Report_{timestamp}_{task_id[:8]}.md"
        file_path = os.path.join(REPORTS_DIR, safe_filename)
        
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(final_report)
            logger.info(f"💾 [SOC Task {task_id[:8]}] 报告已保存至：{file_path}")
            download_url = f"/download_report/{safe_filename}"
        except Exception as save_err:
            logger.error(f"保存报告失败：{save_err}")
            download_url = None
        
        with TASK_LOCK:
            TASK_POOL[task_id]["status"] = "completed"
            TASK_POOL[task_id]["result"] = final_report
            TASK_POOL[task_id]["download_url"] = download_url  # ✅ 存储下载链接
            TASK_POOL[task_id]["end_time"] = time.time()
            TASK_POOL[task_id]["rag_indexed"] = True
            TASK_POOL[task_id]["progress_percent"] = 100
            TASK_POOL[task_id]["progress_msg"] = "SOC 分析完成!"
            
        logger.info(f"🎉 [SOC Task {task_id[:8]}] 分析完成!")
            
    except Exception as e:
        logger.error(f"❌ [SOC Task {task_id[:8]}] 分析失败：{str(e)}", exc_info=True)
        with TASK_LOCK:
            TASK_POOL[task_id]["status"] = "failed"
            TASK_POOL[task_id]["error"] = str(e)
            TASK_POOL[task_id]["progress_msg"] = f"SOC 分析错误：{str(e)}"
            TASK_POOL[task_id]["progress_percent"] = 100

@app.post("/analyze_soc")
async def analyze_file_soc(file: UploadFile = File(...)):
    logger.info(f"📥 收到 SOC 多智能体分析请求：{file.filename}")
    
    try:
        content_bytes = await file.read()
        log_content = content_bytes.decode("utf-8", errors="ignore")
        
        if not log_content.strip():
            raise HTTPException(status_code=400, detail="File is empty")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File read error: {str(e)}")

    task_id = str(uuid.uuid4())
    
    with TASK_LOCK:
        TASK_POOL[task_id] = {
            "status": "processing",
            "filename": file.filename,
            "size_mb": round(len(content_bytes) / (1024 * 1024), 2),
            "mode": "soc_multi_agent",
            "start_time": time.time(),
            "result": None,
            "error": None,
            "download_url": None,  # ✅ 初始化
            "rag_indexed": False,
            "stage": "initializing",
            "progress_percent": 0,
            "progress_msg": "准备启动 SOC 团队..."
        }
    
    thread = threading.Thread(
        target=run_soc_analysis_task,
        args=(task_id, log_content, file.filename)
    )
    thread.daemon = True
    thread.start()
    
    return {
        "task_id": task_id,
        "message": "SOC Multi-Agent Analysis started",
        "mode": "soc_multi_agent"
    }

# ================= API 路由 =================

@app.post("/analyze_async")
async def analyze_file_async(file: UploadFile = File(...)):
    if not analyze_log_text_func:
        raise HTTPException(status_code=500, detail="Server configuration error: No analyzer loaded.")

    logger.info(f"📥 收到异步分析请求：{file.filename}")
    
    try:
        content_bytes = await file.read()
        log_content = content_bytes.decode("utf-8", errors="ignore")
        file_size_mb = len(content_bytes) / (1024 * 1024)
        
        if not log_content.strip():
            raise HTTPException(status_code=400, detail="File is empty or unreadable")
            
    except Exception as e:
        logger.error(f"文件读取失败：{e}")
        raise HTTPException(status_code=500, detail=f"File read error: {str(e)}")

    is_large = len(log_content) > 800000  
    task_id = str(uuid.uuid4())
    
    with TASK_LOCK:
        TASK_POOL[task_id] = {
            "status": "processing",
            "filename": file.filename,
            "size_mb": round(file_size_mb, 2),
            "mode": "advanced" if is_large else "simple",
            "start_time": time.time(),
            "result": None,
            "error": None,
            "rag_indexed": False
        }
    
    thread = threading.Thread(
        target=run_analysis_task,
        args=(task_id, log_content, file.filename, is_large)
    )
    thread.daemon = True
    thread.start()
    
    logger.info(f"✅ 任务 {task_id[:8]} 已创建并启动 (模式：{'Advanced' if is_large else 'Simple'})")
    
    return {
        "task_id": task_id,
        "message": "Analysis started in background",
        "filename": file.filename,
        "size_mb": round(file_size_mb, 2),
        "estimated_mode": "advanced" if is_large else "simple",
        "hint": "Use GET /status/{task_id} to poll results"
    }

@app.get("/status/{task_id}")
async def get_task_status(task_id: str):
    with TASK_LOCK:
        task = TASK_POOL.get(task_id)
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return task

# ================= 下载报告接口 =================
@app.get("/download_report/{filename}")
async def download_report(filename: str):
    """提供报告文件下载"""
    file_path = os.path.join(REPORTS_DIR, filename)
    
    # 安全检查：防止目录遍历攻击
    if not os.path.abspath(file_path).startswith(os.path.abspath(REPORTS_DIR)):
        raise HTTPException(status_code=403, detail="Invalid filename")
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="报告文件未找到，可能已被清理或生成失败")
    
    return FileResponse(
        path=file_path,
        media_type="text/markdown",
        filename=filename,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ================= RAG 问答接口 =================
@app.post("/chat")
async def chat_with_log(
    task_id: str = Body(..., embed=True),
    question: str = Body(..., embed=True)
):
    if not RAG_ENABLED or not rag_engine:
        raise HTTPException(status_code=503, detail="RAG engine is not available")
    
    with TASK_LOCK:
        task = TASK_POOL.get(task_id)
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Task is still {task['status']}, please wait.")
    
    if not task.get("rag_indexed", False):
        raise HTTPException(status_code=400, detail="This task was processed in Simple Mode and does not have RAG index.")

    logger.info(f"💬 [Chat] 收到来自任务 {task_id[:8]} 的问题：{question[:50]}...")
    
    try:
        relevant_chunks = rag_engine.query(file_id=task_id, user_question=question, top_k=5)
        
        if not relevant_chunks:
            return {
                "answer": "未在日志中找到与该问题相关的信息。请尝试更换关键词。",
                "sources": []
            }
        
        context_parts = []
        for i, chunk in enumerate(relevant_chunks):
            context_parts.append(f"[片段 {i+1}]:\n{chunk['content']}")
        
        context = "\n\n---\n\n".join(context_parts)
        
        from simple_analyzer import call_llm
        
        prompt = f"""
        你是一名安全日志分析助手。
        基于以下检索到的日志片段，回答用户的问题。
        如果日志中没有相关信息，请诚实告知。
        
        【相关日志片段】:
        {context}
        
        【用户问题】:
        {question}
        
        请给出清晰、专业的回答。
        """
        
        answer = call_llm(prompt, system_prompt="你是安全日志助手，基于事实回答。")
        
        sources = [
            {
                "chunk_id": c['chunk_id'],
                "similarity": round(c['similarity_score'], 3),
                "preview": c['content'][:100] + "..." if len(c['content']) > 100 else c['content']
            }
            for c in relevant_chunks
        ]
        
        return {
            "answer": answer,
            "sources": sources,
            "task_id": task_id
        }
        
    except Exception as e:
        logger.error(f"Chat 处理失败：{e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")

@app.post("/analyze")
async def analyze_file_sync(file: UploadFile = File(...)):
    logger.info(f"📥 收到同步分析请求：{file.filename}")
    
    if not analyze_log_text_func:
        raise HTTPException(status_code=500, detail="Analyzer not loaded")

    try:
        content_bytes = await file.read()
        log_content = content_bytes.decode("utf-8", errors="ignore")
        
        logger.info("🟢 触发 [简单模式] (Sync)")
        result = analyze_log_text_func(log_content)
        
        return {
            "status": "completed",
            "filename": file.filename,
            "result": result
        }
        
    except Exception as e:
        logger.error(f"同步分析失败：{e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ================= 启动入口 =================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, timeout_keep_alive=300)
