import os
import logging
import hashlib
import json
import time
from datetime import datetime
from fastapi import FastAPI, File, UploadFile, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Dict, Any, Callable

# --- 配置与初始化 ---
from config import LLM_MODEL, TEMPERATURE, MAX_TOKENS, CHUNK_SIZE, MAX_THREADS, CHUNK_OVERLAP
from llm_client import call_llm

# 动态导入 Advanced Analyzer
try:
    from advanced_analyzer import analyze_logs as analyze_large_log_func
    ADVANCED_ANALYZER_AVAILABLE = True
    logging.info("✅ Advanced Analyzer 模块加载成功")
except Exception as e:
    logging.error(f"❌ Advanced Analyzer 模块导入失败: {e}")
    ADVANCED_ANALYZER_AVAILABLE = False
    analyze_large_log_func = None

app = FastAPI()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- 挂载静态文件目录 ---
app.mount("/static", StaticFiles(directory="static"), name="static")
# --- 挂载下载目录，用于提供报告文件服务 ---
app.mount("/downloads", StaticFiles(directory="downloads"), name="downloads")

# 存储任务状态
task_status: Dict[str, Dict[str, Any]] = {}

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

# 同步分析接口（保留，但仅支持 advanced 模式）
@app.post("/analyze")
async def analyze_log(file: UploadFile = File(...), mode: str = "advanced"):
    content = await file.read()
    log_content = content.decode('utf-8')
    
    if mode == "advanced" and ADVANCED_ANALYZER_AVAILABLE:
        result = analyze_large_log_func(log_content, log_source=file.filename)
        return {"advanced_result": result}
    elif mode == "advanced" and not ADVANCED_ANALYZER_AVAILABLE:
        return JSONResponse(status_code=500, content={"error": "Advanced Analyzer 模块不可用"})
    else:
        return JSONResponse(status_code=400, content={"error": "仅支持 advanced 模式"})

# 异步分析接口
@app.post("/analyze_async")
async def analyze_log_async(background_tasks: BackgroundTasks, file: UploadFile = File(...), mode: str = "advanced"):
    # 强制要求 mode 为 advanced
    if mode != "advanced":
        return JSONResponse(status_code=400, content={"error": "仅支持 advanced 模式"})
    
    content = await file.read()
    log_content = content.decode('utf-8')
    task_id = hashlib.md5((file.filename + str(time.time())).encode()).hexdigest()
    
    task_status[task_id] = { 
        "status": "processing", 
        "progress": 0, 
        "total": 100, 
        "message": "任务初始化...",
        "result": None, 
        "created_at": datetime.now().isoformat() 
    }
    
    logging.info(f"📥 收到异步分析请求：{file.filename}, 模式: {mode}")
    
    # 进度回调函数
    def update_progress(step: str, current: int, total: int, message: str):
        percent = int(current / total * 100) if total > 0 else 0
        task_status[task_id]["progress"] = percent 
        task_status[task_id]["step"] = step 
        task_status[task_id]["message"] = message
        if current >= total:
            task_status[task_id]["status"] = "completed"
    
    background_tasks.add_task(run_analysis_task, task_id, log_content, file.filename, mode, update_progress)
    return {"task_id": task_id, "message": "任务创建成功"}

def run_analysis_task(task_id: str, log_content: str, filename: str, mode: str, progress_callback: Callable):
    try:
        logging.info(f"🚀 [Task {task_id}] 开始后台分析，模式：{mode}...")
        
        if mode != "advanced":
            task_status[task_id]["status"] = "failed"
            task_status[task_id]["message"] = "仅支持 advanced 模式"
            return
        
        if not ADVANCED_ANALYZER_AVAILABLE:
            error_msg = "Advanced Analyzer 模块不可用，请检查 advanced_analyzer.py 文件"
            logging.error(f"❌ [Task {task_id}] {error_msg}")
            task_status[task_id]["status"] = "failed"
            task_status[task_id]["message"] = error_msg
            task_status[task_id]["result"] = error_msg
            return
        
        # 高级模式：传入进度回调
        result = analyze_large_log_func(
            log_content, 
            log_source=filename,
            progress_callback=progress_callback
        )
        
        if isinstance(result, dict):
            result_str = json.dumps(result, ensure_ascii=False, indent=2)
        else:
            result_str = str(result)

        # --- 保存报告文件 ---
        os.makedirs("downloads", exist_ok=True)
        safe_filename = f"report_{task_id}.md"
        file_path = os.path.join("downloads", safe_filename)
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("# 网络安全日志分析报告\n\n")
            f.write(f"**任务ID**: {task_id}\n")
            f.write(f"**分析时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**源文件**: {filename}\n\n")
            f.write("---\n\n")
            f.write(result_str)

        download_url = f"/downloads/{safe_filename}"

        task_status[task_id]["status"] = "completed"
        task_status[task_id]["result"] = result_str
        task_status[task_id]["download_url"] = download_url
        task_status[task_id]["message"] = "分析完成！点击报告标签页查看结果。"
        
    except Exception as e:
        error_msg = f"分析失败：{str(e)}"
        logging.error(f"❌ [Task {task_id}] {error_msg}", exc_info=True)
        task_status[task_id]["status"] = "failed"
        task_status[task_id]["message"] = error_msg
        task_status[task_id]["result"] = error_msg

@app.get("/status/{task_id}")
async def get_task_status(task_id: str):
    if task_id not in task_status:
        return JSONResponse(status_code=404, content={"error": "任务不存在"})
    return task_status[task_id]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
