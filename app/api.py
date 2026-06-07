import asyncio
import logging
import uuid
from enum import Enum
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from app.config import Config
from app.advanced_analyzer import AdvancedLogAnalyzer
from app.rag_engine import RAGEngine
from app.log_stats import extract_iocs

logger = logging.getLogger(__name__)
config = Config()

# ==================== 配置常量 ====================
MAX_LOG_SIZE_BYTES = config.MAX_LOG_SIZE_MB * 1024 * 1024
SUPPORTED_ENCODINGS = ["utf-8", "gbk", "latin-1"]

# 初始化全局分析器
_rag_engine = RAGEngine(config=config)
_analyzer = AdvancedLogAnalyzer(config=config, rag_engine=_rag_engine)


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ==================== 内存任务存储 ====================
_task_store: Dict[str, Dict[str, Any]] = {}
_TASK_STORE_LOCK = asyncio.Lock()


async def _update_task(task_id: str, **kwargs):
    async with _TASK_STORE_LOCK:
        if task_id in _task_store:
            _task_store[task_id].update(kwargs)


# ==================== 后台任务执行器 ====================
async def _run_analysis_only(task_id: str, text: str):
    """仅三层漏斗分析（无Agent编排）"""
    await _update_task(task_id, status=TaskStatus.RUNNING)
    try:
        result = await asyncio.to_thread(_analyzer.analyze_logs, text)
        await _update_task(task_id, status=TaskStatus.COMPLETED, result=result)
        logger.info(f"[API] 分析任务 {task_id} 完成: {result.get('summary', '')}")
    except Exception as e:
        logger.error(f"[API] 分析任务 {task_id} 失败: {e}", exc_info=True)
        await _update_task(
            task_id,
            status=TaskStatus.FAILED,
            error={"code": "ANALYSIS_FAILED", "detail": str(e)},
        )


async def _run_full_pipeline(task_id: str, text: str):
    """完整Agent编排（占位，可使用SOCCrew修复后再实现）"""
    await _update_task(task_id, status=TaskStatus.RUNNING)
    try:
        # TODO: 待SOCCrew修复后调用
        # 暂时返回未实现错误
        raise NotImplementedError("完整Agent编排尚未实现")
    except Exception as e:
        logger.error(f"[API] 完整流水线任务 {task_id} 失败: {e}", exc_info=True)
        await _update_task(
            task_id,
            status=TaskStatus.FAILED,
            error={"code": "PIPELINE_NOT_IMPLEMENTED", "detail": str(e)},
        )


# ==================== 辅助函数 ====================
def _decode_log_content(raw: bytes) -> str:
    """多编码容错解码"""
    for encoding in SUPPORTED_ENCODINGS:
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _validate_file(file: UploadFile) -> None:
    if not file.filename:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FILENAME", "detail": "上传文件缺少文件名"})


# ==================== FastAPI 应用 ====================
app = FastAPI(
    title="Production SOC Analysis API",
    description="三层漏斗日志分析 + Agent编排威胁狩猎 + 结构化IOC提取",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载静态文件（如果存在static目录）
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except RuntimeError:
    logger.warning("Static directory not found, skipping mount.")


@app.get("/", include_in_schema=False)
async def read_root():
    return FileResponse("static/index.html")


@app.post("/analyze", summary="三层漏斗日志分析（异步）")
async def analyze_logs(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    _validate_file(file)
    content = await file.read()
    if len(content) > MAX_LOG_SIZE_BYTES:
        max_mb = MAX_LOG_SIZE_BYTES // 1024 // 1024
        raise HTTPException(
            status_code=413,
            detail={"code": "FILE_TOO_LARGE", "detail": f"日志文件大小超过{max_mb}MB限制"},
        )
    text = _decode_log_content(content)
    task_id = str(uuid.uuid4())[:8]
    async with _TASK_STORE_LOCK:
        _task_store[task_id] = {"status": TaskStatus.PENDING, "created_at": asyncio.get_event_loop().time()}
    background_tasks.add_task(_run_analysis_only, task_id, text)
    return {"task_id": task_id, "status": TaskStatus.PENDING, "poll_url": f"/tasks/{task_id}"}


@app.post("/full-pipeline", summary="完整Agent编排分析（异步）")
async def full_pipeline(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    _validate_file(file)
    content = await file.read()
    if len(content) > MAX_LOG_SIZE_BYTES:
        max_mb = MAX_LOG_SIZE_BYTES // 1024 // 1024
        raise HTTPException(
            status_code=413,
            detail={"code": "FILE_TOO_LARGE", "detail": f"日志文件大小超过{max_mb}MB限制"},
        )
    text = _decode_log_content(content)
    task_id = str(uuid.uuid4())[:8]
    async with _TASK_STORE_LOCK:
        _task_store[task_id] = {"status": TaskStatus.PENDING, "created_at": asyncio.get_event_loop().time()}
    background_tasks.add_task(_run_full_pipeline, task_id, text)
    return {"task_id": task_id, "status": TaskStatus.PENDING, "poll_url": f"/tasks/{task_id}"}


@app.get("/tasks/{task_id}", summary="查询异步任务状态与结果")
async def get_task_status(task_id: str):
    async with _TASK_STORE_LOCK:
        task = _task_store.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail={"code": "TASK_NOT_FOUND", "detail": f"任务{task_id}不存在或已过期"})
    response = {"task_id": task_id, "status": task["status"]}
    if task["status"] == TaskStatus.COMPLETED:
        response["result"] = task.get("result")
    elif task["status"] == TaskStatus.FAILED:
        response["error"] = task.get("error")
    return response


@app.post("/extract-iocs", summary="轻量IOC提取（同步）")
async def extract_iocs_endpoint(file: UploadFile = File(...)):
    _validate_file(file)
    content = await file.read()
    ioc_max_size = 50 * 1024 * 1024
    if len(content) > ioc_max_size:
        raise HTTPException(
            status_code=413,
            detail={"code": "FILE_TOO_LARGE", "detail": "IOC提取端点限制50MB，请使用/analyze处理大文件"},
        )
    text = _decode_log_content(content)
    iocs = extract_iocs(text) 
    return {
        "total_iocs_found": len(iocs),
        "iocs": iocs,
    }


@app.exception_handler(HTTPException)
async def structured_http_exception_handler(request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        return JSONResponse(status_code=exc.status_code, content=detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": "HTTP_ERROR", "detail": str(detail)},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    logger.critical(f"[API] 未捕获异常: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"code": "INTERNAL_SERVER_ERROR", "detail": "服务内部错误，请联系管理员查看日志"},
    )
