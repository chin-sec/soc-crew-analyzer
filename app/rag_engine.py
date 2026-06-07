import os 
import time 
import hashlib 
import threading 
from typing import Optional, List, Dict
import chromadb 
from chromadb.config import Settings 
import dashscope 
from dotenv import load_dotenv 
from config import Config 
from log_stats import extract_iocs


logger = logging.getLogger(__name__) 

class RAGEngine: 
    """RAG知识库引擎...""" 
    
    def __init__(self, config: Optional[Config] = None): 
        self.config = config or Config() 
        self._api_key = os.getenv("DASHSCOPE_API_KEY", "") 
        # ... (中间代码保持不变) ...
        
        self.client = chromadb.PersistentClient( 
            path=self.chroma_persist_dir, 
            settings=Settings(anonymized_telemetry=False) 
        ) 
        self.collection = self.client.get_or_create_collection( 
            name=self.chroma_collection_name, 
            metadata={"hnsw:space": "cosine"} 
        ) 
        
        # ✅ 移除了此处的 mitre_count 检查，因为它可能导致连接未建立就查询
        
        if not self._api_key: 
            raise ValueError("DASHSCOPE_API_KEY 未配置") 

        self.client = chromadb.PersistentClient(
            path=self.chroma_persist_dir,
            settings=Settings(anonymized_telemetry=False)
        )
        self.collection = self.client.get_or_create_collection(
            name=self.chroma_collection_name,
            metadata={"hnsw:space": "cosine"}
        )

        self._embed_semaphore = threading.Semaphore(5)
        self._embed_min_interval = 0.2
        self._last_embed_time = 0.0
        self._embed_lock = threading.Lock()

    # ==================== Embedding 限流调用 ====================

    def _call_embed_api(self, texts: list[str]) -> list[list[float]]:
        """
        带速率限制的Embedding API调用
        ✅ 修复：通过参数传递api_key，不再修改全局变量，线程安全
        """
        with self._embed_semaphore:
            with self._embed_lock:
                elapsed = time.time() - self._last_embed_time
                if elapsed < self._embed_min_interval:
                    time.sleep(self._embed_min_interval - elapsed)
                self._last_embed_time = time.time()

            response = dashscope.TextEmbedding.call(
                model=self.embedding_model,
                input=texts,
                dimension=self.embedding_dimension,
                api_key=self._api_key
            )
            if response.status_code != 200:
                raise Exception(
                    f"Embedding API error: {response.status_code} {response.message}"
                )
            return [item["embedding"] for item in response.output["embeddings"]]

    def _embed_batch(self, texts: list[str], batch_size: int = 20) -> list[list[float]]:
        """分批并发Embedding，每批内部受信号量限流保护"""
        all_embeddings = []
        batches = [texts[i:i + batch_size] for i in range(0, len(texts), batch_size)]

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_idx = {
                executor.submit(self._call_embed_api, batch): idx
                for idx, batch in enumerate(batches)
            }
            results = [None] * len(batches)
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                results[idx] = future.result()

        for batch_result in results:
            all_embeddings.extend(batch_result)
        return all_embeddings

    def _enhance_query(self, query: str) -> str:
        """SOC场景专用查询预处理，提升向量召回相关性"""
        if not query or not query.strip():
            return ""

        try:
            iocs = extract_iocs(query)
        except Exception:
            iocs = []

        if iocs:
            ioc_str = " ".join(iocs[:3])
            return f"{ioc_str} threat intelligence IOC malicious indicator"

        soc_keywords = [
            "attack", "vulnerability", "cve", "malware", "intrusion",
            "threat", "indicator", "exploit", "webshell", "injection"
        ]
        has_keyword = any(kw.lower() in query.lower() for kw in soc_keywords)
        if not has_keyword:
            return f"{query} cybersecurity threat analysis SOC"

        return query

    # ==================== 核心检索接口 ====================

    def query(self, file_id: Optional[str] = None, user_question: str = "", top_k: int = 5) -> dict:
        """语义检索接口，file_id可选，未传时使用default_file_id"""
        target_file_id = file_id or self.default_file_id

        if not user_question.strip():
            return {"documents": [], "message": "empty query"}

        enhanced = self._enhance_query(user_question)
        if not enhanced:
            return {"documents": [], "message": "empty query after enhancement"}

        try:
            query_embedding = self._call_embed_api([enhanced])[0]
        except Exception as e:
            print(f"[RAG] Embedding查询失败: {e}")
            return {"documents": [], "message": f"embedding error: {e}"}

        try:
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where={"file_id": target_file_id},
                include=["documents", "metadatas", "distances"]
            )
        except Exception as e:
            print(f"[RAG] ChromaDB查询失败: {e}")
            return {"documents": [], "message": f"chroma query error: {e}"}

        documents = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                documents.append({
                    "id": doc_id,
                    "content": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i]
                })

        return {"documents": documents, "file_id": target_file_id}


    def index_file(self, file_path: str, file_id: Optional[str] = None) -> dict:
        """索引文件到知识库，基于内容SHA256去重"""
        if not os.path.exists(file_path):
            return {"status": "error", "message": f"File not found: {file_path}"}

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        existing = self.collection.get(
            where={"content_hash": content_hash},
            limit=1
        )
        if existing and existing["ids"]:
            existing_file_id = existing["metadatas"][0].get("file_id", "unknown")
            return {
                "status": "skipped",
                "reason": "duplicate content",
                "file_id": existing_file_id,
                "content_hash": content_hash
            }

        target_file_id = file_id or self.default_file_id

        chunk_size = int(os.getenv("RAG_CHUNK_SIZE", "500"))
        chunk_overlap = int(os.getenv("RAG_CHUNK_OVERLAP", "50"))
        chunks = []
        start = 0
        while start < len(content):
            end = start + chunk_size
            chunks.append(content[start:end])
            start += chunk_size - chunk_overlap

        if not chunks:
            return {"status": "error", "message": "No chunks generated"}

        embeddings = self._embed_batch(chunks)

        ids = [f"{target_file_id}_chunk_{i}" for i in range(len(chunks))]
        metadatas = [
            {
                "file_id": target_file_id,
                "chunk_index": i,
                "content_hash": content_hash,
                "source": os.path.basename(file_path)
            }
            for i in range(len(chunks))
        ]

        self.collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=chunks,
            metadatas=metadatas
        )

        return {
            "status": "success",
            "file_id": target_file_id,
            "chunks": len(chunks),
            "content_hash": content_hash
        }

    # ==================== 索引管理 ====================

    def delete_by_file_id(self, file_id: str) -> dict:
        """按file_id删除知识库条目"""
        try:
            self.collection.delete(where={"file_id": file_id})
            return {"status": "success", "deleted_file_id": file_id}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def list_indexed_files(self) -> List[Dict]:
        """列出所有已索引的文件及其块数"""
        try:
            all_meta = self.collection.get(include=["metadatas"])
            file_stats = {}
            if all_meta and all_meta["metadatas"]:
                for meta in all_meta["metadatas"]:
                    fid = meta.get("file_id", "unknown")
                    if fid not in file_stats:
                        file_stats[fid] = {
                            "file_id": fid,
                            "chunks": 0,
                            "source": meta.get("source", ""),
                            "content_hash": meta.get("content_hash", "")
                        }
                    file_stats[fid]["chunks"] += 1
            return list(file_stats.values())
        except Exception as e:
            print(f"[RAG] list_indexed_files error: {e}")
            return []
