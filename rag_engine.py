import logging
import time
import hashlib
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import chromadb
from chromadb.config import Settings
from openai import OpenAI

from config import Config

logger = logging.getLogger(__name__)

class RAGEngine:
    def __init__(self):
        logger.info("🚀 初始化 RAG 引擎...")
        
        # ✅ 确认配置加载
        if not Config.DASHSCOPE_API_KEY:
            raise ValueError("❌ 致命错误: Config 中缺少 DASHSCOPE_API_KEY")
        if not Config.DASHSCOPE_BASE_URL:
            raise ValueError("❌ 致命错误: Config 中缺少 DASHSCOPE_BASE_URL")
            
        self.client = OpenAI(
            api_key=Config.DASHSCOPE_API_KEY,
            base_url=Config.DASHSCOPE_BASE_URL, # ✅ 确保这里指向阿里云
            timeout=Config.REQUEST_TIMEOUT
        )
        
        self.chroma_client = chromadb.PersistentClient(path=Config.CHROMA_PERSIST_DIR)
        self.collection = self.chroma_client.get_or_create_collection(
            name=Config.COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"}
        )
        logger.info(f"✅ RAG 引擎初始化完成。Collection: {Config.COLLECTION_NAME}, BaseURL: {Config.DASHSCOPE_BASE_URL}")

    def get_embedding(self, text: str) -> List[float]:
        """获取单条文本的向量"""
        try:
            response = self.client.embeddings.create(
                model=Config.EMBEDDING_MODEL, # 例如 'text-embedding-v3'
                input=text
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"❌ Embedding 调用失败: {e}")
            # 如果是 403 错误，打印更明确的提示
            if "unsupported_country_region_territory" in str(e):
                logger.critical("🚫 检测到地域限制错误！请检查 base_url 是否配置为阿里云地址。")
            raise

    def _embed_batch(self, texts: List[str]) -> List[List[float]]:
        """
        【优化】并发计算 Embedding
        使用线程池并发调用 API，显著提升速度
        """
        if not texts:
            return []
            
        vectors = [None] * len(texts)
        # 对于小文件测试，10 个并发没问题；如果 Token 紧张，可降为 2-3
        max_workers = 10 
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {
                executor.submit(self.get_embedding, text): i 
                for i, text in enumerate(texts)
            }
            
            completed = 0
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    vectors[idx] = future.result()
                    completed += 1
                    if completed % 20 == 0:
                        logger.info(f"⏳ Embedding 进度：{completed}/{len(texts)}")
                except Exception as e:
                    logger.error(f"分块 {idx} 向量化失败: {e}")
                    # 失败时返回零向量占位，避免整个流程中断，但会影响检索质量
                    vectors[idx] = [0.0] * 1024 
                    
        return vectors

    def ingest_chunks(self, file_id: str, chunks: List[Dict[str, Any]], progress_callback=None) -> int:
        """
        【核心方法】接收已分好的 chunks 进行索引
        :param chunks: 列表，每项包含 {'text': str, 'metadata': dict}
        """
        if not chunks:
            return 0
            
        logger.info(f"📥 [RAG] 开始索引文件: {file_id} (共 {len(chunks)} 个分块)")
        
        ids = []
        documents = []
        metadatas = []
        
        for i, chunk in enumerate(chunks):
            c_id = f"{file_id}_chunk_{i}"
            ids.append(c_id)
            documents.append(chunk['text'])
            meta = chunk.get('metadata', {})
            meta['file_id'] = file_id
            meta['chunk_index'] = i
            metadatas.append(meta)
        
        if progress_callback:
            progress_callback(0, len(documents), "正在计算向量...")
            
        logger.info(f"⏳ [RAG] 并发计算 {len(documents)} 个分块的向量...")
        vectors = self._embed_batch(documents)
        
        if progress_callback:
            progress_callback(len(documents), len(documents), "向量计算完成，正在写入数据库...")

        try:
            self.collection.add(
                ids=ids,
                embeddings=vectors,
                documents=documents,
                metadatas=metadatas
            )
            logger.info(f"🎉 [RAG] 成功索引文件 {file_id}")
            return len(chunks)
        except Exception as e:
            logger.error(f"❌ [RAG] 写入 ChromaDB 失败: {e}")
            raise

    def ingest_file(self, file_id: str, log_content: str, progress_callback=None) -> int:
        """
        兼容旧接口：内部自动分块后调用 ingest_chunks
        """
        if not log_content:
            return 0
            
        chunks = []
        start_idx = 0
        text_len = len(log_content)
        
        # 简单按字符分块逻辑
        while start_idx < text_len:
            end_idx = start_idx + Config.CHUNK_SIZE
            if end_idx < text_len:
                # 尝试在换行符处截断，保持日志完整性
                last_newline = log_content.rfind('\n', start_idx, end_idx)
                if last_newline > start_idx:
                    end_idx = last_newline + 1
            
            chunk_text = log_content[start_idx:end_idx]
            if chunk_text.strip(): # 忽略空块
                chunks.append({
                    "text": chunk_text,
                    "metadata": {"start_char": start_idx}
                })
            
            start_idx = end_idx - Config.CHUNK_OVERLAP
            if start_idx <= 0: 
                start_idx = end_idx
                
        return self.ingest_chunks(file_id, chunks, progress_callback)

    def query(self, file_id: str, user_question: str, top_k: int = None) -> List[Dict[str, Any]]:
        """检索函数"""
        if top_k is None:
            top_k = Config.TOP_K_RESULTS
            
        logger.info(f"🔍 [RAG] 检索问题: '{user_question[:30]}...' (File: {file_id})")
        
        try:
            query_vector = self.get_embedding(user_question)
        except Exception as e:
            logger.error(f"问题向量化失败: {e}")
            return []
        
        try:
            results = self.collection.query(
                query_embeddings=[query_vector],
                n_results=top_k,
                where={"file_id": file_id},
                include=["documents", "metadatas", "distances"]
            )
        except Exception as e:
            logger.error(f"ChromaDB 查询失败: {e}")
            return []
        
        formatted_results = []
        if results['ids'] and results['ids'][0]:
            for i, doc_id in enumerate(results['ids'][0]):
                # 距离转相似度 (Cosine Distance: 0~2, 1-distance 近似相似度)
                dist = results['distances'][0][i] if results['distances'] else 0
                formatted_results.append({
                    "chunk_id": doc_id,
                    "content": results['documents'][0][i],
                    "metadata": results['metadatas'][0][i],
                    "similarity_score": 1 - dist if dist <= 2 else 0 
                })
        
        return formatted_results

    def delete_file_index(self, file_id: str):
        """删除指定文件的索引"""
        try:
            all_ids = self.collection.get(where={"file_id": file_id}, include=[])['ids']
            if all_ids:
                self.collection.delete(ids=all_ids)
                logger.info(f"🗑️ [RAG] 已删除文件 {file_id} 的索引 ({len(all_ids)} 个分块)")
            else:
                logger.warning(f"未找到文件 {file_id} 的索引")
        except Exception as e:
            logger.error(f"删除索引失败: {e}")

# 单例模式
rag_engine = RAGEngine()
