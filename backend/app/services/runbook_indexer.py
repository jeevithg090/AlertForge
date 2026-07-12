"""Runbook vector store — ChromaDB indexer + semantic search.

Indexes all markdown runbooks into ChromaDB using text-embedding-v4
(or sentence-transformers fallback). Provides semantic search for the
Investigation Agent's search_runbook tool.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentinelforge.runbook_indexer")

RUNBOOKS_DIR = os.environ.get("RUNBOOKS_DIR", "/runbooks")
CHROMA_DIR = os.environ.get("CHROMA_DIR", "/app/.chroma")
COLLECTION_NAME = "sentinelforge_runbooks"

_collection = None


def _get_collection():
    global _collection
    if _collection is not None:
        return _collection
    import chromadb

    client = chromadb.PersistentClient(path=CHROMA_DIR)
    _collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    return _collection


def _get_embeddings(texts: list[str]) -> list[list[float]]:
    """Get embeddings via a hosted embeddings API if the provider offers one, else a local sentence-transformers model."""
    from app.config import settings

    if settings.llm_enabled:
        try:
            return _qwen_embeddings(texts, settings)
        except Exception as exc:
            logger.warning("hosted embeddings failed (%s), falling back to sentence-transformers", exc)

    return _local_embeddings(texts)


def _qwen_embeddings(texts: list[str], settings) -> list[list[float]]:
    """Use DashScope text-embedding-v4 API."""
    import asyncio

    import aiohttp

    async def _fetch():
        async with aiohttp.ClientSession() as session:
            url = f"{settings.llm_base_url}/embeddings"
            headers = {"Authorization": f"Bearer {settings.llm_api_key}"}
            payload = {"model": settings.embedding_model, "input": texts}
            async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                data = await resp.json()
                return [item["embedding"] for item in data["data"]]

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, _fetch()).result()
        return loop.run_until_complete(_fetch())
    except Exception:
        return asyncio.run(_fetch())


def _local_embeddings(texts: list[str]) -> list[list[float]]:
    """Fallback: sentence-transformers on CPU."""
    try:
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer("all-MiniLM-L6-v2")
        embeddings = model.encode(texts, show_progress_bar=False)
        return embeddings.tolist()
    except Exception as exc:
        logger.warning("sentence-transformers failed (%s), using hash-based fallback", exc)
        # Last resort: deterministic pseudo-embeddings from text hash
        import hashlib

        result = []
        for text in texts:
            h = hashlib.sha256(text.encode()).digest()
            vec = [float(b) / 255.0 for b in h] * 12  # 384-dim
            result.append(vec[:384])
        return result


def _load_runbooks(directory: str) -> list[dict[str, str]]:
    """Load all .md files from the runbooks directory."""
    runbooks = []
    base = Path(directory)
    if not base.exists():
        logger.warning("Runbooks directory not found: %s", directory)
        return runbooks
    for md_file in base.rglob("*.md"):
        try:
            content = md_file.read_text(encoding="utf-8")
            title = content.split("\n")[0].lstrip("# ").strip()
            rel_path = str(md_file.relative_to(base))
            runbooks.append({
                "title": title,
                "content": content,
                "path": f"runbooks/{rel_path}",
                "category": md_file.parent.name,
            })
        except Exception as exc:
            logger.warning("Failed to load %s: %s", md_file, exc)
    return runbooks


async def index_runbooks(directory: str = RUNBOOKS_DIR) -> int:
    """Index all runbooks into ChromaDB. Returns count of indexed documents."""
    runbooks = _load_runbooks(directory)
    if not runbooks:
        logger.warning("No runbooks found to index")
        return 0

    collection = _get_collection()
    texts = [rb["content"] for rb in runbooks]
    embeddings = _get_embeddings(texts)

    ids = [f"runbook_{i}" for i in range(len(runbooks))]
    metadatas = [
        {"title": rb["title"], "path": rb["path"], "category": rb["category"]}
        for rb in runbooks
    ]

    collection.upsert(ids=ids, embeddings=embeddings, documents=texts, metadatas=metadatas)
    logger.info("Indexed %d runbooks into ChromaDB", len(runbooks))
    return len(runbooks)


async def search_runbooks(query: str, top_k: int = 3) -> list[dict[str, Any]]:
    """Semantic search over indexed runbooks."""
    collection = _get_collection()
    if collection.count() == 0:
        logger.info("No runbooks indexed — returning empty results")
        return []

    query_embedding = _get_embeddings([query])[0]
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=min(top_k, collection.count()),
        include=["metadatas", "distances", "documents"],
    )

    out = []
    for i in range(len(results["ids"][0])):
        meta = results["metadatas"][0][i]
        distance = results["distances"][0][i]
        doc = results["documents"][0][i] if results.get("documents") else ""
        out.append({
            "title": meta.get("title", ""),
            "path": meta.get("path", ""),
            "category": meta.get("category", ""),
            "relevance": round(1.0 - distance, 3),
            "summary": doc[:200] if doc else "",
        })
    return out


# CLI entry point
if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO)
    count = asyncio.run(index_runbooks())
    print(f"Indexed {count} runbooks")
