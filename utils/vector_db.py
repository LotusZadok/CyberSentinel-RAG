# Tool for ingesting .json and .csv files into the Chroma vector store and performing semantic queries for CyberSentinel.

import os
import json
import pandas as pd
from chromadb import PersistentClient
from chromadb.utils import embedding_functions
from tqdm import tqdm

def get_embedder():
    return embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

def setup_vector_db(knowledge_base_dir="data/knowledge_base", persist_dir="data/vector_store", max_lines=None, fast=True):
    client = PersistentClient(path=persist_dir)
    try:
        collection = client.get_collection("cyber_kb")
        print("Using existing collection with its current embedding function")
    except ValueError:
        collection = client.create_collection("cyber_kb", embedding_function=get_embedder())
        print("Created new collection with SentenceTransformer embedding function")
    BATCH_SIZE = 10000 if fast else 1000
    files = [f for f in os.listdir(knowledge_base_dir) if f.endswith(('.json', '.csv'))]
    print(f"\nIngesting {len(files)} files from {knowledge_base_dir} using batch size {BATCH_SIZE}...\n")
    for fname in files:
        fpath = os.path.join(knowledge_base_dir, fname)
        print(f"Processing file: {fname}")
        if fname.endswith(".csv"):
            try:
                df = pd.read_csv(fpath)
                candidate_cols = [col for col in df.columns if any(keyword in col.lower() for keyword in ["desc", "summary", "name", "title"])]
                if not candidate_cols:
                    print(f"  Skipped: No usable text column found in {fname}")
                    continue
                text_col = candidate_cols[0]
                texts = df[text_col].dropna().astype(str).tolist()
                if max_lines:
                    texts = texts[:max_lines]
                total = len(texts)
                print(f"  Total rows to process: {total}")
                for i in tqdm(range(0, total, BATCH_SIZE), desc="  Ingesting CSV rows"):
                    batch = texts[i:i + BATCH_SIZE]
                    ids = [f"{fname}_{j}" for j in range(i, i + len(batch))]
                    metas = [{"source": fname, "row": j} for j in range(i, i + len(batch))]
                    collection.add(documents=batch, metadatas=metas, ids=ids)
            except Exception as e:
                print(f"  Failed to process {fname}: {e}")
        elif fname.endswith(".json"):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "objects" in data:
                    items = data["objects"]
                elif isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = [data]
                else:
                    print(f"  Skipped: Unknown JSON structure in {fname}")
                    continue
                if max_lines:
                    items = items[:max_lines]
                total = len(items)
                print(f"  Total JSON items to process: {total}")
                docs = []
                metas = []
                ids = []
                for i, item in enumerate(tqdm(items, desc="  Ingesting JSON items")):
                    if isinstance(item, dict):
                        text = item.get("description") or item.get("name") or json.dumps(item)
                        docs.append(text)
                        metas.append({"source": fname, "idx": i})
                        ids.append(f"{fname}_{i}")
                        if len(docs) >= BATCH_SIZE:
                            collection.add(documents=docs, metadatas=metas, ids=ids)
                            docs, metas, ids = [], [], []
                if docs:
                    collection.add(documents=docs, metadatas=metas, ids=ids)
            except Exception as e:
                print(f"  Failed to process {fname}: {e}")
        print(f"  Finished processing {fname}\n")
    print("Knowledge base successfully ingested into Chroma vector store.\n")

def query_vector_db(query, persist_dir="data/vector_store"):
    client = PersistentClient(path=persist_dir)
    try:
        collection = client.get_collection("cyber_kb")
    except ValueError:
        collection = client.create_collection("cyber_kb", embedding_function=get_embedder())
        print("Warning: Created new empty collection as no existing collection was found.")
        return []
    results = collection.query(
        query_texts=[query],
        n_results=5
    )
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    scores = results.get("distances", [[]])[0]
    return list(zip(docs, metas, scores))

if __name__ == "__main__":
    setup_vector_db(max_lines=None, fast=True)
    print("\nQuery test:")
    results = query_vector_db("unauthorized ssh brute force attack")
    for doc, meta, score in results:
        print(f"\nScore: {score:.4f}")
        print(f"Source: {meta.get('source')}")
        print(f"Content (first 300 chars):\n{doc[:300]}...")
