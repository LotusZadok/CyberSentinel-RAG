import os
import json
import pandas as pd
from chromadb import Client
from chromadb.config import Settings
from chromadb.utils import embedding_functions
from tqdm import tqdm

def setup_vector_db(knowledge_base_dir="data/knowledge_base", persist_dir="data/vector_store", max_lines=100000, fast=False):
    client = Client(Settings(persist_directory=persist_dir))
    collection = client.get_or_create_collection("cyber_kb")
    embedder = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

    files = [f for f in os.listdir(knowledge_base_dir) if f.endswith(('.txt', '.json', '.csv'))]
    print(f"\n📚 Ingesting {len(files)} files from {knowledge_base_dir}...\n")

    BATCH_SIZE = 5000

    for fname in files:
        fpath = os.path.join(knowledge_base_dir, fname)
        print(f"🔍 Processing {fname}...")

        if fname.endswith(".txt"):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except UnicodeDecodeError:
                with open(fpath, "r", encoding="latin-1") as f:
                    lines = f.readlines()

            if max_lines:
                lines = lines[:max_lines]
                print(f"  ℹ️ Limited to first {max_lines} lines")

            total = len(lines)
            for i in range(0, total, BATCH_SIZE):
                batch = [line.strip() for line in lines[i:i+BATCH_SIZE] if line.strip()]
                ids = [f"{fname}_{j}" for j in range(i, i + len(batch))]
                metas = [{"source": fname, "line": j} for j in range(i, i + len(batch))]
                if batch:
                    collection.add(documents=batch, metadatas=metas, ids=ids)
                if fast and (i // BATCH_SIZE) % 5 == 0:
                    print(f"    ...{i+len(batch)} lines processed")

        elif fname.endswith(".csv"):
            try:
                df = pd.read_csv(fpath)
                candidate_cols = [col for col in df.columns if any(kw in col.lower() for kw in ["desc", "summary", "name", "title"])]
                if not candidate_cols:
                    print(f"  ⚠️ No usable column found in {fname}")
                    continue
                text_col = candidate_cols[0]
                texts = df[text_col].dropna().astype(str).tolist()
                if max_lines:
                    texts = texts[:max_lines]
                total = len(texts)
                for i in range(0, total, BATCH_SIZE):
                    batch = texts[i:i + BATCH_SIZE]
                    ids = [f"{fname}_{j}" for j in range(i, i + len(batch))]
                    metas = [{"source": fname, "row": j} for j in range(i, i + len(batch))]
                    collection.add(documents=batch, metadatas=metas, ids=ids)
                if fast:
                    print(f"    ...{total} rows processed")
            except Exception as e:
                print(f"  ❌ Failed to read CSV {fname}: {e}")

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
                    print(f"  ⚠️ Unknown JSON structure in {fname}")
                    continue

                docs = []
                metas = []
                ids = []
                for i, item in enumerate(items):
                    if isinstance(item, dict):
                        text = item.get("description") or item.get("name") or json.dumps(item)
                        docs.append(text)
                        metas.append({"source": fname, "idx": i})
                        ids.append(f"{fname}_{i}")
                        if len(docs) >= BATCH_SIZE:
                            collection.add(documents=docs, metadatas=metas, ids=ids)
                            docs, metas, ids = [], [], []
                        if fast and (i % (BATCH_SIZE*5) == 0):
                            print(f"    ...{i} items processed")
                if docs:
                    collection.add(documents=docs, metadatas=metas, ids=ids)
            except Exception as e:
                print(f"  ❌ Failed to read JSON {fname}: {e}")
                continue

        print(f"  ✅ Finished {fname}")

    print("\n✅ Knowledge base successfully ingested into Chroma vector store.")

def query_vector_db(query, persist_dir="data/vector_store"):
    client = Client(Settings(persist_directory=persist_dir))
    collection = client.get_or_create_collection("cyber_kb")
    embedder = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    results = collection.query(
        query_texts=[query],
        n_results=5,
        embedding_function=embedder
    )
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    scores = results.get("distances", [[]])[0]
    return list(zip(docs, metas, scores))

if __name__ == "__main__":
    # Ingest knowledge base
    setup_vector_db(max_lines=100000)

    # Query test
    print("\n🔎 Testing query...\n")
    results = query_vector_db("unauthorized ssh brute force attack")
    for doc, meta, score in results:
        print(f"\n🔹 Score: {score:.4f}")
        print(f"📁 Source: {meta.get('source')}")
        print(f"📝 Content: {doc[:300]}...")
