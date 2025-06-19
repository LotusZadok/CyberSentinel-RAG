# tool for ingesting .json and .csv files into the chroma vector store and performing semantic queries for cybersentinel.

import os
import json
import pandas as pd
from chromadb import PersistentClient
from chromadb.utils import embedding_functions
from tqdm import tqdm

# returns a sentence transformer embedder for semantic search
# this model is lightweight and works well for most security text data
def get_embedder():
    return embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

# sets up the vector database by ingesting all .json and .csv files from the knowledge base directory
# supports batching for performance and can limit the number of lines/items processed
def setup_vector_db(knowledge_base_dir="data/knowledge_base", persist_dir="data/vector_store", max_lines=None, fast=True):
    client = PersistentClient(path=persist_dir)
    try:
        # try to use an existing collection if available
        collection = client.get_collection("cyber_kb")
        print("using existing collection with its current embedding function")
    except ValueError:
        # create a new collection if none exists
        collection = client.create_collection("cyber_kb", embedding_function=get_embedder())
        print("created new collection with sentencetransformer embedding function")
    batch_size = 10000 if fast else 1000
    files = [f for f in os.listdir(knowledge_base_dir) if f.endswith(('.json', '.csv'))]
    print(f"\ningesting {len(files)} files from {knowledge_base_dir} using batch size {batch_size}...\n")
    for fname in files:
        fpath = os.path.join(knowledge_base_dir, fname)
        print(f"processing file: {fname}")
        if fname.endswith(".csv"):
            try:
                df = pd.read_csv(fpath)
                # try to find a column with description, summary, name, or title for text embedding
                candidate_cols = [col for col in df.columns if any(keyword in col.lower() for keyword in ["desc", "summary", "name", "title"])]
                if not candidate_cols:
                    print(f"  skipped: no usable text column found in {fname}")
                    continue
                text_col = candidate_cols[0]
                texts = df[text_col].dropna().astype(str).tolist()
                if max_lines:
                    texts = texts[:max_lines]
                total = len(texts)
                print(f"  total rows to process: {total}")
                for i in tqdm(range(0, total, batch_size), desc="  ingesting csv rows"):
                    batch = texts[i:i + batch_size]
                    ids = [f"{fname}_{j}" for j in range(i, i + len(batch))]
                    metas = [{"source": fname, "row": j} for j in range(i, i + len(batch))]
                    collection.add(documents=batch, metadatas=metas, ids=ids)
            except Exception as e:
                print(f"  failed to process {fname}: {e}")
        elif fname.endswith(".json"):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # support for different json structures: list, dict with 'objects', or single dict
                if isinstance(data, dict) and "objects" in data:
                    items = data["objects"]
                elif isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = [data]
                else:
                    print(f"  skipped: unknown json structure in {fname}")
                    continue
                if max_lines:
                    items = items[:max_lines]
                total = len(items)
                print(f"  total json items to process: {total}")
                docs = []
                metas = []
                ids = []
                for i, item in enumerate(tqdm(items, desc="  ingesting json items")):
                    if isinstance(item, dict):
                        # try to use description or name, fallback to full json
                        text = item.get("description") or item.get("name") or json.dumps(item)
                        docs.append(text)
                        metas.append({"source": fname, "idx": i})
                        ids.append(f"{fname}_{i}")
                        if len(docs) >= batch_size:
                            collection.add(documents=docs, metadatas=metas, ids=ids)
                            docs, metas, ids = [], [], []
                if docs:
                    collection.add(documents=docs, metadatas=metas, ids=ids)
            except Exception as e:
                print(f"  failed to process {fname}: {e}")
        print(f"  finished processing {fname}\n")
    print("knowledge base successfully ingested into chroma vector store.\n")

# performs a semantic query against the vector database and returns the top results
def query_vector_db(query, persist_dir="data/vector_store"):
    client = PersistentClient(path=persist_dir)
    try:
        collection = client.get_collection("cyber_kb")
    except ValueError:
        collection = client.create_collection("cyber_kb", embedding_function=get_embedder())
        print("warning: created new empty collection as no existing collection was found.")
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
    # run the full ingestion process and test a sample query
    setup_vector_db(max_lines=None, fast=True)
    print("\nquery test:")
    results = query_vector_db("unauthorized ssh brute force attack")
    for doc, meta, score in results:
        print(f"\nscore: {score:.4f}")
        print(f"source: {meta.get('source')}")
        print(f"content (first 300 chars):\n{doc[:300]}...")
