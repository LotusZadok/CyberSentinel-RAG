# tool for ingesting .json and .csv files into the chroma vector store and performing semantic queries for cybersentinel.

import os
import json
from collections import Counter

import pandas as pd
from chromadb import PersistentClient
from chromadb.utils import embedding_functions
from tqdm import tqdm

# stix object types that hold no standalone prose worth embedding
SKIPPED_STIX_TYPES = {"relationship", "marking-definition"}

# external_references source_name values that carry the public catalog id (T1078, CAPEC-66, ...)
EXTERNAL_ID_SOURCES = ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack", "capec")

# cvss metric keys in order of preference; a single cve may carry several at once
CVSS_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")

# returns a sentence transformer embedder for semantic search
# this model is lightweight and works well for most security text data
def get_embedder():
    return embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

# normalizes a value for chroma metadata, which only accepts str, int, float and bool.
# returns None when the value is missing, NaN or empty so the caller can omit the key.
def _clean(value):
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return None if pd.isna(value) else value
    text = str(value).strip()
    return text or None

# sets meta[key] only when the value survives normalization; reports whether it was set
def _put(meta, key, value):
    cleaned = _clean(value)
    if cleaned is None:
        return False
    meta[key] = cleaned
    return True

# builds (text, metadata) for one stix object from an att&ck or capec bundle.
# returns None and records a reason when the object carries no usable prose.
def extract_stix(obj, fname, skips):
    if not isinstance(obj, dict):
        skips["not an object"] += 1
        return None
    stix_type = obj.get("type")
    if stix_type in SKIPPED_STIX_TYPES:
        skips[f"stix type '{stix_type}'"] += 1
        return None
    name = _clean(obj.get("name"))
    if not name:
        skips["no name"] += 1
        return None
    description = _clean(obj.get("description"))
    text = f"{name}\n{description}" if description else str(name)
    meta = {"source": fname}
    _put(meta, "stix_type", stix_type)
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") in EXTERNAL_ID_SOURCES:
            if _put(meta, "external_id", ref.get("external_id")):
                break
    return text, meta

# builds (text, metadata) for one entry of an nvd 2.0 feed, shaped as {"cve": {...}}.
# returns None and records a reason when there is no english description to embed.
def extract_nvd(entry, fname, skips):
    cve = entry.get("cve") if isinstance(entry, dict) else None
    if not isinstance(cve, dict):
        skips["malformed entry"] += 1
        return None
    text = None
    for desc in cve.get("descriptions") or []:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            text = _clean(desc.get("value"))
            if text:
                break
    if not text:
        skips["no english description"] += 1
        return None
    meta = {"source": fname}
    _put(meta, "cve_id", cve.get("id"))
    _put(meta, "published", cve.get("published"))
    metrics = cve.get("metrics") or {}
    for key in CVSS_METRIC_KEYS:
        scored = metrics.get(key)
        if not scored:
            continue
        cvss = scored[0].get("cvssData") or {}
        # cvssMetricV2 does not always carry baseSeverity, so the key is omitted rather than guessed
        _put(meta, "severity", cvss.get("baseSeverity"))
        _put(meta, "cvss_score", cvss.get("baseScore"))
        _put(meta, "cvss_version", cvss.get("version"))
        break
    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = _clean(desc.get("value"))
            if isinstance(value, str) and value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    if cwes:
        meta["cwe"] = ", ".join(cwes)
    return text, meta

# builds (text, metadata) for one row of the cisa kev catalog, using fixed column names.
# returns None and records a reason when the row has no text in either column.
def extract_kev(row, fname, skips):
    name = _clean(row.get("vulnerabilityName"))
    description = _clean(row.get("shortDescription"))
    parts = [str(part) for part in (name, description) if part is not None]
    if not parts:
        skips["no text columns"] += 1
        return None
    meta = {"source": fname}
    _put(meta, "cve_id", row.get("cveID"))
    _put(meta, "vendor", row.get("vendorProject"))
    _put(meta, "product", row.get("product"))
    _put(meta, "date_added", row.get("dateAdded"))
    _put(meta, "ransomware", row.get("knownRansomwareCampaignUse"))
    _put(meta, "cwe", row.get("cwes"))
    return "\n".join(parts), meta

# reads one source file and returns (records, extractor) for it, or (None, None) when the
# shape is not recognized. no file is ever collapsed into a single document.
def _dispatch(fpath, fname):
    if fname.endswith(".csv"):
        return pd.read_csv(fpath).to_dict("records"), extract_kev
    with open(fpath, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "objects" in data:
        return data["objects"], extract_stix          # stix bundle: att&ck, capec
    if isinstance(data, dict) and "vulnerabilities" in data:
        return data["vulnerabilities"], extract_nvd   # nvd 2.0 feed
    if isinstance(data, list):
        return data, extract_stix                     # generic list of name/description objects
    return None, None

# sets up the vector database by ingesting all .json and .csv files from the knowledge base directory
# supports batching for performance and can limit the number of lines/items processed
def setup_vector_db(knowledge_base_dir="data/knowledge_base", persist_dir="data/vector_store", max_lines=None, fast=True):
    client = PersistentClient(path=persist_dir)
    collection = client.get_or_create_collection("cyber_kb", embedding_function=get_embedder())
    batch_size = 10000 if fast else 1000
    # chroma rejects an add() larger than its own limit, so never ask for more than it accepts
    try:
        batch_size = min(batch_size, client.get_max_batch_size())
    except Exception:
        batch_size = min(batch_size, 1000)
    files = sorted(f for f in os.listdir(knowledge_base_dir) if f.endswith(('.json', '.csv')))
    print(f"\ningesting {len(files)} files from {knowledge_base_dir} using batch size {batch_size}...\n")
    report = []
    for fname in files:
        fpath = os.path.join(knowledge_base_dir, fname)
        print(f"processing file: {fname}")
        try:
            records, extract = _dispatch(fpath, fname)
        except Exception as e:
            print(f"  failed to read {fname}: {e}")
            continue
        if records is None:
            print(f"  skipped: unrecognized structure in {fname}")
            continue
        if max_lines:
            records = records[:max_lines]
        print(f"  total items to process: {len(records)}")
        skips = Counter()
        indexed = 0
        docs, metas, ids = [], [], []
        for i, record in enumerate(tqdm(records, desc="  ingesting items")):
            extracted = extract(record, fname, skips)
            if extracted is None:
                continue
            text, meta = extracted
            docs.append(text)
            metas.append(meta)
            ids.append(f"{fname}_{i}")
            indexed += 1
            if len(docs) >= batch_size:
                collection.add(documents=docs, metadatas=metas, ids=ids)
                docs, metas, ids = [], [], []
        if docs:
            collection.add(documents=docs, metadatas=metas, ids=ids)
        report.append((fname, indexed, skips))
        print(f"  finished processing {fname}: {indexed} indexed, {sum(skips.values())} skipped\n")
    _print_report(report)
    print("knowledge base successfully ingested into chroma vector store.\n")

# prints the per-file ingestion tally plus the reasons objects were left out
def _print_report(report):
    print("=" * 72)
    print(f"{'file':<40}{'indexed':>10}{'skipped':>10}")
    print("-" * 72)
    total_indexed = 0
    total_skipped = 0
    for fname, indexed, skips in report:
        skipped = sum(skips.values())
        total_indexed += indexed
        total_skipped += skipped
        print(f"{fname:<40}{indexed:>10}{skipped:>10}")
        for reason, count in skips.most_common():
            print(f"    - {reason}: {count}")
    print("-" * 72)
    print(f"{'TOTAL':<40}{total_indexed:>10}{total_skipped:>10}")
    print("=" * 72 + "\n")

# performs a semantic query against the vector database and returns the top results
def query_vector_db(query, persist_dir="data/vector_store"):
    client = PersistentClient(path=persist_dir)
    try:
        collection = client.get_collection("cyber_kb", embedding_function=get_embedder())
    except Exception:
        print("warning: no existing collection was found; run setup_vector_db first.")
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
