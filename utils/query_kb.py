# CLI tool for semantic search in the CyberSentinel vector knowledge base. Provides a minimal interface for querying and displaying results.

from chromadb import PersistentClient
from chromadb.utils import embedding_functions
from typing import List, Tuple, Dict, Any

# Returns a sentence transformer embedder for semantic search.
# This model is lightweight and works well for most security text data.
def get_embedder():
    return embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

# Performs a semantic search in the vector knowledge base using the provided query.
# Returns a list of (document, metadata, score) tuples for downstream use.
def search_knowledge_base(
    query: str,
    n_results: int = 5,
    persist_dir: str = "data/vector_store"
) -> List[Tuple[str, Dict[str, Any], float]]:
    client = PersistentClient(path=persist_dir)
    try:
        # Get the main collection for cyber knowledge base.
        collection = client.get_collection("cyber_kb")
    except ValueError:
        # If the collection does not exist, return empty results.
        return []
    results = collection.query(
        query_texts=[query],
        n_results=n_results
    )
    # Extract documents, metadata, and similarity scores from the query result.
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    scores = results.get("distances", [[]])[0]
    return list(zip(docs, metas, scores))

# Pretty-prints the search results for CLI usage.
# Shows score, source, and a snippet of the content for each result.
def print_results(results: List[Tuple[str, Dict[str, Any], float]], max_chars: int = 300) -> None:
    if not results:
        print("No results found.")
        return
    for doc, meta, score in results:
        print(f"\nScore: {score:.4f}")
        print(f"Source: {meta.get('source', 'Unknown')}")
        if 'idx' in meta:
            print(f"Index: {meta['idx']}")
        elif 'row' in meta:
            print(f"Row: {meta['row']}")
        print(f"Content:\n{doc[:max_chars]}...")
        if len(doc) > max_chars:
            print("...")

if __name__ == "__main__":
    # Interactive CLI for manual testing and exploration of the knowledge base.
    print("\nCyberSentinel Knowledge Base Query")
    print("=" * 60)
    print("Type 'q', 'exit' or press Enter to quit.")
    print("=" * 60)
    while True:
        try:
            query = input("\nQuery > ").strip()
            if query.lower() in ['q', 'exit', 'salir', '']:
                break
            results = search_knowledge_base(query)
            print_results(results)
        except KeyboardInterrupt:
            break
        except Exception as e:
            # Print any unexpected errors for easier debugging.
            print(f"Error: {e}")
    print("\nGoodbye!\n")
