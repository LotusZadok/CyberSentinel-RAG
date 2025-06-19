# ContextAgent: enriches security findings with contextual information from the vector knowledge base using RAG. Optimized for performance and API limits.

from typing import List, Dict, Any
import os
import sys
import time

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)
from utils.query_kb import search_knowledge_base
from langchain_openai import OpenAI
from langchain.prompts import PromptTemplate

class ContextAgent:
    def __init__(self, vector_store_path: str = "data/vector_store"):
        self.vector_store_path = vector_store_path
        # Inicializa el LLM de LangChain usando la API key de OpenAI
        self.llm = OpenAI(openai_api_key=os.getenv("OPENAI_API_KEY"), temperature=0.2)
        self.query_prompt = PromptTemplate(
            input_variables=["finding_type", "ip", "count", "entry"],
            template=(
                "Given a security finding with the following data: "
                "type: {finding_type}, IP: {ip}, count: {count}, entry: {entry}. "
                "Generate a concise and relevant query to search for context in a cybersecurity knowledge base."
            )
        )

    def generate_query(self, finding: Dict[str, Any]) -> str:
        prompt = self.query_prompt.format(
            finding_type=finding.get('type', ''),
            ip=finding.get('ip', ''),
            count=finding.get('count', ''),
            entry=finding.get('entry', '')
        )
        query = self.llm.invoke(prompt)
        return query.strip()

    def provide_context(self, query: str) -> List[Dict[str, Any]]:
        print(f"[ContextAgent] Searching context for: '{query}'")
        start = time.time()
        context_results = search_knowledge_base(
            query=query,
            n_results=3,
            persist_dir=self.vector_store_path
        )
        elapsed = time.time() - start
        print(f"[ContextAgent] Search time for '{query}': {elapsed:.2f} seconds")
        return [{
            'source': meta['source'],
            'relevance_score': score,
            'description': doc[:500]
        } for doc, meta, score in context_results]

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        query = self.generate_query(finding)
        enriched = finding.copy()
        enriched['context'] = self.provide_context(query)
        return enriched

    def process_findings(self, findings: List[Dict[str, Any]], max_enrich: int = 20) -> List[Dict[str, Any]]:
        print(f"[ContextAgent] Processing {len(findings)} findings...")
        start = time.time()
        query_to_findings = {}
        for finding in findings[:max_enrich]:
            query = self.generate_query(finding)
            if query not in query_to_findings:
                query_to_findings[query] = []
            query_to_findings[query].append(finding)
        query_context_cache = {}
        for query in query_to_findings:
            query_context_cache[query] = self.provide_context(query)
        enriched = []
        for query, findings_group in query_to_findings.items():
            for finding in findings_group:
                enriched_finding = finding.copy()
                enriched_finding['context'] = query_context_cache[query]
                enriched.append(enriched_finding)
        elapsed = time.time() - start
        print(f"[ContextAgent] Total time to enrich findings (grouped): {elapsed:.2f} seconds")
        if len(findings) > max_enrich:
            print(f"[ContextAgent] Only the first {max_enrich} findings were enriched. The rest are returned without context.")
            for finding in findings[max_enrich:]:
                enriched.append(finding)
        return enriched

if __name__ == "__main__":
    test_findings = [
        {
            "type": "multiple_failed_logins",
            "ip": "192.168.1.100",
            "count": 5
        },
        {
            "type": "suspicious_ip",
            "ip": "10.0.0.200",
            "entry": "Unauthorized access attempt from 10.0.0.200"
        }
    ]
    agent = ContextAgent()
    enriched_findings = agent.process_findings(test_findings)
    for finding in enriched_findings:
        print("\nFinding:", finding['type'])
        if 'ip' in finding:
            print(f"IP: {finding['ip']}")
        if 'count' in finding:
            print(f"Count: {finding['count']}")
        print("\nContext found:")
        for ctx in finding['context']:
            print(f"\nSource: {ctx['source']}")
            print(f"Score: {ctx['relevance_score']:.4f}")
            print(f"Description:\n{ctx['description']}")
