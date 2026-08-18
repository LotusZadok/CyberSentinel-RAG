# ContextAgent: enriches security findings with contextual information from the vector knowledge base using RAG. Runs against a local Ollama model.

from typing import List, Dict, Any
import os
import sys
import time

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)
from utils.query_kb import search_knowledge_base
from langchain_ollama import ChatOllama
from langchain_core.prompts import PromptTemplate

# local model served by ollama; never left implicit
OLLAMA_MODEL = "llama3.1:8b"
OLLAMA_NUM_CTX = 8192
# reduces variation between runs; ollama does not honour it strictly
OLLAMA_SEED = 42

# the ip is not passed as its own field: it is banned from the output, and labelling it
# in the input only invites the model to copy it. entry is passed whole.
QUERY_TEMPLATE = """You generate search queries for a cybersecurity knowledge base containing MITRE ATT&CK techniques, CAPEC attack patterns and CVE records.

Write ONE search query for the security event below.

Output rules, all mandatory:
- Output the query text and nothing else: no preamble, no trailing explanation, no quotation marks, no backticks, no bullet points, no label.
- Exactly one line.
- Plain descriptive English. Never use boolean operators such as AND, OR, NOT. Never use field:value or key=value syntax.
- Describe the general class of attack or technique. Never include IP addresses, user names, timestamps, host names or process IDs from the event.

Event type: {finding_type}
Occurrences: {count}
Log entry: {entry}"""


class ContextAgent:
    def __init__(self, vector_store_path: str = "data/vector_store"):
        self.vector_store_path = vector_store_path
        # local inference: no api key, no external service
        self.llm = ChatOllama(
            model=OLLAMA_MODEL,
            temperature=0,
            num_ctx=OLLAMA_NUM_CTX,
            seed=OLLAMA_SEED,
        )
        self.query_prompt = PromptTemplate(
            input_variables=["finding_type", "count", "entry"],
            template=QUERY_TEMPLATE,
        )

    def generate_query(self, finding: Dict[str, Any]) -> str:
        prompt = self.query_prompt.format(
            finding_type=finding.get('type', ''),
            count=finding.get('count', ''),
            entry=finding.get('entry', '')
        )
        # ChatOllama returns an AIMessage, not a str
        response = self.llm.invoke(prompt)
        return response.content.strip()

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
            'external_id': meta.get('external_id') or meta.get('cve_id') or '',
            'relevance_score': score,
            'description': doc[:500]
        } for doc, meta, score in context_results]

    def process_findings(self, findings: List[Dict[str, Any]], max_enrich: int = 20) -> List[Dict[str, Any]]:
        print(f"[ContextAgent] Processing {len(findings)} findings...")
        start = time.time()
        query_to_findings = {}
        # one llm call per finding; queries are deduplicated only after generation
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
                # add the relevant context found for this query to the finding
                # this allows each finding to have contextualized information for further analysis
                enriched_finding['context'] = query_context_cache[query]
                enriched.append(enriched_finding)
        elapsed = time.time() - start
        # print the total enrichment time for performance monitoring
        print(f"[ContextAgent] Total time to enrich findings (grouped): {elapsed:.2f} seconds")
        if len(findings) > max_enrich:
            # warn if not all findings were enriched due to performance/config limits
            print(f"[ContextAgent] Only the first {max_enrich} findings were enriched. The rest are returned without context.")
            for finding in findings[max_enrich:]:
                # findings outside the limit are returned without additional context
                enriched.append(finding)
        return enriched

if __name__ == "__main__":
    # this block allows testing the context agent in isolation with sample findings
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
    # process the test findings to verify enrichment logic
    enriched_findings = agent.process_findings(test_findings)
    for finding in enriched_findings:
        print("\nFinding:", finding['type'])
        if 'ip' in finding:
            print(f"IP: {finding['ip']}")
        if 'count' in finding:
            print(f"Count: {finding['count']}")
        print("\nContext found:")
        # print the context found for each finding to facilitate debugging and validation
        for ctx in finding['context']:
            print(f"\nSource: {ctx['source']}")
            print(f"Score: {ctx['relevance_score']:.4f}")
            print(f"Description:\n{ctx['description']}")
