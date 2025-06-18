# Automated pipeline: DetectorAgent + ContextAgent + ResponseAgent for CyberSentinel-RAG

import os
import sys
from agents.detector_agent import DetectorAgent
from agents.context_agent import ContextAgent
from agents.response_agent import ResponseAgent

LOG_PATH = os.path.join("data", "logs", "custom_test.log")
VECTOR_STORE_PATH = os.path.join("data", "vector_store")

if __name__ == "__main__":
    print("\n=== CyberSentinel-RAG: Automated Analysis Pipeline ===\n")
    print("[1/3] Detecting incidents with DetectorAgent...")
    detector = DetectorAgent()
    findings = detector.analyze(LOG_PATH)
    print(f"  Findings detected: {len(findings)}")
    if not findings:
        print("No findings detected in the log. Pipeline finished.")
        sys.exit(0)
    print("[2/3] Enriching findings with ContextAgent...")
    context_agent = ContextAgent(vector_store_path=VECTOR_STORE_PATH)
    enriched_findings = context_agent.process_findings(findings, max_enrich=300)
    MAX_FINDINGS_FOR_RESPONSE = 20
    MAX_CONTEXT_CHARS = 100
    # Sort by most relevant context score (lowest relevance_score)
    def best_score(finding):
        if 'context' in finding and finding['context']:
            return min(ctx['relevance_score'] for ctx in finding['context'])
        return float('inf')
    findings_for_response = []
    for finding in sorted(enriched_findings, key=best_score)[:MAX_FINDINGS_FOR_RESPONSE]:
        finding_copy = finding.copy()
        if 'context' in finding_copy:
            for ctx in finding_copy['context']:
                ctx['description'] = ctx['description'][:MAX_CONTEXT_CHARS]
        findings_for_response.append(finding_copy)
    if len(enriched_findings) > MAX_FINDINGS_FOR_RESPONSE:
        print(f"[Pipeline] Only the {MAX_FINDINGS_FOR_RESPONSE} most relevant enriched findings will be sent to the ResponseAgent to avoid token limit errors.")
    print("[3/3] Generating expert report with ResponseAgent...")
    response_agent = ResponseAgent()
    report = response_agent.suggest_action(findings_for_response)
    print("\n=== FINAL REPORT ===")
    print(f"Timestamp: {report.get('timestamp')}")
    if 'error' in report:
        print(f"Error: {report['error']}")
    else:
        print(f"Model used: {report.get('model_used')}")
        print("\nExpert analysis:\n")
        print(report.get('raw_analysis'))
    print("\n=== END ===\n")
