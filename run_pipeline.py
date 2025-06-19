# Automated pipeline: DetectorAgent + ContextAgent + ResponseAgent for CyberSentinel-RAG

import os
import sys
from agents.detector_agent import DetectorAgent
from agents.context_agent import ContextAgent
from agents.response_agent import ResponseAgent
from langgraph.graph import StateGraph, END

LOG_PATH = os.path.join("data", "logs", "custom_test.log")
VECTOR_STORE_PATH = os.path.join("data", "vector_store")

# Define pipeline steps as functions compatible with LangChain/LangGraph

def detect_step(state):
    detector = DetectorAgent()
    findings = detector.analyze(LOG_PATH)
    return {"findings": findings}

def context_step(state):
    findings = state["findings"]
    if not findings:
        return {"enriched_findings": []}
    context_agent = ContextAgent(vector_store_path=VECTOR_STORE_PATH)
    enriched_findings = context_agent.process_findings(findings, max_enrich=300)
    return {"enriched_findings": enriched_findings}

def response_step(state):
    enriched_findings = state["enriched_findings"]
    MAX_FINDINGS_FOR_RESPONSE = 20
    MAX_CONTEXT_CHARS = 100
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
    response_agent = ResponseAgent()
    report = response_agent.suggest_action(findings_for_response)
    return {"report": report}

if __name__ == "__main__":
    print("\n=== CyberSentinel-RAG: Automated Analysis Pipeline (LangGraph) ===\n")
    # Define the graph
    workflow = StateGraph(state_schema=dict) 
    workflow.add_node("detect", detect_step)
    workflow.add_node("context", context_step)
    workflow.add_node("response", response_step)
    workflow.set_entry_point("detect")
    workflow.add_edge("detect", "context")
    workflow.add_edge("context", "response")
    workflow.add_edge("response", END)
    graph = workflow.compile()
    # Run the graph
    result = graph.invoke({})
    findings = result.get("findings", [])
    print(f"  Findings detected: {len(findings)}")
    if not findings:
        print("No findings detected in the log. Pipeline finished.")
        sys.exit(0)
    enriched_findings = result.get("enriched_findings", [])
    if len(enriched_findings) > 20:
        print(f"[Pipeline] Only the 20 most relevant enriched findings will be sent to the ResponseAgent to avoid token limit errors.")
    report = result.get("report", {})
    print("\n=== FINAL REPORT ===")
    print(f"Timestamp: {report.get('timestamp')}")
    if 'error' in report:
        print(f"Error: {report['error']}")
    else:
        print(f"Model used: {report.get('model_used')}")
        print("\nExpert analysis:\n")
        print(report.get('raw_analysis'))
    print("\n=== END ===\n")
