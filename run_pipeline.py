# automated pipeline: detectoragent + contextagent + responseagent for cybersentinel-rag

import os
import sys
from agents.detector_agent import DetectorAgent
from agents.context_agent import ContextAgent
from agents.response_agent import ResponseAgent
from langgraph.graph import StateGraph, END

# set the log and vector store paths for the pipeline
log_path = os.path.join("data", "logs", "custom_test.log")
vector_store_path = os.path.join("data", "vector_store")

# define pipeline steps as functions compatible with langchain/langgraph
# each step receives and returns a state dict for chaining

def detect_step(state):
    # run the detector agent to analyze the log and extract findings
    detector = DetectorAgent()
    findings = detector.analyze(log_path)
    return {"findings": findings}

def context_step(state):
    # enrich findings with context using the context agent and vector store
    findings = state["findings"]
    if not findings:
        return {"enriched_findings": []}
    context_agent = ContextAgent(vector_store_path=vector_store_path)
    enriched_findings = context_agent.process_findings(findings, max_enrich=300)
    return {"enriched_findings": enriched_findings}

def response_step(state):
    # select the most relevant findings and generate a report using the response agent
    enriched_findings = state["enriched_findings"]
    max_findings_for_response = 20
    max_context_chars = 100
    def best_score(finding):
        if 'context' in finding and finding['context']:
            return min(ctx['relevance_score'] for ctx in finding['context'])
        return float('inf')
    findings_for_response = []
    # sort findings by best context score and truncate context descriptions
    for finding in sorted(enriched_findings, key=best_score)[:max_findings_for_response]:
        finding_copy = finding.copy()
        if 'context' in finding_copy:
            for ctx in finding_copy['context']:
                ctx['description'] = ctx['description'][:max_context_chars]
        findings_for_response.append(finding_copy)
    response_agent = ResponseAgent()
    report = response_agent.suggest_action(findings_for_response)
    return {"report": report}

if __name__ == "__main__":
    # main orchestration using langgraph stategraph
    print("\n=== cybersentinel-rag: automated analysis pipeline (langgraph) ===\n")
    # define the graph with state dict as schema
    workflow = StateGraph(state_schema=dict)
    workflow.add_node("detect", detect_step)
    workflow.add_node("context", context_step)
    workflow.add_node("response", response_step)
    workflow.set_entry_point("detect")
    workflow.add_edge("detect", "context")
    workflow.add_edge("context", "response")
    workflow.add_edge("response", END)
    graph = workflow.compile()
    # run the graph and collect results
    result = graph.invoke({})
    findings = result.get("findings", [])
    print(f"  findings detected: {len(findings)}")
    if not findings:
        print("no findings detected in the log. pipeline finished.")
        sys.exit(0)
    enriched_findings = result.get("enriched_findings", [])
    if len(enriched_findings) > 20:
        print(f"[pipeline] only the 20 most relevant enriched findings will be sent to the responseagent to avoid token limit errors.")
    report = result.get("report", {})
    print("\n=== final report ===")
    print(f"timestamp: {report.get('timestamp')}")
    if 'error' in report:
        print(f"error: {report['error']}")
    else:
        print(f"model used: {report.get('model_used')}")
        print("\nexpert analysis:\n")
        print(report.get('raw_analysis'))
    print("\n=== end ===\n")
