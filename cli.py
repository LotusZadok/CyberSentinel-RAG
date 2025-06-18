# CLI for running the CyberSentinel-RAG pipeline: select a log, analyze, enrich, and get an expert report.

import os
import sys
from agents.detector_agent import DetectorAgent
from agents.context_agent import ContextAgent
from agents.response_agent import ResponseAgent

LOGS_DIR = os.path.join("data", "logs")
VECTOR_STORE_PATH = os.path.join("data", "vector_store")

def list_logs():
    logs = [f for f in os.listdir(LOGS_DIR) if f.endswith('.log')]
    return logs

def select_log():
    logs = list_logs()
    if not logs:
        print("No log files found in data/logs/")
        sys.exit(1)
    print("\nAvailable logs:")
    for idx, log in enumerate(logs, 1):
        print(f"  [{idx}] {log}")
    while True:
        try:
            sel = int(input("\nSelect the log number to analyze: "))
            if 1 <= sel <= len(logs):
                return os.path.join(LOGS_DIR, logs[sel-1])
        except Exception:
            pass
        print("Invalid option. Try again.")

def main():
    print("\n=== CyberSentinel-RAG CLI ===\n")
    log_path = select_log()
    print(f"\nAnalyzing: {log_path}\n")
    detector = DetectorAgent()
    findings = detector.analyze(log_path)
    print(f"  Findings detected: {len(findings)}")
    if not findings:
        print("No findings detected in the log. Pipeline finished.")
        return
    context_agent = ContextAgent(vector_store_path=VECTOR_STORE_PATH)
    enriched_findings = context_agent.process_findings(findings, max_enrich=20)
    MAX_FINDINGS_FOR_RESPONSE = 5
    MAX_CONTEXT_CHARS = 100
    findings_for_response = []
    for finding in enriched_findings[:MAX_FINDINGS_FOR_RESPONSE]:
        finding_copy = finding.copy()
        if 'context' in finding_copy:
            for ctx in finding_copy['context']:
                ctx['description'] = ctx['description'][:MAX_CONTEXT_CHARS]
        findings_for_response.append(finding_copy)
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

if __name__ == "__main__":
    main()
