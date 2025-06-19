# cli for running the cybersentinel-rag pipeline: select a log, analyze, enrich, and get an expert report.

import os
import sys
from agents.detector_agent import DetectorAgent
from agents.context_agent import ContextAgent
from agents.response_agent import ResponseAgent

# set the directory for log files and the vector store path
logs_dir = os.path.join("data", "logs")
vector_store_path = os.path.join("data", "vector_store")

# list all available log files in the logs directory
def list_logs():
    logs = [f for f in os.listdir(logs_dir) if f.endswith('.log')]
    return logs

# prompt the user to select a log file for analysis
def select_log():
    logs = list_logs()
    if not logs:
        print("no log files found in data/logs/")
        sys.exit(1)
    print("\navailable logs:")
    for idx, log in enumerate(logs, 1):
        print(f"  [{idx}] {log}")
    while True:
        try:
            sel = int(input("\nselect the log number to analyze: "))
            if 1 <= sel <= len(logs):
                return os.path.join(logs_dir, logs[sel-1])
        except Exception:
            pass
        print("invalid option. try again.")

# main cli entry point for running the pipeline interactively
def main():
    print("\n=== cybersentinel-rag cli ===\n")
    log_path = select_log()
    print(f"\nanalyzing: {log_path}\n")
    # run the detector agent to extract findings from the selected log
    detector = DetectorAgent()
    findings = detector.analyze(log_path)
    print(f"  findings detected: {len(findings)}")
    if not findings:
        print("no findings detected in the log. pipeline finished.")
        return
    # enrich findings with context using the context agent
    context_agent = ContextAgent(vector_store_path=vector_store_path)
    enriched_findings = context_agent.process_findings(findings, max_enrich=20)
    max_findings_for_response = 5
    max_context_chars = 100
    findings_for_response = []
    # select the most relevant findings and truncate context for the llm
    for finding in enriched_findings[:max_findings_for_response]:
        finding_copy = finding.copy()
        if 'context' in finding_copy:
            for ctx in finding_copy['context']:
                ctx['description'] = ctx['description'][:max_context_chars]
        findings_for_response.append(finding_copy)
    # generate the expert report using the response agent
    response_agent = ResponseAgent()
    report = response_agent.suggest_action(findings_for_response)
    print("\n=== final report ===")
    print(f"timestamp: {report.get('timestamp')}")
    if 'error' in report:
        print(f"error: {report['error']}")
    else:
        print(f"model used: {report.get('model_used')}")
        print("\nexpert analysis:\n")
        print(report.get('raw_analysis'))
    print("\n=== end ===\n")

if __name__ == "__main__":
    main()
