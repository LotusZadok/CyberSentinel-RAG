# Entry point for CyberSentinel-RAG multi-agent system

def main():
    print("CyberSentinel-RAG system starting...")
    # TODO: Initialize agents and start processing

if __name__ == "__main__":
    from agents.detector_agent import DetectorAgent
    import os
    log_path = os.path.join("data", "logs", "sample_log.txt")
    detector = DetectorAgent()
    results = detector.analyze(log_path)
    print("Resultados del análisis de logs:")
    for r in results:
        print(r)
