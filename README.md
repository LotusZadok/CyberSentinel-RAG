# CyberSentinel-RAG

Four-node LangGraph pipeline that turns SSH/sudo auth logs into a severity-rated incident report, running fully local on Ollama.

---

## Instituto Tecnológico de Costa Rica

## Inteligencia Artificial

Author: Sebastián Granados Artavia
Professor: Kenneth Obando Rodríguez

## Installation & Setup

### Prerequisites

- Python 3.8 or higher
- Git
- [Ollama](https://ollama.com/), which serves the language model locally
- About 6 GB of free VRAM to run the model on the GPU. It also runs on CPU, far slower

Everything runs locally. No API key, account or paid service is needed.

### 1. Clone the repository

```sh
git clone <repo-url>
cd CyberSentinel-RAG
```

### 2. Create and activate a virtual environment

```sh
python -m venv venv
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Windows (cmd):
.\venv\Scripts\activate.bat
# On Linux/macOS:
source venv/bin/activate
```

### 3. Install dependencies

```sh
pip install -r requirements.txt
```

### 4. Pull the language model

```sh
ollama pull llama3.1:8b
```

Around 4.9 GB of download. With `num_ctx=8192` it occupies about 5.8 GB of VRAM
and fits entirely on an 8 GB card. Check that Ollama is serving it:

```sh
ollama ps
```

`100% GPU` in the PROCESSOR column means nothing spilled to CPU.

---

## Vector Database Setup (IMPORTANT)

The vector database (ChromaDB) is not included in the repository. Before running the pipeline, you must build your own vector database. This allows you to customize the knowledge base as needed.

**To build the vector database:**

```sh
python utils/vector_db.py
```

This script will ingest all files in `data/knowledge_base/` into the vector store at `data/vector_store/`.

- You can add or remove files in `data/knowledge_base/` to customize your knowledge base.
- The vector store is ignored by git (`/data/vector_store/` in `.gitignore`).

---

## Quick Pipeline Usage

1. Place your log file in `data/logs/` (e.g., `custom_test.log`).
2. Edit `run_pipeline.py` to use the log you want:
   ```python
   log_path = os.path.join("data", "logs", "custom_test.log")
   ```
3. Run the pipeline:
   ```sh
   python run_pipeline.py
   ```
4. The system will detect incidents, enrich them with context, judge severity, and write
   an expert report. See [docs/sample-run.md](docs/sample-run.md) for the full output of a
   real run.

---

## CLI Interface

You can use the command-line interface to choose the log to analyze and run the pipeline interactively:

```sh
python cli.py
```

The CLI allows you to:

- List available logs
- Select the log to analyze
- Run the pipeline and see the report in the terminal

---

## Pipeline Limits and Performance

- The pipeline will enrich up to 300 findings per run (configurable in `run_pipeline.py`).
- Only the 20 most relevant enriched findings (based on context score) reach the triage and report steps.
- Each retrieved document is truncated to 500 characters before it enters a prompt.
- One model call per finding is spent generating its retrieval query, plus one call for triage and one for the report. That first group dominates the runtime.
- The report prompt measures around 3300 tokens, against a context window of 8192.

---

## Project Structure

```
CyberSentinel-RAG/
├── agents/              # Pipeline nodes
├── data/                # Data and knowledge base
│   ├── knowledge_base/
│   ├── logs/
│   └── vector_store/
├── diagrams/            # Project diagrams
├── docs/                # Sample run and corpus manifest
├── utils/               # Utilities
└── requirements.txt     # Project dependencies
```

---

## Notes

- You can customize the nodes and detection patterns as needed.
- Example logs are in `data/logs/`. `sample_auth.log` is synthetic: it was written for this
  project and describes no real host or incident.
- The knowledge base is in `data/knowledge_base/`, documented in [docs/corpus.md](docs/corpus.md).
- [docs/sample-run.md](docs/sample-run.md) records one complete run, with the environment it
  came from.

---

## Limitations

- The detector covers six finding types over SSH and sudo authentication logs. Anything else
  in a log passes through unnoticed.
- The detector is rule-based. It matches regular expressions, so it finds what those patterns
  describe and nothing more.
- Retrieval quality has not been evaluated against a labelled set. There is no measurement of
  whether the documents pulled for a finding are the right ones.
- LLM output is not deterministic. Wording changes between runs on the same input, and the
  Ollama runtime does not honour a fixed seed strictly.
- Severity judgement had to be isolated in its own node. While the model wrote the report and
  judged severity in the same call, it did not apply the rubric: it would list two or three
  HIGH conditions and still return HIGH, where the rubric calls for CRITICAL.

---

## Troubleshooting

If you encounter issues during installation:

1. Ensure you are using the correct Python version.
2. Verify the virtual environment is activated (`(venv)` should appear in your terminal).
3. If there are problems with a dependency, try installing it individually with pip.

---

## LangChain & LangGraph Orchestration

This project leverages [LangChain](https://python.langchain.com/) and [LangGraph](https://langchain-ai.github.io/langgraph/) to orchestrate and enhance the four-node pipeline:

- **LangChain** talks to the local model through `langchain-ollama`, in the `ContextAgent`, the `TriageAgent` and the `ResponseAgent`.
- **LangGraph** defines the pipeline as a directed graph, one node per step, which makes steps easy to add, remove or reorder.

### How it works

The graph has four nodes, run in order:

1. **Rule-based detector** — `DetectorAgent` reads the log and flags six kinds of finding. This step is
   rule-based: plain regular expressions over each line, no machine learning and no model call.
   A single line can match more than one pattern and yield several findings, so the finding
   count does not track the line count.
2. **Per-finding retrieval against ChromaDB** — `ContextAgent` asks the model to write one search query
   per finding, then pulls the three closest documents for each from ChromaDB.
3. **Isolated severity triage against a fixed rubric** — `TriageAgent` sees only the findings and the severity rubric, no
   retrieved documents and no prose. It returns which HIGH conditions are present, the log line
   that satisfies each, and the resulting level.
4. **Report generation** — `ResponseAgent` writes the report. It receives the severity already decided and
   copies it; it does not recompute it.

Findings and retrieved documents travel to the report in separate labelled blocks, so the model
cannot present reference material as something observed on the host.

---

Questions or suggestions? Contributions and feedback are welcome!
