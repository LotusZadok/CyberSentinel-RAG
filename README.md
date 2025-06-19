# CyberSentinel-RAG

Multi-agent system for automated cybersecurity incident analysis and response using RAG (Retrieval Augmented Generation) and vector knowledge bases.

---

# Multiagents

## Instituto Tecnológico de Costa Rica

## Inteligencia Artificial

Authors: Emanuel Rodríguez Oviedo y Sebastián Granados Artavia
Professor: Kenneth Obando Rodríguez

## Installation & Setup

### Prerequisites

- Python 3.8 or higher
- Git

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

### 4. Set your OpenAI key

Create a `.env` file in the root directory and add:

```env
OPENAI_API_KEY=sk-...
```

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
   LOG_PATH = os.path.join("data", "logs", "custom_test.log")
   ```
3. Run the pipeline:
   ```sh
   python run_pipeline.py
   ```
4. The system will detect incidents, enrich them with context, and generate an expert report using GPT.

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
- Only the 20 most relevant enriched findings (based on context score) will be sent to the ResponseAgent (GPT) to avoid token limit errors.
- Each context is truncated to 100 characters before sending to GPT.
- You can increase these limits if your hardware and OpenAI account allow it, but be aware of token and performance constraints.

---

## Project Structure

```
CyberSentinel-RAG/
├── agents/              # System agents
├── config/              # Configurations
├── data/                # Data and knowledge base
│   ├── knowledge_base/
│   ├── logs/
│   └── vector_store/
├── diagrams/            # Project diagrams
├── notebooks/           # Jupyter notebooks
├── utils/               # Utilities
└── requirements.txt     # Project dependencies
```

---

## Notes

- The system is optimized to avoid OpenAI token/rate errors.
- You can customize the agents and detection patterns as needed.
- Example logs are in `data/logs/`.
- The knowledge base is in `data/knowledge_base/`.

---

## Troubleshooting

If you encounter issues during installation:

1. Ensure you are using the correct Python version.
2. Verify the virtual environment is activated (`(venv)` should appear in your terminal).
3. If there are problems with a dependency, try installing it individually with pip.

---

## LangChain & LangGraph Orchestration

This project leverages [LangChain](https://python.langchain.com/) and [LangGraph](https://langchain-ai.github.io/langgraph/) to orchestrate and enhance the multi-agent pipeline:

- **LangChain** is used to integrate Large Language Models (LLMs) for advanced query generation and context enrichment, especially within the `ContextAgent`.
- **LangGraph** is used to define and manage the pipeline as a directed graph, where each agent (Detector, Context, Response) is a node, allowing for flexible and extensible orchestration of the analysis workflow.

### How it works

- The pipeline is defined as a graph: `DetectorAgent → ContextAgent → ResponseAgent`.
- LangChain enables the use of LLMs (e.g., OpenAI GPT) to generate more relevant queries for context retrieval and to enhance the quality of the analysis.
- LangGraph manages the execution flow, making it easy to add, remove, or modify steps in the pipeline.

---

Questions or suggestions? Contributions and feedback are welcome!
