# Aletheia-MCP 🛡️🔍

**Aletheia-MCP** (named after *Aletheia*, the Greek goddess/concept of truth and disclosure) is an advanced multi-agent runtime validation and execution engine. Inspired by Google DeepMind's **AI Control Roadmap** (June 2026), it establishes a dual-agent boundary system designed to secure autonomous LLMs executing terminal commands, modifying files, and running code.

It exposes execution capabilities through the **Model Context Protocol (MCP)**, running untrusted agent-generated code inside a secure, containerized Docker sandbox while a real-time **Supervisor Agent** audits the worker's reasoning process and intercepts tool parameters before they execute.

---

## Key Features
*   **Dual-Agent A2A Collaboration**: Implements stateful worker-supervisor interaction protocols via `LangGraph`.
*   **DeepMind AI Control Audit**: Intercepts the Worker's thinking trace and proposed tool arguments out-of-band, validating actions against security rules.
*   **Secure Dockerized Sandbox**: Executes terminal instructions and script tasks in ephemeral, resource-constrained containers.
*   **Dynamic Security Dashboard**: Built with FastAPI and real-time streaming to visualize agent reasoning, decision logs, and manual approval gates.
*   **OKF (Open Knowledge Format) RAG**: Pulls target environment parameters and security runbooks dynamically using semantic search to guide the supervisor.

---

## System Architecture

```
                     +---------------------------------------+
                     |            User Request               |
                     +-------------------+-------------------+
                                         |
                                         v
                     +-------------------+-------------------+
                     |           Worker Agent                |
                     |  (Generates code, runs terminal cmds)  |
                     +-------------------+-------------------+
                                         |
                                         | [Intercepts Tool Calls]
                                         v
+----------------------------------------+---------------------------------------+
|                                  Supervisor Agent                              |
|  - Reasoning Trace Auditor                                                     |
|  - Tool Call Validator (Checks payloads, paths, code safety)                   |
|  - Security Guardrail (OWASP Agentic Top 10 Scanner)                           |
+----------------------------------------+---------------------------------------+
                                         |
                       [Approved]        |        [Rejected]
                    +--------------------+--------------------+
                    |                                         |
                    v                                         v
+-------------------+-------------------+           +---------+---------+
|        Sandboxed MCP Server           |           |  Force Rollback   |
| (Dockerized execution of bash/python) |           |  & Re-planning    |
+---------------------------------------+           +-------------------+
```

---

## Getting Started

### Prerequisites
*   Python 3.10+
*   Docker (for containerized execution)
*   Gemini API Key (set as `GEMINI_API_KEY`)

### Setup & Run
1.  Clone the repository:
    ```bash
    git clone https://github.com/xenoroses/aletheia-mcp.git
    cd aletheia-mcp
    ```
2.  Install dependencies:
    ```bash
    pip install uv
    uv pip install -e .
    ```
3.  Start the FastAPI dashboard and safety orchestrator:
    ```bash
    python -m aletheia.app
    ```
4.  Open `http://localhost:8000` to interact with the UI.

---

## License
MIT License.
