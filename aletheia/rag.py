import os
import json
import logging
from typing import List, Dict, Any
from aletheia.config import GEMINI_API_KEY

logger = logging.getLogger("aletheia.rag")

# In-memory mock database that mirrors OKF (Open Knowledge Format) files
DEFAULT_SECURITY_RULES = [
    {
        "title": "Rule SEC-01: Command Injection Prevention",
        "content": "All shell commands must run in the sandbox. Any script containing commands with unescaped pipes, logical operators (&&, ||), or external variables must be scrutinized. Disallow running raw wget/curl downloads directly to execution pipelines.",
        "category": "security"
    },
    {
        "title": "Rule SEC-02: Local File Traversals",
        "content": "Agents should only read and write within the provided target directory (/workspace). File operations accessing '../' or absolute paths pointing to root filesystems like /etc or C:\\Windows must be rejected.",
        "category": "security"
    },
    {
        "title": "Rule SEC-03: Package Installation Guardrails",
        "content": "Agents must not execute arbitrary system-level packages (apt-get, apk, winget). Python pip installs are permitted ONLY inside virtual environments or sandboxes without network access.",
        "category": "security"
    },
    {
        "title": "Rule CON-01: Environment Resource Limits",
        "content": "Docker container limits are locked to 256MB RAM and 1 CPU Core. Infinite recursive iterations or multi-threaded CPU hogs will be automatically killed when timeout limits are exceeded.",
        "category": "constraints"
    }
]

class OKFRagEngine:
    """A RAG Engine that retrieves safety runbooks formatted in OKF (Open Knowledge Format) standard.
    Uses ChromaDB for vector similarity searches, with an overlap keyword ranking fallback.
    """
    def __init__(self, workspace_path: str = "./"):
        self.workspace_path = workspace_path
        self.rules = list(DEFAULT_SECURITY_RULES)
        self.chroma_client = None
        self.collection = None
        
        # Initialize ChromaDB if possible
        try:
            import chromadb
            from chromadb.config import Settings
            # Create a local persistent database
            self.chroma_client = chromadb.PersistentClient(path=os.path.join(workspace_path, ".chroma"))
            self.collection = self.chroma_client.get_or_create_collection(
                name="aletheia_okf_rules"
            )
            # Seed default rules
            self._seed_chromadb()
        except Exception as e:
            logger.warning(f"ChromaDB not available or failed to initialize, running in memory overlap mode: {e}")

        self.load_local_okf_files()

    def _seed_chromadb(self):
        """Seeds ChromaDB collection with default rules."""
        if not self.collection:
            return
        
        # Count existing documents to prevent duplicate inserts
        if self.collection.count() == 0:
            ids = [f"sec_{i}" for i in range(len(self.rules))]
            documents = [r["content"] for r in self.rules]
            metadatas = [{"title": r["title"], "category": r["category"]} for r in self.rules]
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )

    def load_local_okf_files(self):
        """Discovers and parses local .okf or .md documents in the workspace directory."""
        if not os.path.exists(self.workspace_path):
            return
        
        local_rules = []
        for root, _, files in os.walk(self.workspace_path):
            for file in files:
                if file.endswith((".okf", ".md")) and file != "README.md":
                    try:
                        filepath = os.path.join(root, file)
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                        rule = {
                            "title": f"Local OKF Reference: {file}",
                            "content": content,
                            "category": "local_context"
                        }
                        self.rules.append(rule)
                        local_rules.append(rule)
                    except Exception as e:
                        logger.error(f"Error reading OKF document {file}: {e}")

        # Add local rules to Chroma collection if active
        if self.collection and local_rules:
            try:
                ids = [f"local_{i}" for i in range(len(local_rules))]
                documents = [r["content"] for r in local_rules]
                metadatas = [{"title": r["title"], "category": r["category"]} for r in local_rules]
                self.collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
            except Exception as e:
                logger.error(f"Failed to index local rules in Chroma: {e}")

    def query(self, search_text: str, limit: int = 2) -> List[Dict[str, Any]]:
        """Performs vector query if Chroma is active, fallback to overlap matcher otherwise."""
        if self.collection:
            try:
                results = self.collection.query(
                    query_texts=[search_text],
                    n_results=limit
                )
                formatted_rules = []
                if results and "documents" in results and results["documents"]:
                    docs = results["documents"][0]
                    metas = results["metadatas"][0]
                    for doc, meta in zip(docs, metas):
                        formatted_rules.append({
                            "title": meta.get("title", "Vector Match"),
                            "content": doc,
                            "category": meta.get("category", "unclassified")
                        })
                    return formatted_rules
            except Exception as e:
                logger.error(f"ChromaDB query failed: {e}. Falling back to keyword search.")

        # Heuristic word overlap fallback
        search_words = set(search_text.lower().split())
        scored_rules = []
        for rule in self.rules:
            content_words = set(rule["content"].lower().split())
            title_words = set(rule["title"].lower().split())
            score = len(search_words.intersection(content_words)) + 3 * len(search_words.intersection(title_words))
            scored_rules.append((score, rule))
            
        scored_rules.sort(key=lambda x: x[0], reverse=True)
        return [rule for score, rule in scored_rules[:limit]]

    def add_rule(self, title: str, content: str, category: str = "custom"):
        """Dynamically appends new safety directives discovered at runtime."""
        self.rules.append({
            "title": title,
            "content": content,
            "category": category
        })
