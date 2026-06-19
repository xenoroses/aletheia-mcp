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
    """A RAG Engine that retrieves safety runbooks formatted in OKF (Open Knowledge Format) standard."""
    def __init__(self, workspace_path: str = "./"):
        self.workspace_path = workspace_path
        self.rules = list(DEFAULT_SECURITY_RULES)
        self.load_local_okf_files()

    def load_local_okf_files(self):
        """Discovers and parses local .okf or .md documents in the workspace directory."""
        if not os.path.exists(self.workspace_path):
            return
        
        for root, _, files in os.walk(self.workspace_path):
            for file in files:
                if file.endswith((".okf", ".md")) and file != "README.md":
                    try:
                        filepath = os.path.join(root, file)
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                        self.rules.append({
                            "title": f"Local OKF Reference: {file}",
                            "content": content,
                            "category": "local_context"
                        })
                    except Exception as e:
                        logger.error(f"Error reading OKF document {file}: {e}")

    def query(self, search_text: str, limit: int = 2) -> List[Dict[str, Any]]:
        """Performs simple keyword/semantic overlap routing to find relevant security rules."""
        # Simple overlap ranking (highly robust, no embedding download overhead for initial setups)
        search_words = set(search_text.lower().split())
        scored_rules = []
        for rule in self.rules:
            content_words = set(rule["content"].lower().split())
            title_words = set(rule["title"].lower().split())
            
            # Weighted scoring (title matches score higher)
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
