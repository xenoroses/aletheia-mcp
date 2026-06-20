import os
import json
import time
from typing import Dict, Any, List

class SessionManager:
    def __init__(self, workspace_path: str = "./"):
        self.registry_file = os.path.join(workspace_path, "sessions.json")
        self._initialize_file()

    def _initialize_file(self):
        if not os.path.exists(self.registry_file):
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump({}, f)

    def load_sessions(self) -> Dict[str, Any]:
        try:
            with open(self.registry_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_run(self, run_id: str, state: Dict[str, Any]):
        """Saves or updates a specific session run."""
        sessions = self.load_sessions()
        
        # Serialize history entries safely
        serialized_history = []
        for entry in state.get("history", []):
            serialized_history.append(dict(entry))

        sessions[run_id] = {
            "run_id": run_id,
            "task": state.get("task", ""),
            "safety_score": state.get("safety_score", 0.0),
            "is_safe": state.get("is_safe", False),
            "exit_code": state.get("exit_code", 0),
            "stdout": state.get("stdout", ""),
            "stderr": state.get("stderr", ""),
            "history": serialized_history,
            "pending_approval": state.get("pending_approval", False),
            "hitl_status": state.get("hitl_status", ""),
            "updated_at": time.time()
        }

        try:
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(sessions, f, indent=2)
        except Exception:
            pass

    def get_session(self, run_id: str) -> Dict[str, Any]:
        sessions = self.load_sessions()
        return sessions.get(run_id, {})

    def delete_session(self, run_id: str):
        sessions = self.load_sessions()
        if run_id in sessions:
            del sessions[run_id]
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(sessions, f, indent=2)
