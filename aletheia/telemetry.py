import os
import json
import time
from typing import Dict, Any, List

class TelemetryCollector:
    def __init__(self, storage_dir: str = "./.telemetry"):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        self.log_file = os.path.join(storage_dir, "runs.json")
        self._initialize_file()

    def _initialize_file(self):
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump([], f)

    def record_run(self, task: str, safety_score: float, execution_time: float, sandbox_type: str, findings_count: int):
        """Records diagnostic stats for a run."""
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []

        entry = {
            "timestamp": time.time(),
            "task": task,
            "safety_score": safety_score,
            "execution_time_ms": int(execution_time * 1000),
            "sandbox_type": sandbox_type,
            "findings_count": findings_count
        }
        data.append(entry)

        # Cap storage to last 100 entries
        data = data[-100:]

        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def get_metrics(self) -> Dict[str, Any]:
        """Calculates system metrics over the recorded runs."""
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []

        if not data:
            return {
                "total_runs": 0,
                "average_safety": 1.0,
                "average_time_ms": 0,
                "total_findings": 0,
                "sandbox_distribution": {}
            }

        total_runs = len(data)
        avg_safety = sum(x["safety_score"] for x in data) / total_runs
        avg_time = sum(x["execution_time_ms"] for x in data) / total_runs
        total_findings = sum(x["findings_count"] for x in data)

        sandboxes = {}
        for x in data:
            s = x["sandbox_type"]
            sandboxes[s] = sandboxes.get(s, 0) + 1

        return {
            "total_runs": total_runs,
            "average_safety": round(avg_safety, 2),
            "average_time_ms": int(avg_time),
            "total_findings": total_findings,
            "sandbox_distribution": sandboxes
        }
