import re
import ast
from typing import List, Dict, Any

class SecurityPolicy:
    def __init__(self, id: str, name: str, description: str, enabled: bool = True):
        self.id = id
        self.name = name
        self.description = description
        self.enabled = enabled

class PolicyEngine:
    def __init__(self):
        self.policies = {
            "POL-ENV": SecurityPolicy("POL-ENV", "Block Environment Leaks", "Strictly disallows reading environment variables or accessing os.environ keys.", True),
            "POL-NET": SecurityPolicy("POL-NET", "Block Outbound Network", "Detects curl, wget, urllib, socket, or requests usage which could lead to data exfiltration.", True),
            "POL-FILE": SecurityPolicy("POL-FILE", "Sandbox Path Containment", "Ensures all file operations are strictly relative (no absolute paths or directory traversal).", True),
            "POL-DYN": SecurityPolicy("POL-DYN", "Prevent Dynamic Execution", "Blocks usage of eval(), exec(), or modifying sys.modules dynamically.", True),
            "POL-SYS": SecurityPolicy("POL-SYS", "Restrict Process Spawning", "Blocks subprocess commands, fork requests, or spawning host terminals.", True)
        }

    def get_policies(self) -> List[Dict[str, Any]]:
        return [
            {"id": p.id, "name": p.name, "description": p.description, "enabled": p.enabled}
            for p in self.policies.values()
        ]

    def update_policy(self, id: str, enabled: bool) -> bool:
        if id in self.policies:
            self.policies[id].enabled = enabled
            return True
        return False

    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        """Scans python/bash code against active policies and returns structural findings."""
        findings = []
        lower_code = code.lower()

        # 1. POL-ENV Check
        if self.policies["POL-ENV"].enabled:
            env_patterns = [r"os\.environ", r"os\.getenv", r"getenv", r"environ"]
            for pat in env_patterns:
                if re.search(pat, code):
                    findings.append({
                        "policy_id": "POL-ENV",
                        "severity": "CRITICAL",
                        "details": f"Environment lookup matched pattern: '{pat}'"
                    })

        # 2. POL-NET Check
        if self.policies["POL-NET"].enabled:
            net_patterns = [r"curl ", r"wget ", r"socket\.", r"requests\.", r"urllib", r"http\.client", r"aiohttp"]
            for pat in net_patterns:
                if re.search(pat, lower_code):
                    findings.append({
                        "policy_id": "POL-NET",
                        "severity": "HIGH",
                        "details": f"Potential network action matched pattern: '{pat}'"
                    })

        # 3. POL-FILE Check
        if self.policies["POL-FILE"].enabled:
            file_patterns = [r"\.\./", r"\.\.\\", r"^/etc", r"^c:\\windows", r"os\.chmod", r"os\.chown"]
            for pat in file_patterns:
                if re.search(pat, lower_code):
                    findings.append({
                        "policy_id": "POL-FILE",
                        "severity": "CRITICAL",
                        "details": f"Sandbox breakout or traversal pattern matched: '{pat}'"
                    })

        # 4. POL-DYN Check
        if self.policies["POL-DYN"].enabled:
            dyn_patterns = [r"eval\(", r"exec\(", r"__import__", r"getattr\("]
            for pat in dyn_patterns:
                if re.search(pat, lower_code):
                    findings.append({
                        "policy_id": "POL-DYN",
                        "severity": "HIGH",
                        "details": f"Dynamic execution threat matched pattern: '{pat}'"
                    })

        # 5. POL-SYS Check
        if self.policies["POL-SYS"].enabled:
            sys_patterns = [r"subprocess", r"os\.system", r"os\.popen", r"pty\.", r"shutil\.rmtree"]
            for pat in sys_patterns:
                if re.search(pat, lower_code):
                    findings.append({
                        "policy_id": "POL-SYS",
                        "severity": "CRITICAL",
                        "details": f"Host process invocation pattern matched: '{pat}'"
                    })

        return findings
