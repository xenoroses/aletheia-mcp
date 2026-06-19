import sys
import os
import subprocess
import tempfile
import logging
from typing import Dict, Any, Tuple
from aletheia.config import DOCKER_IMAGE, SANDBOX_TIMEOUT

logger = logging.getLogger("aletheia.sandbox")

class SandboxResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str, sandbox_type: str):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.sandbox_type = sandbox_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "sandbox_type": self.sandbox_type
        }

def run_in_docker(code: str, file_extension: str = "py") -> SandboxResult:
    """Runs Python or Bash code inside a secure Docker container."""
    try:
        import docker
        client = docker.from_env()
        # Verify docker daemon responds
        client.ping()
    except Exception as e:
        logger.warning(f"Docker not available, falling back to subprocess sandbox. Error: {e}")
        return run_in_subprocess(code, file_extension)

    with tempfile.TemporaryDirectory() as temp_dir:
        filename = f"script.{file_extension}"
        temp_file_path = os.path.join(temp_dir, filename)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(code)

        # Map temporary directory to container
        volumes = {temp_dir: {"bind": "/workspace", "mode": "ro"}}
        
        # Command depending on extension
        if file_extension == "py":
            command = ["python", f"/workspace/{filename}"]
        else:
            command = ["bash", f"/workspace/{filename}"]

        try:
            container = client.containers.run(
                image=DOCKER_IMAGE,
                command=command,
                volumes=volumes,
                working_dir="/workspace",
                detach=True,
                network_mode="none",  # disable internet access for maximum safety
                mem_limit="256m",     # restrict memory
                nano_cpus=1000000000,  # limit to 1 CPU core
            )
            
            # Wait for execution with timeout
            try:
                result = container.wait(timeout=SANDBOX_TIMEOUT)
                exit_code = result.get("StatusCode", 0)
                stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")
                stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="ignore")
            except Exception as e:
                # Execution timed out or failed
                container.kill()
                exit_code = -1
                stdout = ""
                stderr = f"Sandbox execution timed out or failed: {str(e)}"
            finally:
                container.remove(force=True)

            return SandboxResult(exit_code, stdout, stderr, "docker")
        except Exception as e:
            return SandboxResult(-1, "", f"Failed to start Docker container: {str(e)}", "docker-error")

def run_in_subprocess(code: str, file_extension: str = "py") -> SandboxResult:
    """Fallback: runs code inside a restricted subprocess (OS-level process boundary)."""
    with tempfile.TemporaryDirectory() as temp_dir:
        filename = f"script.{file_extension}"
        temp_file_path = os.path.join(temp_dir, filename)
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(code)

        if file_extension == "py":
            cmd = [sys.executable, temp_file_path]
        else:
            cmd = ["powershell", "-Command", temp_file_path] if sys.platform == "win32" else ["bash", temp_file_path]

        try:
            # Execute subprocess with strict environment and limits
            env = {"PATH": os.environ.get("PATH", "")}  # Strip custom secrets, only pass PATH
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SANDBOX_TIMEOUT,
                cwd=temp_dir,
                env=env
            )
            return SandboxResult(res.returncode, res.stdout, res.stderr, "subprocess_fallback")
        except subprocess.TimeoutExpired as e:
            return SandboxResult(-1, e.stdout or "", f"Timeout expired: code took longer than {SANDBOX_TIMEOUT}s.", "subprocess_fallback")
        except Exception as e:
            return SandboxResult(-1, "", f"Subprocess exception: {str(e)}", "subprocess_fallback_error")
