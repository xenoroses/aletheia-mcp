import pytest
import os
from aletheia.sandbox import run_in_subprocess, SandboxResult

def test_safe_subprocess_python():
    code = "print('Hello ' + 'World')"
    res = run_in_subprocess(code, "py")
    assert res.exit_code == 0
    assert "Hello World" in res.stdout
    assert res.stderr == ""

def test_sandbox_timeout():
    # Infinite loop code
    code = "import time\nwhile True:\n    time.sleep(0.1)"
    # We should see a timeout exception or fallback status
    res = run_in_subprocess(code, "py")
    assert res.exit_code == -1
    assert "timeout" in res.stderr.lower()

def test_sandbox_isolation_env():
    # Attempting to read env variables in restricted subprocess
    code = "import os\nprint(os.environ.get('SECRET_TOKEN', 'not_found'))"
    os.environ['SECRET_TOKEN'] = 'super_secret_value'
    res = run_in_subprocess(code, "py")
    # Secret should NOT propagate to the sandbox env
    assert "super_secret_value" not in res.stdout
