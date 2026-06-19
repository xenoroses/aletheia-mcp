import pytest
from aletheia.supervisor import SupervisorAgent

def test_supervisor_heuristics_malicious_path():
    agent = SupervisorAgent()
    
    # Simulating a file system traversal code proposal
    malicious_code = """
import os
files = os.listdir('../../../etc')
print(files)
"""
    report = agent.audit(
        task="Read files",
        code=malicious_code,
        run_type="py",
        worker_trace="I will read parent directories."
    )
    
    # Should flag as unsafe
    assert report.is_safe is False
    assert report.safety_score < 0.5
    assert "traversal" in report.risk_assessment.lower()

def test_supervisor_heuristics_safe_code():
    agent = SupervisorAgent()
    
    safe_code = """
def sum_numbers(a, b):
    return a + b
print(sum_numbers(5, 10))
"""
    report = agent.audit(
        task="Sum two numbers",
        code=safe_code,
        run_type="py",
        worker_trace="I will write a simple safe function to add two inputs."
    )
    
    # Should approve
    assert report.is_safe is True
    assert report.safety_score > 0.7
