import pytest
from aletheia.rag import OKFRagEngine

def test_rag_query_match():
    engine = OKFRagEngine()
    
    # Query for command injection
    results = engine.query("rm -rf system files", limit=1)
    assert len(results) == 1
    assert "SEC-01" in results[0]["title"] or "SEC-03" in results[0]["title"]

def test_rag_path_traversal_match():
    engine = OKFRagEngine()
    
    # Query for path traversal
    results = engine.query("read absolute directory paths /etc", limit=1)
    assert len(results) == 1
    assert "SEC-02" in results[0]["title"]

def test_dynamic_rule_addition():
    engine = OKFRagEngine()
    engine.add_rule(
        title="Rule SEC-99: Mock Custom Rules",
        content="Reject all executions attempting to contact external APIs.",
        category="security"
    )
    
    results = engine.query("external APIs call", limit=1)
    assert len(results) == 1
    assert "SEC-99" in results[0]["title"]
