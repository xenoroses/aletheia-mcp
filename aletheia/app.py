import os
import uuid
import time
import logging
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, Any, List

from aletheia.graph import create_aletheia_graph
from aletheia.sessions import SessionManager
from aletheia.telemetry import TelemetryCollector
from aletheia.policy_engine import PolicyEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("aletheia.app")

app = FastAPI(title="Aletheia-MCP Dashboard", version="1.0.0")

# Setup Web Assets Directory
web_dir = os.path.join(os.path.dirname(__file__), "web")
os.makedirs(web_dir, exist_ok=True)

# Initialize Core Services
sessions_mgr = SessionManager()
telemetry_coll = TelemetryCollector()
policy_engine = PolicyEngine()

# In-Memory Cache for currently active runs
ACTIVE_RUNS = {}

class TaskRequest(BaseModel):
    task: str

class ApproveRequest(BaseModel):
    run_id: str

class RejectRequest(BaseModel):
    run_id: str
    feedback: str = ""

class TogglePolicyRequest(BaseModel):
    policy_id: str
    enabled: bool

@app.post("/api/run")
def run_task(request: TaskRequest):
    """Starts the LangGraph execution flow for a user task."""
    start_time = time.time()
    try:
        graph = create_aletheia_graph()
        run_id = str(uuid.uuid4())
        initial_state = {
            "task": request.task,
            "code": "",
            "run_type": "",
            "worker_trace": "",
            "is_safe": False,
            "safety_score": 0.0,
            "risk_assessment": "",
            "feedback": "",
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "iterations": 0,
            "history": [],
            "pending_approval": False,
            "hitl_status": ""
        }
        
        final_state = graph.invoke(initial_state)
        ACTIVE_RUNS[run_id] = final_state
        
        # Save run session state
        sessions_mgr.save_run(run_id, final_state)
        
        # Log telemetry metrics
        execution_time = time.time() - start_time
        telemetry_coll.record_run(
            task=request.task,
            safety_score=final_state.get("safety_score", 0.0),
            execution_time=execution_time,
            sandbox_type="Docker" if final_state.get("exit_code") == 0 else "Blocked",
            findings_count=len(final_state.get("risk_assessment", "").split(" | ")) if not final_state.get("is_safe") else 0
        )
        
        return {
            "run_id": run_id,
            "task": final_state["task"],
            "success": final_state.get("is_safe", False) and final_state.get("exit_code", -1) == 0,
            "stdout": final_state.get("stdout", ""),
            "stderr": final_state.get("stderr", ""),
            "exit_code": final_state.get("exit_code", 0),
            "history": final_state.get("history", []),
            "safety_score": final_state.get("safety_score", 0.0),
            "pending_approval": final_state.get("pending_approval", False),
            "hitl_status": final_state.get("hitl_status", "")
        }
    except Exception as e:
        logger.exception("Failed to execute graph")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/approve")
def approve_run(request: ApproveRequest):
    """Manually approves execution of a blocked/grey-zone action."""
    start_time = time.time()
    run_id = request.run_id
    
    # Check memory first, then restore from SessionManager if needed
    if run_id not in ACTIVE_RUNS:
        session_data = sessions_mgr.get_session(run_id)
        if not session_data:
            raise HTTPException(status_code=404, detail="Run ID not found.")
        ACTIVE_RUNS[run_id] = session_data

    state = ACTIVE_RUNS[run_id]
    state["hitl_status"] = "approved"
    state["pending_approval"] = False
    state["is_safe"] = True
    
    try:
        graph = create_aletheia_graph()
        final_state = graph.invoke(state)
        ACTIVE_RUNS[run_id] = final_state
        sessions_mgr.save_run(run_id, final_state)
        
        execution_time = time.time() - start_time
        telemetry_coll.record_run(
            task=state.get("task", ""),
            safety_score=1.0,
            execution_time=execution_time,
            sandbox_type="Docker",
            findings_count=0
        )
        
        return {
            "run_id": run_id,
            "task": final_state["task"],
            "success": final_state.get("is_safe", False) and final_state.get("exit_code", -1) == 0,
            "stdout": final_state.get("stdout", ""),
            "stderr": final_state.get("stderr", ""),
            "exit_code": final_state.get("exit_code", 0),
            "history": final_state.get("history", []),
            "safety_score": final_state.get("safety_score", 0.0),
            "pending_approval": final_state.get("pending_approval", False),
            "hitl_status": final_state.get("hitl_status", "")
        }
    except Exception as e:
        logger.exception("Failed to execute graph after manual approval")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/reject")
def reject_run(request: RejectRequest):
    """Manually rejects execution, sending feedback to Worker agent for mitigation."""
    start_time = time.time()
    run_id = request.run_id
    
    if run_id not in ACTIVE_RUNS:
        session_data = sessions_mgr.get_session(run_id)
        if not session_data:
            raise HTTPException(status_code=404, detail="Run ID not found.")
        ACTIVE_RUNS[run_id] = session_data
        
    state = ACTIVE_RUNS[run_id]
    state["hitl_status"] = "rejected"
    state["pending_approval"] = False
    state["is_safe"] = False
    
    user_feed = request.feedback or "User rejected this code."
    state["feedback"] = f"HITL Rejection Feedback: {user_feed}\nPrevious feedback: {state.get('feedback', '')}"
    
    try:
        graph = create_aletheia_graph()
        final_state = graph.invoke(state)
        ACTIVE_RUNS[run_id] = final_state
        sessions_mgr.save_run(run_id, final_state)
        
        execution_time = time.time() - start_time
        telemetry_coll.record_run(
            task=state.get("task", ""),
            safety_score=state.get("safety_score", 0.0),
            execution_time=execution_time,
            sandbox_type="Mitigated",
            findings_count=1
        )
        
        return {
            "run_id": run_id,
            "task": final_state["task"],
            "success": final_state.get("is_safe", False) and final_state.get("exit_code", -1) == 0,
            "stdout": final_state.get("stdout", ""),
            "stderr": final_state.get("stderr", ""),
            "exit_code": final_state.get("exit_code", 0),
            "history": final_state.get("history", []),
            "safety_score": final_state.get("safety_score", 0.0),
            "pending_approval": final_state.get("pending_approval", False),
            "hitl_status": final_state.get("hitl_status", "")
        }
    except Exception as e:
        logger.exception("Failed to execute graph after rejection")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/policies")
def get_policies():
    """Retrieves current safety policies."""
    return policy_engine.get_policies()

@app.post("/api/policies/toggle")
def toggle_policy(request: TogglePolicyRequest):
    """Dynamically enables or disables a security policy."""
    success = policy_engine.update_policy(request.policy_id, request.enabled)
    if not success:
        raise HTTPException(status_code=404, detail="Policy ID not found.")
    return {"status": "success", "policy_id": request.policy_id, "enabled": request.enabled}

@app.get("/api/metrics")
def get_metrics():
    """Retrieves telemetry diagnostic metrics."""
    return telemetry_coll.get_metrics()

@app.get("/api/sessions")
def get_sessions():
    """Lists saved session summaries."""
    return sessions_mgr.load_sessions()

@app.get("/api/sessions/{run_id}")
def get_session_details(run_id: str):
    """Retrieves detailed log details for a run."""
    session = sessions_mgr.get_session(run_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    return session

# Server routing for index.html
@app.get("/")
def get_dashboard():
    index_file = os.path.join(web_dir, "index.html")
    if not os.path.exists(index_file):
        raise HTTPException(status_code=404, detail="Index file not found. Ensure web UI is built.")
    return FileResponse(index_file)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("aletheia.app:app", host="0.0.0.0", port=8000, reload=True)
