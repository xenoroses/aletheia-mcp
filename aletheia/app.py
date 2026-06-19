import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from aletheia.graph import create_aletheia_graph

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("aletheia.app")

app = FastAPI(title="Aletheia-MCP Dashboard", version="0.1.0")

# Setup Web Assets Directory
web_dir = os.path.join(os.path.dirname(__file__), "web")
os.makedirs(web_dir, exist_ok=True)

class TaskRequest(BaseModel):
    task: str

@app.post("/api/run")
def run_task(request: TaskRequest):
    """Starts the LangGraph execution flow for a user task."""
    try:
        graph = create_aletheia_graph()
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
            "history": []
        }
        
        final_state = graph.invoke(initial_state)
        
        # Clean final state formatting
        return {
            "task": final_state["task"],
            "success": final_state.get("is_safe", False) and final_state.get("exit_code", -1) == 0,
            "stdout": final_state.get("stdout", ""),
            "stderr": final_state.get("stderr", ""),
            "exit_code": final_state.get("exit_code", 0),
            "history": final_state.get("history", []),
            "safety_score": final_state.get("safety_score", 0.0)
        }
    except Exception as e:
        logger.exception("Failed to execute graph")
        raise HTTPException(status_code=500, detail=str(e))

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
