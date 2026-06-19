import logging
from typing import Dict, TypedDict, List, Any
from langgraph.graph import StateGraph, END
from aletheia.worker import WorkerAgent
from aletheia.supervisor import SupervisorAgent
from aletheia.sandbox import run_in_docker, run_in_subprocess
from aletheia.config import MAX_RETRIES

logger = logging.getLogger("aletheia.graph")

class AgentState(TypedDict):
    task: str
    code: str
    run_type: str
    worker_trace: str
    is_safe: bool
    safety_score: float
    risk_assessment: str
    feedback: str
    stdout: str
    stderr: str
    exit_code: int
    iterations: int
    history: List[Dict[str, Any]]

# Initialize Agents
worker = WorkerAgent()
supervisor = SupervisorAgent()

def worker_node(state: AgentState) -> Dict[str, Any]:
    """Node where the Worker Agent writes the implementation script."""
    logger.info("Executing Worker Node...")
    last_feedback = state.get("feedback", "")
    
    # Generate solution
    output = worker.execute(state["task"], supervisor_feedback=last_feedback)
    
    history_entry = {
        "node": "worker",
        "trace": output.trace,
        "code": output.code,
        "run_type": output.run_type
    }
    
    current_history = state.get("history", [])
    current_history.append(history_entry)

    return {
        "code": output.code,
        "run_type": output.run_type,
        "worker_trace": output.trace,
        "iterations": state.get("iterations", 0) + 1,
        "history": current_history
    }

def supervisor_node(state: AgentState) -> Dict[str, Any]:
    """Node where the Supervisor Agent audits the proposed code and reasoning trace."""
    logger.info("Executing Supervisor Node...")
    report = supervisor.audit(
        task=state["task"],
        code=state["code"],
        run_type=state["run_type"],
        worker_trace=state["worker_trace"]
    )
    
    history_entry = {
        "node": "supervisor",
        "is_safe": report.is_safe,
        "safety_score": report.safety_score,
        "risk_assessment": report.risk_assessment,
        "feedback": report.feedback
    }
    
    current_history = state.get("history", [])
    current_history.append(history_entry)

    return {
        "is_safe": report.is_safe,
        "safety_score": report.safety_score,
        "risk_assessment": report.risk_assessment,
        "feedback": report.feedback,
        "history": current_history
    }

def execution_node(state: AgentState) -> Dict[str, Any]:
    """Node where code execution happens in the Docker sandbox."""
    logger.info("Executing Sandbox Node...")
    
    # Run sandbox
    res = run_in_docker(state["code"], state["run_type"])
    
    history_entry = {
        "node": "sandbox",
        "stdout": res.stdout,
        "stderr": res.stderr,
        "exit_code": res.exit_code,
        "sandbox_type": res.sandbox_type
    }
    
    current_history = state.get("history", [])
    current_history.append(history_entry)

    return {
        "stdout": res.stdout,
        "stderr": res.stderr,
        "exit_code": res.exit_code,
        "history": current_history
    }

# Routing Condition
def safety_check_router(state: AgentState) -> str:
    """Decides where to route execution depending on security clearance."""
    if state["is_safe"]:
        return "execute"
    
    if state["iterations"] >= MAX_RETRIES:
        logger.warning(f"Maximum safety mitigation loops ({MAX_RETRIES}) reached. Aborting execution.")
        return END

    return "worker"  # Return to worker for self-healing/rewrite

def create_aletheia_graph():
    """Builds the state graph using LangGraph."""
    workflow = StateGraph(AgentState)

    # Define Nodes
    workflow.add_node("worker", worker_node)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("execute", execution_node)

    # Set Entry Point
    workflow.set_entry_point("worker")

    # Define Relationships
    workflow.add_edge("worker", "supervisor")
    
    # Conditional Routing from Supervisor
    workflow.add_conditional_edges(
        "supervisor",
        safety_check_router,
        {
            "execute": "execute",
            "worker": "worker",
            END: END
        }
    )
    
    workflow.add_edge("execute", END)

    return workflow.compile()
