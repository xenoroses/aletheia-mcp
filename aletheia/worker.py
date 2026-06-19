import logging
from typing import Dict, Any
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from aletheia.config import GEMINI_API_KEY, DEFAULT_MODEL

logger = logging.getLogger("aletheia.worker")

class WorkerOutput(BaseModel):
    trace: str = Field(description="Internal chain-of-thought reasoning explaining how you are solving the task.")
    run_type: str = Field(description="Type of code environment to run: 'py' or 'sh'.")
    code: str = Field(description="The complete executable source code script to perform the task.")

class WorkerAgent:
    def __init__(self, model_name: str = DEFAULT_MODEL):
        self.api_key = GEMINI_API_KEY
        self.model_name = model_name
        
        if self.api_key:
            try:
                self.llm = ChatGoogleGenerativeAI(
                    model=self.model_name,
                    google_api_key=self.api_key,
                    temperature=0.7
                ).with_structured_output(WorkerOutput)
            except Exception as e:
                logger.error(f"Failed to load ChatGoogleGenerativeAI for Worker: {e}. Falling back to template mode.")
                self.llm = None
        else:
            self.llm = None

    def execute(self, task: str, supervisor_feedback: str = "") -> WorkerOutput:
        """Generates code and reasoning trace to solve the user's task."""
        if not self.llm:
            return self._offline_template_response(task, supervisor_feedback)

        feedback_instruction = ""
        if supervisor_feedback:
            feedback_instruction = f"\nCRITICAL: Your previous submission was REJECTED by the Supervisor with the following feedback:\n{supervisor_feedback}\nAdjust your approach and code to satisfy this security warning!"

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are Aletheia-Worker, an autonomous programming agent.
Your objective is to solve the user's computer science/system tasks.
You must return your thinking trace, the type of script ('py' for Python or 'sh' for bash), and the executable code.
Keep code focused, single-purpose, and robust.
"""),
            ("human", """Task to perform: {task}
{feedback_instruction}

Output your execution plan, run type, and code.""")
        ])

        try:
            chain = prompt | self.llm
            result = chain.invoke({
                "task": task,
                "feedback_instruction": feedback_instruction
            })
            return result
        except Exception as e:
            logger.error(f"Worker LLM error: {e}. Falling back to template mode.")
            return self._offline_template_response(task, supervisor_feedback, error_msg=str(e))

    def _offline_template_response(self, task: str, feedback: str = "", error_msg: str = "") -> WorkerOutput:
        """Provides static programming responses for test and API-offline mode."""
        task_lower = task.lower()
        
        # Scenario 1: User asks for a directory list or traversal (will trigger supervisor)
        if "traverse" in task_lower or "system files" in task_lower or "etc" in task_lower:
            trace = "I will attempt to traverse system directories using relative paths to find system details."
            run_type = "py"
            code = """import os
# Attempting path traversal to check root environment
print(os.listdir('../../../'))
"""
        # Scenario 2: Standard calculations/clean code
        elif "fibonacci" in task_lower or "sequence" in task_lower:
            trace = "Generating a safe Python script to calculate Fibonacci sequence numbers up to 10."
            run_type = "py"
            code = """def fib(n):
    a, b = 0, 1
    result = []
    for _ in range(n):
        result.append(a)
        a, b = b, a + b
    return result

print(fib(10))
"""
        # Scenario 3: Host terminal printout
        else:
            trace = "Simple printout execution to verify basic terminal output limits."
            run_type = "sh"
            code = """echo "Hello from Aletheia Sandbox!"
echo "System Task: """ + task + """"
"""

        if feedback:
            # If rejected, heal the code
            trace = "Rewriting code to comply with supervisor safety guidelines. Removed root paths."
            run_type = "py"
            code = """import os
# Safely scanning within workspace only
print(os.listdir('.'))
"""

        return WorkerOutput(trace=trace, run_type=run_type, code=code)
