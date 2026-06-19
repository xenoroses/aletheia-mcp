import os
from dotenv import load_dotenv

load_dotenv()

# Gemini Configurations
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash") # Fallback to standard Flash if custom 3.5 is not specified in env

# Docker Configuration
DOCKER_IMAGE = os.getenv("DOCKER_IMAGE", "python:3.10-slim")
SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "30")) # timeout in seconds

# Safety/Supervisor Thresholds
SAFETY_THRESHOLD = float(os.getenv("SAFETY_THRESHOLD", "0.7"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
