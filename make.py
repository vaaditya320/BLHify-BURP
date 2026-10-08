"""Compatibility entry point: build the complete extension on Windows."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
subprocess.run(
    ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
     str(root / "build.ps1"), *(["-Test"] if "--test" in sys.argv else [])],
    cwd=root, check=True,
)
