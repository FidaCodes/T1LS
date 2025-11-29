#!/usr/bin/env python3
"""
Project scripts - like npm run scripts
Usage: python scripts.py <command>
"""

import sys
import subprocess
import os
import platform

def get_python_path():
    """Get the correct Python executable path based on OS"""
    if platform.system() == "Windows":
        return r"threat_intel_env\Scripts\python.exe"
    else:
        return "./threat_intel_env/bin/python3"

def run_command(cmd):
    """Run a shell command"""
    print(f"🚀 Running: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=os.path.dirname(__file__))
    return result.returncode

def start():
    """Start the server"""
    python_path = get_python_path()
    return run_command(f"{python_path} -m uvicorn app.main:app --host 0.0.0.0 --port 8000")

def dev():
    """Start in development mode with auto-reload"""
    python_path = get_python_path()
    return run_command(f"{python_path} -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload")

def install():
    """Install dependencies"""
    return run_command("./threat_intel_env/bin/pip install -r requirements.txt")

def test():
    """Run tests"""
    return run_command("source threat_intel_env/bin/activate && python -m pytest")

def clean():
    """Clean cache files"""
    return run_command("find . -type d -name '__pycache__' -exec rm -rf {} + && find . -type f -name '*.pyc' -delete")

def main():
    if len(sys.argv) < 2:
        print("Available commands:")
        print("  start  - Start the server")
        print("  dev    - Start with auto-reload")
        print("  install- Install dependencies")
        print("  test   - Run tests")
        print("  clean  - Clean cache files")
        print("\nUsage: python scripts.py <command>")
        return 1
    
    command = sys.argv[1]
    
    commands = {
        'start': start,
        'dev': dev,
        'install': install,
        'test': test,
        'clean': clean
    }
    
    if command in commands:
        return commands[command]()
    else:
        print(f"Unknown command: {command}")
        return 1

if __name__ == "__main__":
    sys.exit(main())