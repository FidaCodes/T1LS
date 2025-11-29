#!/bin/bash
# Simple startup script
cd "$(dirname "$0")"
source threat_intel_env/bin/activate
echo "🚀 Starting Threat Intelligence Analyzer API..."
echo "📖 Documentation: http://localhost:8000/docs"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload