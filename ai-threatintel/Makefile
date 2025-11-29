#!/usr/bin/env make

.PHONY: start dev install clean

# Start the server
start:
	@echo "🚀 Starting Threat Intelligence Analyzer API..."
	@source threat_intel_env/bin/activate && uvicorn app.main:app --host 0.0.0.0 --port 8000

# Start with auto-reload (development)
dev:
	@echo "🚀 Starting in development mode..."
	@source threat_intel_env/bin/activate && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Install dependencies
install:
	@echo "📦 Installing dependencies..."
	@source threat_intel_env/bin/activate && pip install -r requirements.txt

# Clean cache
clean:
	@echo "🧹 Cleaning cache..."
	@find . -type d -name "__pycache__" -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete