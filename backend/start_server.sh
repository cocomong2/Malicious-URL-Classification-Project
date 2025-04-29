#!/bin/bash

# Exit on error
set -e

# Navigate to the backend directory
cd "$(dirname "$0")"

# Check if virtual environment exists, create if it doesn't
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    uv venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install dependencies if needed
echo "Checking dependencies..."
uv pip install -r requirements.txt

# Start the FastAPI server
echo "Starting server..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Note: The --host 0.0.0.0 parameter makes the server accessible from other devices on the network
# Remove it if you only want local access
