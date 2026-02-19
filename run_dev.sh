#!/bin/bash
# SafeNotes Development Server
# Run this script from the project root

set -e

cd "$(dirname "$0")"

echo "Starting SafeNotes development server..."
echo "Frontend + API will be available at: http://localhost:8000"
echo ""

cd backend

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run uvicorn with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
