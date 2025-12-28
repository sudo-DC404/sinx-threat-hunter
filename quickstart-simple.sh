#!/bin/bash

# sinX Threat Hunter - Ultra-Simple Quick Start
# Works with Python 3.13 + SQLite - No external dependencies!

set -e

echo "🛡️  sinX Threat Hunter - Simple Start (SQLite + Python 3.13)"
echo "=============================================================="
echo ""

cd "$(dirname "$0")/backend"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate and install
source venv/bin/activate

echo "📦 Installing minimal dependencies..."
echo "   (This will take about 30 seconds)"
echo ""

pip install -q --upgrade pip
pip install -q -r requirements-minimal.txt

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 Starting sinX Threat Hunter..."
echo ""
echo "   📊 Backend API: http://localhost:8000"
echo "   📚 API Documentation: http://localhost:8000/api/docs"
echo "   🏥 Health Check: http://localhost:8000/health"
echo ""
echo "   Database: SQLite (threat_hunter.db)"
echo ""
echo "   Press Ctrl+C to stop the server"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run the application
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
