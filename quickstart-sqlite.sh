#!/bin/bash

# sinX Threat Hunter - Super Quick Start with SQLite
# No PostgreSQL or Redis required - just run and go!

set -e

echo "🛡️  sinX Threat Hunter - Quick Start (SQLite)"
echo "=============================================="
echo ""

cd "$(dirname "$0")/backend"

# Enable SQLite mode
echo "📝 Configuring SQLite mode..."
sed -i 's|^        return f"postgresql|        # return f"postgresql|' app/core/config.py
sed -i 's|^        # return "sqlite|        return "sqlite|' app/core/config.py

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate and install
source venv/bin/activate

echo "📦 Installing dependencies (this may take a minute)..."
pip install -q --upgrade pip
pip install -q -r requirements.txt
pip install -q aiosqlite  # SQLite async driver

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 Starting sinX Threat Hunter..."
echo ""
echo "   📊 Backend API: http://localhost:8000"
echo "   📚 API Docs: http://localhost:8000/api/docs"
echo ""
echo "   Press Ctrl+C to stop"
echo ""

# Run the application
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
