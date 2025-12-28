#!/bin/bash

# sinX Threat Hunter - Manual Start (No Docker Required)
# For development and quick testing

set -e

echo "🛡️  sinX Threat Hunter - Manual Setup"
echo "======================================"
echo ""

cd "$(dirname "$0")"

# Check prerequisites
echo "🔍 Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

if ! command -v psql &> /dev/null; then
    echo "⚠️  PostgreSQL client not found (optional for remote DB)"
fi

echo "✅ Prerequisites OK"
echo ""

# Setup backend
echo "📦 Setting up backend..."
cd backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "   Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "   Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "✅ Backend setup complete"
echo ""

# Setup database (optional - will work with SQLite if PostgreSQL not available)
echo "📊 Database configuration..."
echo "   Using configuration from .env file"
echo "   Default: PostgreSQL on localhost:5432"
echo "   DB: threat_hunter, User: sinx"
echo ""

# Start services
echo "🚀 Starting sinX Threat Hunter..."
echo ""
echo "   Backend API will be available at: http://localhost:8000"
echo "   API Documentation: http://localhost:8000/api/docs"
echo ""
echo "   Press Ctrl+C to stop the server"
echo ""

# Run the application
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
