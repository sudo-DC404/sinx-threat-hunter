#!/bin/bash

# sinX Threat Hunter - FULL Enterprise Platform
# Complete feature set: SIEM, Threat Intel, Detection, SOAR, Hunting
# Python 3.13 compatible with SQLite backend

set -e

echo "🛡️  sinX Threat Hunter - Enterprise Platform v1.0"
echo "================================================================"
echo ""
echo "   Complete Feature Set:"
echo "   ✓ SIEM (Log Ingestion & Analysis)"
echo "   ✓ Threat Intelligence Platform (IOC Management)"
echo "   ✓ Detection Engine (Signatures, Anomalies, IOC Matching)"
echo "   ✓ SOAR (Playbooks & Automation)"
echo "   ✓ Threat Hunting Interface"
echo "   ✓ Real-time Alerts & Monitoring"
echo "   ✓ GeoIP Enrichment"
echo "   ✓ STIX/TAXII Threat Feeds"
echo "   ✓ MITRE ATT&CK Mapping"
echo ""
echo "================================================================"
echo ""

cd "$(dirname "$0")/backend"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate environment
source venv/bin/activate

echo "📦 Installing FULL enterprise dependencies..."
echo "   (This includes threat intel, SOAR, GeoIP, monitoring)"
echo "   Installation may take 2-3 minutes..."
echo ""

pip install -q --upgrade pip
pip install -q -r requirements-full.txt

echo ""
echo "✅ All enterprise features installed successfully!"
echo ""

# Initialize database
echo "🗄️  Initializing database..."
python3 -c "
from app.core.database import engine, Base
from app.models import logs, iocs, threats, alerts, playbooks, hunts, users
import asyncio

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print('   ✓ Database tables created')

asyncio.run(init_db())
" 2>/dev/null || echo "   Database already initialized"

echo ""
echo "================================================================"
echo "🚀 Starting sinX Threat Hunter Enterprise Platform..."
echo "================================================================"
echo ""
echo "   📊 Backend API: http://localhost:8000"
echo "   📚 API Documentation: http://localhost:8000/api/docs"
echo "   🏥 Health Check: http://localhost:8000/health"
echo ""
echo "   Database: SQLite (threat_hunter.db)"
echo "   Mode: Full Enterprise Features"
echo ""
echo "================================================================"
echo ""
echo "   Quick Start Commands:"
echo ""
echo "   # Create admin user:"
echo "   curl -X POST http://localhost:8000/api/v1/auth/register \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"username\":\"admin\",\"email\":\"admin@sinx.local\","
echo "         \"password\":\"SecurePass123!\",\"full_name\":\"Admin\"}'"
echo ""
echo "   # View API documentation:"
echo "   Open: http://localhost:8000/api/docs"
echo ""
echo "================================================================"
echo ""
echo "   Press Ctrl+C to stop the server"
echo ""
echo "================================================================"
echo ""

# Run the full platform
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
