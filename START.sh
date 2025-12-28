#!/bin/bash

echo "🛡️  sinX Threat Hunter - Starting Platform..."
echo ""

# Navigate to directory
cd "$(dirname "$0")"

# Start the backend API
echo "Starting backend API server..."
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "✓ Backend API running on http://localhost:8000 (PID: $BACKEND_PID)"
cd ..

# Wait for backend to start
echo "Waiting for backend to initialize..."
sleep 3

# Start the web dashboard
echo ""
echo "Starting web dashboard..."
python3 -m http.server 8080 --directory dashboard &
WEB_PID=$!
echo "✓ Web Dashboard running on http://localhost:8080 (PID: $WEB_PID)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ sinX Threat Hunter is READY!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🌐 Web Dashboard:  http://localhost:8080"
echo "📡 API Endpoint:   http://localhost:8000"
echo "📚 API Docs:       http://localhost:8000/api/docs"
echo ""
echo "👤 Login: sinX / Moorehaven1990"
echo ""
echo "CLI Commands:"
echo "  ./sinx-hunt help          - Show CLI help"
echo "  ./sinx-hunt login         - Login via CLI"
echo "  ./sinx-hunt dashboard     - View dashboard stats"
echo "  ./sinx-hunt alerts        - View active alerts"
echo ""
echo "Press Ctrl+C to stop all services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Trap Ctrl+C to cleanup
cleanup() {
    echo ""
    echo "Shutting down services..."
    kill $BACKEND_PID 2>/dev/null
    kill $WEB_PID 2>/dev/null
    echo "✓ Services stopped"
    exit 0
}

trap cleanup INT

# Keep script running
wait
