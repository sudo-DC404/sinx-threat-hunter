#!/bin/bash

# sinX Threat Hunter - Quick Start Script
# This script helps you quickly launch the platform

set -e

echo "🛡️  sinX Threat Hunter - Enterprise Threat Hunting Platform"
echo "============================================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Detect Docker Compose command (v1 vs v2)
COMPOSE_CMD=""
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    echo "✅ Found docker-compose (v1)"
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
    echo "✅ Found docker compose (v2 plugin)"
else
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ .env file created. You can edit it to customize settings."
    echo ""
fi

# Start services
echo "🚀 Starting sinX Threat Hunter services..."
echo ""

$COMPOSE_CMD up -d

echo ""
echo "✅ Services started successfully!"
echo ""
echo "📊 Access Points:"
echo "   - Backend API:  http://localhost:8000"
echo "   - API Docs:     http://localhost:8000/api/docs"
echo "   - Frontend:     http://localhost:3000 (once frontend is built)"
echo ""
echo "🔍 View logs:"
echo "   $COMPOSE_CMD logs -f"
echo ""
echo "🛑 Stop services:"
echo "   $COMPOSE_CMD down"
echo ""
echo "📚 Full documentation: README.md"
echo ""
