#!/bin/bash

echo "🧹 Cleaning sinX Threat Hunter for GitHub..."
echo ""

# Remove databases
echo "Removing databases..."
rm -f backend/threat_hunter.db threat_hunter.db *.sqlite* *.db
echo "✓ Removed databases"

# Remove logs
echo "Removing logs..."
rm -rf logs/ *.log
echo "✓ Removed logs"

# Remove Python cache
echo "Removing Python cache..."
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete
echo "✓ Removed Python cache"

# Remove tokens
echo "Removing tokens..."
rm -f /tmp/sinx_token *.token
echo "✓ Removed tokens"

# Remove .env (keep .env.example)
echo "Removing environment files..."
rm -f backend/.env .env
echo "✓ Removed environment files (kept .env.example)"

# Remove virtual environment
echo "Removing virtual environment..."
rm -rf backend/venv
echo "✓ Removed virtual environment"

# Remove node_modules if exists
if [ -d "frontend/node_modules" ]; then
    echo "Removing node_modules..."
    rm -rf frontend/node_modules
    echo "✓ Removed node_modules"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Cleaned and ready for GitHub!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. Review the code:"
echo "   - Check for any personal IPs/domains"
echo "   - Ensure default credentials are generic"
echo ""
echo "2. Initialize git repository:"
echo "   git init"
echo "   git add ."
echo "   git commit -m 'Initial commit: sinX Threat Hunter v1.0.0'"
echo ""
echo "3. Create GitHub repository at:"
echo "   https://github.com/new"
echo ""
echo "4. Push to GitHub:"
echo "   git remote add origin https://github.com/YOUR_USERNAME/sinx-threat-hunter.git"
echo "   git push -u origin main"
echo ""
echo "📚 See SETUP_FOR_GITHUB.md for detailed instructions"
echo ""
