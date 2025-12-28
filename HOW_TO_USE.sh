#!/bin/bash

# sinX Threat Hunter - Quick Start Guide
# This script shows you how to use all the main features

echo "🛡️  sinX Threat Hunter - Quick Start Guide"
echo "=========================================="
echo ""

# Step 1: Create user
echo "📝 Step 1: Creating user 'sinX'..."
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"sinX","email":"sinx@example.com","password":"Moorehaven1990","full_name":"sinX User"}' | python3 -m json.tool
echo ""

# Step 2: Login
echo "🔐 Step 2: Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=sinX&password=Moorehaven1990')

TOKEN=$(echo $LOGIN_RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
echo "✅ Logged in! Token: ${TOKEN:0:50}..."
echo ""

# Step 3: Ingest a security log
echo "📊 Step 3: Ingesting security log..."
curl -s -X POST http://localhost:8000/api/v1/siem/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "message": "Failed SSH login attempt from suspicious IP",
    "source_ip": "198.51.100.42",
    "dest_ip": "10.0.0.5",
    "dest_port": 22,
    "event_type": "authentication_failure",
    "severity": "warning"
  }' | python3 -m json.tool
echo ""

# Step 4: Ingest another log with attack pattern
echo "📊 Step 4: Ingesting SQL injection attempt..."
curl -s -X POST http://localhost:8000/api/v1/siem/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "message": "Web request: SELECT * FROM users WHERE id=1 OR 1=1",
    "source_ip": "203.0.113.50",
    "dest_ip": "10.0.0.10",
    "dest_port": 80,
    "event_type": "web_attack",
    "severity": "high"
  }' | python3 -m json.tool
echo ""

# Step 5: Query logs
echo "🔍 Step 5: Querying all logs..."
curl -s -X GET "http://localhost:8000/api/v1/siem/logs?limit=10" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
echo ""

# Step 6: Add a malicious IOC
echo "🎯 Step 6: Adding malicious IP to threat intelligence..."
curl -s -X POST http://localhost:8000/api/v1/intel/iocs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ioc_type": "ip",
    "value": "198.51.100.42",
    "threat_type": "bruteforce",
    "severity": "high",
    "confidence": 90,
    "source": "manual",
    "tags": ["ssh", "bruteforce", "scanner"]
  }' | python3 -m json.tool
echo ""

# Step 7: Check an IP against IOCs
echo "🔍 Step 7: Checking IP against threat intelligence..."
curl -s -X POST http://localhost:8000/api/v1/intel/check \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"value": "198.51.100.42", "ioc_type": "ip"}' | python3 -m json.tool
echo ""

# Step 8: List all IOCs
echo "📋 Step 8: Listing all IOCs..."
curl -s -X GET "http://localhost:8000/api/v1/intel/iocs?limit=10" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
echo ""

# Step 9: View alerts (if any were triggered)
echo "🚨 Step 9: Checking for alerts..."
curl -s -X GET "http://localhost:8000/api/v1/alerts?limit=10" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
echo ""

echo "=========================================="
echo "✅ Quick start complete!"
echo ""
echo "🌐 Next Steps:"
echo "   1. Open API docs: http://localhost:8000/api/docs"
echo "   2. Explore all 30+ endpoints"
echo "   3. Try creating detection rules, playbooks, hunt sessions"
echo ""
echo "📚 Save your token for future use:"
echo "   export SINX_TOKEN=\"$TOKEN\""
echo ""
