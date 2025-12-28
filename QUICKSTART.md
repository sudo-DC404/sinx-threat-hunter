# 🚀 sinX Threat Hunter - Quick Start Guide

Get up and running in 5 minutes!

## Prerequisites

- Docker & Docker Compose installed
- At least 4GB RAM available
- Ports 8000, 5432, 6379, 3000 available

## Step 1: Clone & Setup

```bash
cd sinx-threat-hunter

# Make start script executable
chmod +x start.sh

# Start the platform
./start.sh
```

## Step 2: Access the Platform

### Backend API
- **URL:** http://localhost:8000
- **API Docs:** http://localhost:8000/api/docs
- **Health Check:** http://localhost:8000/health

### Create First User

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@sinx.local",
    "password": "SecurePassword123!",
    "full_name": "System Administrator"
  }'
```

### Login and Get Token

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin&password=SecurePassword123!"
```

Save the `access_token` from the response.

## Step 3: Ingest Sample Logs

```bash
# Set your token
TOKEN="your_access_token_here"

# Ingest a log
curl -X POST http://localhost:8000/api/v1/siem/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Failed login attempt from 192.168.1.100",
    "source_ip": "192.168.1.100",
    "event_type": "auth_failure",
    "severity": "medium",
    "hostname": "web-server-01"
  }'

# View logs
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/siem/logs?limit=10"
```

## Step 4: Add Threat Intelligence

```bash
# Add a malicious IP
curl -X POST http://localhost:8000/api/v1/intel/iocs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_type": "ip",
    "value": "192.168.1.100",
    "threat_type": "brute_force",
    "severity": "high",
    "confidence": 85,
    "source": "manual",
    "tags": ["ssh", "brute_force"]
  }'

# List IOCs
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/intel/iocs"
```

## Step 5: Create Detection Rule

```bash
curl -X POST http://localhost:8000/api/v1/alerts/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SSH Brute Force",
    "description": "Detect SSH brute force attacks",
    "severity": "high",
    "rule_type": "threshold",
    "rule_definition": {
      "condition": {
        "event_type": "auth_failure",
        "dest_port": 22
      },
      "threshold": {
        "count": 5,
        "timeframe": 300,
        "group_by": "source_ip"
      }
    },
    "enabled": true,
    "tags": ["ssh", "brute_force"]
  }'
```

## Step 6: Create SOAR Playbook

```bash
curl -X POST http://localhost:8000/api/v1/soar/playbooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block Malicious IP",
    "description": "Automatically block IPs flagged as malicious",
    "trigger_type": "alert",
    "trigger_conditions": {"severity": "high"},
    "workflow": {
      "steps": [
        {
          "action": "block_ip",
          "parameters": {
            "ip": "{{source_ip}}",
            "duration": 60
          }
        },
        {
          "action": "send_email",
          "parameters": {
            "to": "soc@example.com",
            "subject": "Malicious IP Blocked",
            "body": "IP {{source_ip}} has been blocked"
          }
        }
      ]
    },
    "enabled": true
  }'
```

## Step 7: View Alerts

```bash
# List all alerts
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/alerts"

# Get alert statistics
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/alerts/stats/summary"
```

## Step 8: Start a Threat Hunt

```bash
curl -X POST http://localhost:8000/api/v1/hunts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Suspicious SSH Activity Investigation",
    "hypothesis": "Investigating potential SSH brute force campaign",
    "tags": ["ssh", "brute_force", "investigation"]
  }'
```

## Next Steps

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Access at http://localhost:3000
```

### View Logs

```bash
# All services
docker-compose logs -f

# Backend only
docker-compose logs -f backend

# Database only
docker-compose logs -f postgres
```

### Stop Services

```bash
docker-compose down

# Stop and remove volumes (careful - deletes data!)
docker-compose down -v
```

## Troubleshooting

### Port Already in Use

```bash
# Check what's using port 8000
lsof -i :8000

# Kill the process or change port in docker-compose.yml
```

### Database Connection Error

```bash
# Check if PostgreSQL is running
docker-compose ps

# Restart database
docker-compose restart postgres

# View database logs
docker-compose logs postgres
```

### Permission Denied

```bash
# Make sure you're in the correct directory
cd /home/sinexo/tools/sinx-threat-hunter

# Make start script executable
chmod +x start.sh
```

## Advanced Configuration

### Custom Environment Variables

Edit `.env` file:

```env
# Database
POSTGRES_PASSWORD=your_secure_password

# Threat Intelligence API Keys
ALIENVAULT_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# Detection
DETECTION_INTERVAL=30
MAX_ALERTS_PER_HOUR=500
```

Then restart:

```bash
docker-compose down
docker-compose up -d
```

## Production Deployment

For production use:

1. **Change default passwords** in `.env`
2. **Enable HTTPS** with reverse proxy (Nginx/Traefik)
3. **Set up database backups**
4. **Configure log retention** policies
5. **Enable monitoring** (Prometheus/Grafana)
6. **Set DEBUG=false** in `.env`

## Support

- **Documentation:** README.md
- **API Docs:** http://localhost:8000/api/docs
- **Issues:** Report on GitHub

---

**You're all set! Start hunting threats with sinX Threat Hunter! 🛡️**
