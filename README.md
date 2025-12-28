# sinX Threat Hunter

Open-source threat hunting and security operations platform.

## What is This?

A free alternative to commercial SIEM/threat hunting platforms like CrowdStrike Falcon, SentinelOne, and Splunk.

**Features:**
- Real-time log ingestion and analysis (SIEM)
- Threat intelligence with IOC management
- Automated threat detection
- Security automation (SOAR)
- Web dashboard and CLI tool

## Installation

### Quick Setup

```bash
git clone https://github.com/sudo-DC404/sinx-threat-hunter.git
cd sinx-threat-hunter
./quickstart-full.sh
```

### Start the Platform

```bash
./start.sh
```

Access:
- Web Dashboard: http://localhost:8080
- API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs

**Default Login:**
- Username: `admin`
- Password: `changeme`

## Usage

### Web Interface

Open http://localhost:8080 in your browser and login.

### CLI Tool

```bash
# Login
./sinx-hunt login

# View dashboard
./sinx-hunt dashboard

# View alerts
./sinx-hunt alerts

# Add security log
./sinx-hunt ingest "Security event message"

# Add threat indicator
./sinx-hunt add-ioc 192.168.1.100
```

### API

```python
import requests

# Login
response = requests.post("http://localhost:8000/api/v1/auth/login",
    data={"username": "admin", "password": "changeme"})
token = response.json()["access_token"]

# Ingest log
requests.post("http://localhost:8000/api/v1/siem/ingest",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "message": "Failed login attempt",
        "source_ip": "192.168.1.100",
        "severity": "high"
    })
```

## Configuration

Copy `.env.example` to `.env` in the backend directory and customize:

```bash
# Required - change these!
SECRET_KEY=your-secret-key-32-chars-minimum
ADMIN_PASSWORD=your-secure-password

# Optional API keys for threat feeds
ALIENVAULT_API_KEY=
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
```

## Requirements

- Python 3.11+
- SQLite (default) or PostgreSQL (production)
- Modern web browser

## License

MIT License - see LICENSE file

## Tech Stack

- Backend: FastAPI (Python)
- Frontend: HTML/JavaScript
- Database: SQLite / PostgreSQL
- Auth: JWT
