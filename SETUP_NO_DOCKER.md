# 🚀 sinX Threat Hunter - Manual Setup (No Docker)

Quick guide to run sinX Threat Hunter without Docker.

## Step 1: Start PostgreSQL and Redis

```bash
# Start PostgreSQL (if not running)
sudo systemctl start postgresql

# Start Redis (if not running)
sudo systemctl start redis-server

# Verify they're running
sudo systemctl status postgresql
sudo systemctl status redis-server
```

## Step 2: Create Database

```bash
# Create database user and database
sudo -u postgres psql -c "CREATE USER sinx WITH PASSWORD 'sinx_hunter_secure_2024';"
sudo -u postgres psql -c "CREATE DATABASE threat_hunter OWNER sinx;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE threat_hunter TO sinx;"

# Enable TimescaleDB extension (optional but recommended)
sudo -u postgres psql -d threat_hunter -c "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"
```

## Step 3: Run the Platform

```bash
cd /home/sinexo/tools/sinx-threat-hunter

# Run the manual start script
./start-manual.sh
```

## Step 4: Access the Platform

Once started, open your browser:
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/api/docs
- **Health Check:** http://localhost:8000/health

## Quick Test

In a new terminal:

```bash
# Create first user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@sinx.local",
    "password": "SecurePassword123!",
    "full_name": "Admin User"
  }'

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin&password=SecurePassword123!"

# Save the access_token from response, then:
export TOKEN="your_access_token_here"

# Ingest a test log
curl -X POST http://localhost:8000/api/v1/siem/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Test log entry",
    "source_ip": "192.168.1.100",
    "event_type": "test",
    "severity": "info"
  }'

# View logs
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/siem/logs?limit=10"
```

## Alternative: Simplified Setup (SQLite)

If you don't want to set up PostgreSQL, you can modify the code to use SQLite:

1. Edit `backend/app/core/config.py`
2. Change the `DATABASE_URL` to use SQLite:
   ```python
   @property
   def DATABASE_URL(self) -> str:
       return "sqlite+aiosqlite:///./threat_hunter.db"
   ```

3. Install additional dependency:
   ```bash
   cd backend
   source venv/bin/activate
   pip install aiosqlite
   ```

## Troubleshooting

### Database Connection Error

```bash
# Check if PostgreSQL is accepting connections
psql -U sinx -d threat_hunter -h localhost

# If it fails, check PostgreSQL configuration
sudo nano /etc/postgresql/*/main/pg_hba.conf
# Add: local   all   sinx   md5
sudo systemctl restart postgresql
```

### Port Already in Use

```bash
# Check what's using port 8000
lsof -i :8000

# Kill the process or change port in start-manual.sh
```

### Redis Connection Error

```bash
# Check Redis
redis-cli ping
# Should return: PONG

# If not running
sudo systemctl start redis-server
```

## Stop the Platform

Press `Ctrl+C` in the terminal where the server is running.

---

**Prefer the easy way?** Once you have Docker authentication set up, use `./start.sh` for one-command deployment!
