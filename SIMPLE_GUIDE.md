# sinX Threat Hunter - Simple Usage Guide

> **Enterprise threat hunting made easy - no complex commands needed!**

---

## 🚀 Quick Start (3 Steps)

### 1. Start the Platform

```bash
cd /home/sinexo/tools/sinx-threat-hunter
./START.sh
```

That's it! The platform is now running.

### 2. Open Web Dashboard

Open your web browser and go to:
```
http://localhost:8080
```

**Login:**
- Username: `sinX`
- Password: `Moorehaven1990`

### 3. Start Monitoring!

The dashboard shows:
- 🔴 **Critical Alerts** - Threats that need immediate action
- 🟡 **Active Threats** - All security alerts
- 📊 **Security Logs** - All events being monitored
- 🎯 **Threat Intel** - Known bad IPs, domains, etc.

---

## 📱 Two Ways to Use

### Option 1: Web Dashboard (Easiest)

Just use your browser! Click around the dashboard to:
- View all security alerts
- See recent security logs
- Check threat intelligence
- Everything updates automatically

**Auto-refresh:** Dashboard updates every 30 seconds automatically

### Option 2: Command Line (For Advanced Users)

Use the CLI tool for quick commands:

```bash
# Login first
./sinx-hunt login

# View dashboard stats
./sinx-hunt dashboard

# Show recent alerts
./sinx-hunt alerts

# Show security logs
./sinx-hunt logs

# Show threat intelligence
./sinx-hunt iocs

# Add a security event
./sinx-hunt ingest "Suspicious login from 1.2.3.4"

# Add a malicious IP
./sinx-hunt add-ioc 1.2.3.4

# Show all commands
./sinx-hunt help
```

---

## 🎯 What Am I Looking At?

### Dashboard Sections Explained

#### 1. **Critical Alerts** (Red Box)
Number of HIGH PRIORITY threats that need immediate action
- SQL injections
- Malware detected
- Known attacker IPs

#### 2. **Active Threats** (Yellow Box)
Total number of security alerts waiting for review

#### 3. **Security Logs** (Blue Box)
All security events the system is monitoring:
- Login attempts
- Network connections
- Web requests
- System events

#### 4. **Threat Intel** (Green Box)
Number of known bad IPs/domains in the database

---

## 🔍 Understanding Alerts

Alerts are color-coded by severity:

- **🔴 CRITICAL** - Immediate action required (SQL injection, malware)
- **🟠 HIGH** - Serious threat (brute force, known attackers)
- **🟡 MEDIUM** - Suspicious activity (port scans)
- **🔵 LOW** - Minor security events

**Each alert shows:**
- What happened
- When it happened
- Attack classification (MITRE ATT&CK)
- Current status

---

## 💡 Common Tasks

### View Latest Threats
1. Open web dashboard
2. Look at "Active Security Alerts" section
3. Red badges = most important

### Check What's Being Monitored
1. Click "Security Logs" tab
2. See all events in real-time
3. Shows source IPs, destinations, types

### See Known Threats
1. Click "Threat Intelligence" tab
2. All known malicious IPs/domains
3. Shows confidence level and tags

### Monitor in Real-Time
Just leave the dashboard open - it auto-updates every 30 seconds!

---

## 🛠️ Useful Information

### What is This Platform?

sinX Threat Hunter is YOUR personal enterprise security platform that:
- Monitors all security events
- Detects attacks automatically
- Tracks known threats
- Alerts you to suspicious activity

**It competes with:**
- CrowdStrike Falcon ($60-100/month per device)
- SentinelOne ($50-80/month per device)
- Splunk Enterprise Security ($150+/month)

**But yours is:**
- ✅ FREE
- ✅ sinX branded
- ✅ Fully customizable
- ✅ No vendor lock-in

### Current Detection Rules

The platform automatically detects:
1. **SSH Brute Force** - 3+ failed login attempts in 5 minutes
2. **SQL Injection** - Malicious database queries
3. **Port Scanning** - Network reconnaissance

### API Documentation

For advanced integrations:
```
http://localhost:8000/api/docs
```

This shows ALL available API endpoints you can use.

---

## 🆘 Troubleshooting

### Dashboard won't load?
Check if services are running:
```bash
# Should show two processes
ps aux | grep -E "(uvicorn|http.server)"
```

### "Not logged in" error?
Run this first:
```bash
./sinx-hunt login
```

### Want to restart everything?
```bash
# Stop current session (Ctrl+C)
# Then restart
./START.sh
```

---

## 📊 Next Steps

Once you're comfortable:

1. **Integrate Your Systems**
   - Send logs from your servers
   - Connect firewalls
   - Add application logs

2. **Customize Detection Rules**
   - Create your own threat detection rules
   - Set custom alert thresholds
   - Build automated responses

3. **Add Threat Feeds**
   - Connect to online threat intelligence
   - Import IOC lists
   - Auto-update malicious IPs

---

## 🎓 Key Concepts

### IOC (Indicator of Compromise)
Something that indicates a security threat:
- Malicious IP address
- Bad domain name
- Known malware hash
- Suspicious email

### SIEM (Security Information and Event Management)
Collects and analyzes security logs from all sources in one place

### MITRE ATT&CK
A framework that classifies how attackers operate:
- **Tactic** - What they want (e.g., "Credential Access")
- **Technique** - How they do it (e.g., "Brute Force")

---

## 📞 Quick Reference

| What I Want | What To Do |
|------------|-----------|
| View threats | Open http://localhost:8080 |
| Quick stats | `./sinx-hunt dashboard` |
| See alerts | `./sinx-hunt alerts` |
| Check logs | `./sinx-hunt logs` |
| Start platform | `./START.sh` |
| Get help | `./sinx-hunt help` |

---

**You're now running an enterprise threat hunting platform!** 🎯

Just keep the services running and monitor the dashboard. The system will automatically detect and alert you to threats.
