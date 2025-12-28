# sinX Threat Hunter - Real World Usage

## What Can You Actually DO With This?

### 1. 🔍 Monitor Your Own Systems

Connect your real systems to send logs:

```bash
# Send SSH login attempts
tail -f /var/log/auth.log | while read line; do
    ./sinx-hunt ingest "$line"
done

# Send web server logs
tail -f /var/log/nginx/access.log | while read line; do
    ./sinx-hunt ingest "$line"
done

# Send firewall logs
tail -f /var/log/firewall.log | while read line; do
    ./sinx-hunt ingest "$line"
done
```

### 2. 🎯 Hunt for Specific Threats

**Example: Find all failed login attempts**
```bash
# View recent authentication failures
./sinx-hunt logs 50 | grep -i "authentication"

# Add suspicious IPs to threat intel
./sinx-hunt add-ioc 45.142.212.61 --type ip --threat bruteforce
```

**Example: Detect SQL injection attempts**
```bash
# The system auto-detects these patterns:
# - SELECT * FROM
# - UNION SELECT
# - OR 1=1
# - DROP TABLE

# Just send web logs and it alerts automatically
./sinx-hunt ingest "GET /api/users?id=1' OR '1'='1"
```

### 3. 🛡️ Protect Your Network

**Block attacking IPs automatically:**
```bash
# Get all critical alerts
./sinx-hunt alerts | grep CRITICAL

# For each attacker IP, block it:
sudo iptables -A INPUT -s 198.51.100.42 -j DROP

# Or create a script to auto-block:
./sinx-hunt alerts | grep "source_ip" | while read ip; do
    sudo iptables -A INPUT -s $ip -j DROP
    echo "Blocked $ip"
done
```

### 4. 📊 Analyze Attack Patterns

**Find who's attacking you most:**
```bash
# View all logs and count by source IP
./sinx-hunt logs 1000 | grep "source_ip" | sort | uniq -c | sort -nr

# See what attack types you're getting
./sinx-hunt alerts | grep "event_type"
```

### 5. 🔐 Integrate with Your Tools

**Send to Slack when critical alert:**
```bash
#!/bin/bash
# auto-alert.sh

while true; do
    CRITICAL=$(./sinx-hunt alerts | grep CRITICAL | wc -l)

    if [ $CRITICAL -gt 0 ]; then
        curl -X POST https://hooks.slack.com/YOUR_WEBHOOK \
            -d "{\"text\": \"🚨 $CRITICAL critical threats detected!\"}"
    fi

    sleep 60
done
```

**Send to Discord:**
```bash
WEBHOOK="https://discord.com/api/webhooks/YOUR_WEBHOOK"

./sinx-hunt alerts | while read alert; do
    curl -X POST $WEBHOOK \
        -H "Content-Type: application/json" \
        -d "{\"content\": \"⚠️ New Alert: $alert\"}"
done
```

### 6. 🔬 Threat Intelligence Research

**Check if an IP is malicious:**
```bash
# API endpoint to check any IP
curl -X POST http://localhost:8000/api/v1/intel/check \
    -H "Authorization: Bearer $(cat /tmp/sinx_token)" \
    -H "Content-Type: application/json" \
    -d '{"value": "1.2.3.4", "ioc_type": "ip"}'
```

**Add entire threat feed lists:**
```bash
# Download a threat feed
wget https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt

# Add each IP to your database
cat ipsum.txt | while read ip; do
    ./sinx-hunt add-ioc $ip
done
```

### 7. 🎮 Live Threat Hunting Scenarios

**Scenario 1: Investigating a Breach**
```bash
# 1. Find suspicious activity in last hour
./sinx-hunt logs 100 | grep -E "(failed|error|unauthorized)"

# 2. Check if source IPs are known threats
./sinx-hunt iocs | grep "IP_YOU_FOUND"

# 3. Block the attacker
sudo iptables -A INPUT -s ATTACKER_IP -j DROP

# 4. Add to permanent blocklist
./sinx-hunt add-ioc ATTACKER_IP --threat malicious
```

**Scenario 2: Port Scan Detection**
```bash
# Detect multiple connections from same IP
./sinx-hunt logs 500 | grep "SUSPICIOUS_IP" | wc -l

# If count > 10, it's likely a port scan
# Auto-block it
```

**Scenario 3: Data Exfiltration**
```bash
# Find large outbound transfers
./sinx-hunt logs | grep -E "(upload|transfer|send)" | grep -E "[0-9]{5,}"

# Alert on suspicious destinations
```

### 8. 📡 Connect External Services

**Monitor your cloud infrastructure:**
```python
#!/usr/bin/env python3
# aws-log-shipper.py

import boto3
import requests

# Get AWS CloudTrail logs
client = boto3.client('cloudtrail')

# Send to sinX Threat Hunter
for event in client.lookup_events():
    requests.post('http://localhost:8000/api/v1/siem/ingest',
        headers={'Authorization': 'Bearer YOUR_TOKEN'},
        json={
            'message': event['CloudTrailEvent'],
            'event_type': 'aws_cloudtrail',
            'severity': 'info'
        })
```

**Monitor Docker containers:**
```bash
# Send Docker events to threat hunter
docker events --format '{{.Status}} {{.ID}}' | while read event; do
    ./sinx-hunt ingest "Docker: $event"
done
```

### 9. 🤖 Automate Responses

**Auto-respond to brute force:**
```bash
#!/bin/bash
# auto-block-bruteforce.sh

while true; do
    # Get all brute force alerts
    IPS=$(./sinx-hunt alerts | grep -i "brute" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

    for ip in $IPS; do
        # Block the IP
        sudo iptables -A INPUT -s $ip -j DROP
        echo "🛡️ Blocked brute force from $ip"

        # Log the action
        ./sinx-hunt ingest "Auto-blocked $ip for brute force"
    done

    sleep 30
done
```

### 10. 📈 Daily Security Reports

**Generate daily threat report:**
```bash
#!/bin/bash
# daily-report.sh

echo "📊 sinX Threat Hunter - Daily Report"
echo "Date: $(date)"
echo ""

echo "🔴 Critical Alerts:"
./sinx-hunt alerts | grep CRITICAL

echo ""
echo "📊 Statistics:"
echo "  Total Alerts: $(./sinx-hunt alerts | wc -l)"
echo "  Security Logs: $(./sinx-hunt logs | wc -l)"
echo "  Known Threats: $(./sinx-hunt iocs | wc -l)"

echo ""
echo "🌍 Top Attackers:"
./sinx-hunt logs 1000 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr | head -10
```

---

## 🎯 Real-World Integration Examples

### Connect Your Own Web App

```python
# In your web application
import requests

THREAT_HUNTER_API = "http://localhost:8000/api/v1"
TOKEN = "your_token_here"

def log_security_event(event_type, message, severity="medium"):
    """Send security events to threat hunter"""
    requests.post(
        f"{THREAT_HUNTER_API}/siem/ingest",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "event_type": event_type,
            "message": message,
            "severity": severity
        }
    )

# Example usage in your app:
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']

    if not authenticate(username):
        # Send failed login to threat hunter
        log_security_event(
            "authentication_failure",
            f"Failed login attempt for {username}",
            "warning"
        )
```

### Network-Wide Monitoring

```bash
# Monitor all network traffic
sudo tcpdump -i any -nn | while read line; do
    # Send suspicious patterns to threat hunter
    if echo "$line" | grep -qE "(scan|probe|attack)"; then
        ./sinx-hunt ingest "$line"
    fi
done
```

---

## 💡 Pro Tips

1. **Set up cron jobs** to automatically check for threats every hour
2. **Integrate with your firewall** to auto-block attacking IPs
3. **Connect to Slack/Discord** for real-time notifications
4. **Add threat feeds** from online sources to stay updated
5. **Create custom detection rules** for your specific environment

---

## 🚀 Start Using It NOW

```bash
# 1. Test with a fake attack
./sinx-hunt ingest "SQL Injection: SELECT * FROM users WHERE id='1 OR 1=1"

# 2. Watch it appear in dashboard (refresh browser)

# 3. Check the alert
./sinx-hunt alerts

# 4. Add the attacking IP to blocklist
./sinx-hunt add-ioc 192.168.1.100

# 5. View your threat intel database
./sinx-hunt iocs
```

This is a **working security operations center** - use it to actually protect your systems!
