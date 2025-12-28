#!/bin/bash

echo "🎯 sinX Threat Hunter - Live Examples"
echo "======================================"
echo ""

# Example 1: Simulate a brute force attack
echo "1️⃣ Simulating SSH brute force attack..."
for i in {1..5}; do
    ./sinx-hunt ingest "Failed password for admin from 45.142.212.61 port 52341 ssh2"
    sleep 0.5
done
echo "   ✓ Sent 5 failed login attempts"
echo ""

# Example 2: Simulate SQL injection
echo "2️⃣ Simulating SQL injection attack..."
./sinx-hunt ingest "Web request: /api/users?id=1' UNION SELECT * FROM passwords--"
echo "   ✓ SQL injection attempt logged"
echo ""

# Example 3: Add malicious IPs
echo "3️⃣ Adding known malicious IPs to threat intel..."
./sinx-hunt add-ioc 45.142.212.61
./sinx-hunt add-ioc 103.225.138.45
echo "   ✓ Added 2 malicious IPs"
echo ""

# Example 4: Check for alerts
echo "4️⃣ Checking for new alerts..."
sleep 2
./sinx-hunt alerts 5
echo ""

# Example 5: View dashboard stats
echo "5️⃣ Current threat landscape:"
./sinx-hunt dashboard
echo ""

echo "======================================"
echo "✅ Examples complete!"
echo ""
echo "Now open your browser: http://localhost:8080"
echo "You should see all these events in the dashboard!"
