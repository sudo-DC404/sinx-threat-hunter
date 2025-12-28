"""
sinX Threat Hunter - SIEM Engine
Log processing, parsing, and enrichment
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from ipaddress import ip_address, IPv4Address, IPv6Address

logger = logging.getLogger(__name__)


class SIEMEngine:
    """SIEM processing engine for log ingestion and analysis"""

    def __init__(self):
        self.parsers = {
            "json": self.parse_json,
            "syslog": self.parse_syslog,
            "cef": self.parse_cef,
            "apache": self.parse_apache,
            "nginx": self.parse_nginx,
        }

    def parse_log(self, raw_log: str, log_format: str = "auto") -> Dict[str, Any]:
        """
        Parse raw log into structured format

        Args:
            raw_log: Raw log string
            log_format: Format hint (auto, json, syslog, cef, apache, nginx)

        Returns:
            Parsed log data dictionary
        """
        if log_format == "auto":
            log_format = self.detect_format(raw_log)

        parser = self.parsers.get(log_format, self.parse_generic)

        try:
            parsed = parser(raw_log)
            return parsed
        except Exception as e:
            logger.error(f"Error parsing log: {e}")
            return self.parse_generic(raw_log)

    def detect_format(self, raw_log: str) -> str:
        """Auto-detect log format"""
        # Try JSON first
        if raw_log.strip().startswith('{'):
            return "json"

        # Check for CEF format
        if raw_log.startswith("CEF:"):
            return "cef"

        # Check for syslog pattern
        if re.match(r'^<\d+>', raw_log) or re.match(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', raw_log):
            return "syslog"

        # Check for Apache/Nginx access log
        if re.match(r'^\S+\s+-\s+-\s+\[', raw_log):
            return "apache"

        return "generic"

    def parse_json(self, raw_log: str) -> Dict[str, Any]:
        """Parse JSON formatted logs"""
        try:
            data = json.loads(raw_log)

            return {
                "timestamp": data.get("timestamp") or data.get("@timestamp"),
                "message": data.get("message") or raw_log,
                "event_type": data.get("event_type") or data.get("type"),
                "severity": data.get("severity") or data.get("level"),
                "source_ip": data.get("source_ip") or data.get("src_ip"),
                "dest_ip": data.get("dest_ip") or data.get("dst_ip"),
                "parsed_data": data,
            }
        except json.JSONDecodeError:
            return self.parse_generic(raw_log)

    def parse_syslog(self, raw_log: str) -> Dict[str, Any]:
        """Parse syslog formatted logs"""
        # RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        pattern = r'^(?:<(\d+)>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s+(.*)$'
        match = re.match(pattern, raw_log)

        if match:
            priority, timestamp, hostname, tag, message = match.groups()

            return {
                "timestamp": timestamp,
                "hostname": hostname,
                "message": message,
                "event_type": tag,
                "severity": self.priority_to_severity(int(priority)) if priority else "info",
                "parsed_data": {
                    "priority": priority,
                    "tag": tag,
                },
            }

        return self.parse_generic(raw_log)

    def parse_cef(self, raw_log: str) -> Dict[str, Any]:
        """Parse CEF (Common Event Format) logs"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        pattern = r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
        match = re.match(pattern, raw_log)

        if match:
            version, vendor, product, dev_version, signature, name, severity, extension = match.groups()

            # Parse extension key=value pairs
            ext_data = {}
            for pair in re.findall(r'(\w+)=([^\s]+(?:\s+[^\w=]+)?)', extension):
                ext_data[pair[0]] = pair[1].strip()

            return {
                "message": name,
                "event_type": signature,
                "severity": severity,
                "source_ip": ext_data.get("src"),
                "dest_ip": ext_data.get("dst"),
                "parsed_data": {
                    "vendor": vendor,
                    "product": product,
                    "version": dev_version,
                    "extension": ext_data,
                },
            }

        return self.parse_generic(raw_log)

    def parse_apache(self, raw_log: str) -> Dict[str, Any]:
        """Parse Apache access logs"""
        # Combined log format
        pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'
        match = re.match(pattern, raw_log)

        if match:
            ip, timestamp, request, status, size, referrer, user_agent = match.groups()

            return {
                "timestamp": timestamp,
                "source_ip": ip,
                "message": f"{request} - {status}",
                "event_type": "web_access",
                "severity": "info" if int(status) < 400 else "warning",
                "parsed_data": {
                    "request": request,
                    "status_code": int(status),
                    "response_size": int(size),
                    "referrer": referrer,
                    "user_agent": user_agent,
                },
            }

        return self.parse_generic(raw_log)

    def parse_nginx(self, raw_log: str) -> Dict[str, Any]:
        """Parse Nginx access logs (similar to Apache)"""
        return self.parse_apache(raw_log)

    def parse_generic(self, raw_log: str) -> Dict[str, Any]:
        """Generic parser for unknown formats"""
        # Try to extract IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_log)

        return {
            "message": raw_log,
            "event_type": "unknown",
            "severity": "info",
            "source_ip": ips[0] if ips else None,
            "parsed_data": {"raw": raw_log},
        }

    def priority_to_severity(self, priority: int) -> str:
        """Convert syslog priority to severity level"""
        severity_map = {
            0: "critical",  # Emergency
            1: "critical",  # Alert
            2: "critical",  # Critical
            3: "high",      # Error
            4: "medium",    # Warning
            5: "low",       # Notice
            6: "low",       # Informational
            7: "low",       # Debug
        }
        severity_level = priority & 0x07  # Extract severity from priority
        return severity_map.get(severity_level, "info")

    def enrich_log(self, parsed_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich log data with additional context

        - GeoIP lookup (placeholder)
        - DNS reverse lookup (placeholder)
        - Threat intelligence correlation (placeholder)
        """
        enrichment = {}

        # GeoIP enrichment (placeholder - would use MaxMind GeoIP2)
        if parsed_log.get("source_ip"):
            try:
                ip_obj = ip_address(parsed_log["source_ip"])
                if not ip_obj.is_private:
                    enrichment["geoip"] = {
                        "country": "Unknown",  # Placeholder
                        "city": "Unknown",
                        "latitude": 0.0,
                        "longitude": 0.0,
                    }
            except ValueError:
                pass

        # Reverse DNS (placeholder - would use dnspython)
        if parsed_log.get("source_ip"):
            enrichment["reverse_dns"] = None  # Placeholder

        return enrichment

    def classify_event(self, parsed_log: Dict[str, Any]) -> str:
        """Classify log event type based on content"""
        message = parsed_log.get("message", "").lower()

        # Authentication events
        if any(keyword in message for keyword in ["login", "authentication", "auth", "logon"]):
            if any(keyword in message for keyword in ["failed", "failure", "invalid", "denied"]):
                return "auth_failure"
            return "authentication"

        # Network events
        if any(keyword in message for keyword in ["connection", "tcp", "udp", "port"]):
            return "network"

        # Security events
        if any(keyword in message for keyword in ["attack", "exploit", "malware", "virus", "intrusion"]):
            return "security"

        # Web events
        if any(keyword in message for keyword in ["http", "web", "request", "get", "post"]):
            return "web"

        # System events
        if any(keyword in message for keyword in ["kernel", "system", "service", "process"]):
            return "system"

        return parsed_log.get("event_type", "unknown")
