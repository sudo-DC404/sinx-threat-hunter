"""
sinX Threat Hunter - Advanced Log Parsers
Parsers for various log formats beyond basic SIEM engine
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)


class LogParser:
    """
    Advanced log parsing utilities
    """

    # Common regex patterns
    PATTERNS = {
        'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'url': r'https?://[^\s]+',
        'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b',
        'hash_md5': r'\b[a-fA-F0-9]{32}\b',
        'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
        'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
        'cve': r'CVE-\d{4}-\d{4,7}',
        'user': r'user[=:]?\s*(\w+)',
        'pid': r'pid[=:]?\s*(\d+)',
    }

    @staticmethod
    def extract_iocs(text: str) -> Dict[str, List[str]]:
        """
        Extract Indicators of Compromise from log text
        Returns: Dict with IOC types and their values
        """
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'emails': [],
            'hashes': [],
            'cves': []
        }

        # Extract IPs
        ips = re.findall(LogParser.PATTERNS['ipv4'], text)
        iocs['ips'].extend(ips)

        # Extract domains
        domains = re.findall(LogParser.PATTERNS['domain'], text)
        iocs['domains'].extend(domains)

        # Extract URLs
        urls = re.findall(LogParser.PATTERNS['url'], text)
        iocs['urls'].extend(urls)

        # Extract emails
        emails = re.findall(LogParser.PATTERNS['email'], text)
        iocs['emails'].extend(emails)

        # Extract hashes
        md5_hashes = re.findall(LogParser.PATTERNS['hash_md5'], text)
        sha1_hashes = re.findall(LogParser.PATTERNS['hash_sha1'], text)
        sha256_hashes = re.findall(LogParser.PATTERNS['hash_sha256'], text)
        iocs['hashes'].extend(md5_hashes + sha1_hashes + sha256_hashes)

        # Extract CVEs
        cves = re.findall(LogParser.PATTERNS['cve'], text)
        iocs['cves'].extend(cves)

        # Remove duplicates
        for key in iocs:
            iocs[key] = list(set(iocs[key]))

        return iocs

    @staticmethod
    def parse_cef(cef_string: str) -> Dict[str, Any]:
        """
        Parse Common Event Format (CEF)
        Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        try:
            parts = cef_string.split('|')
            if len(parts) < 8:
                return {}

            parsed = {
                'cef_version': parts[0].replace('CEF:', ''),
                'device_vendor': parts[1],
                'device_product': parts[2],
                'device_version': parts[3],
                'signature_id': parts[4],
                'name': parts[5],
                'severity': parts[6],
                'extension': parts[7] if len(parts) > 7 else ''
            }

            # Parse extension fields (key=value pairs)
            extension_fields = {}
            if parsed['extension']:
                # Split by space but respect quotes
                for match in re.finditer(r'(\w+)=([^\s]+(?:\s+[^\s=]+)*)', parsed['extension']):
                    key, value = match.groups()
                    extension_fields[key] = value

            parsed['fields'] = extension_fields

            return parsed

        except Exception as e:
            logger.error(f"Error parsing CEF: {e}")
            return {}

    @staticmethod
    def parse_leef(leef_string: str) -> Dict[str, Any]:
        """
        Parse Log Event Extended Format (LEEF)
        Format: LEEF:Version|Vendor|Product|Version|EventID|key1=value1<tab>key2=value2
        """
        try:
            parts = leef_string.split('|')
            if len(parts) < 6:
                return {}

            parsed = {
                'leef_version': parts[0].replace('LEEF:', ''),
                'vendor': parts[1],
                'product': parts[2],
                'version': parts[3],
                'event_id': parts[4],
                'fields': {}
            }

            # Parse fields (tab or pipe separated)
            if len(parts) > 5:
                fields_string = '|'.join(parts[5:])
                for field in fields_string.split('\t'):
                    if '=' in field:
                        key, value = field.split('=', 1)
                        parsed['fields'][key] = value

            return parsed

        except Exception as e:
            logger.error(f"Error parsing LEEF: {e}")
            return {}

    @staticmethod
    def parse_key_value(text: str, delimiter: str = '=') -> Dict[str, str]:
        """
        Parse key=value formatted logs
        """
        fields = {}
        pattern = rf'(\w+){re.escape(delimiter)}([^\s]+|"[^"]*")'

        for match in re.finditer(pattern, text):
            key, value = match.groups()
            # Remove quotes if present
            value = value.strip('"')
            fields[key] = value

        return fields

    @staticmethod
    def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        """
        Parse various timestamp formats
        """
        try:
            return date_parser.parse(timestamp_str)
        except Exception:
            return None

    @staticmethod
    def detect_attack_patterns(log_text: str) -> List[str]:
        """
        Detect common attack patterns in log text
        """
        attacks = []

        patterns = {
            'SQL Injection': [
                r"(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table)",
                r"(?i)('|\")\s*(or|and)\s*\d+\s*[=><]",
                r"(?i)(--|\#|\/\*|\*\/)",
            ],
            'XSS': [
                r"(?i)<script[^>]*>.*?</script>",
                r"(?i)javascript:",
                r"(?i)on\w+\s*=",
            ],
            'Command Injection': [
                r"(?i)(\||;|`|\$\(|\${).*?(ls|cat|wget|curl|nc|bash|sh|cmd|powershell)",
                r"(?i)(&&|\|\|)",
            ],
            'Path Traversal': [
                r"\.\./|\.\.\\",
                r"(?i)(/etc/passwd|/etc/shadow|c:\\windows)",
            ],
            'LDAP Injection': [
                r"(?i)(\*|\(|\)|\||&)",
            ],
            'XXE': [
                r"(?i)<!entity",
                r"(?i)<!doctype",
            ]
        }

        for attack_type, attack_patterns in patterns.items():
            for pattern in attack_patterns:
                if re.search(pattern, log_text):
                    attacks.append(attack_type)
                    break

        return list(set(attacks))

    @staticmethod
    def normalize_severity(severity: str) -> str:
        """
        Normalize severity levels to standard format
        """
        severity = severity.lower().strip()

        severity_map = {
            'emerg': 'critical',
            'emergency': 'critical',
            'alert': 'critical',
            'crit': 'critical',
            'critical': 'critical',
            'err': 'error',
            'error': 'error',
            'warn': 'warning',
            'warning': 'warning',
            'notice': 'info',
            'info': 'info',
            'debug': 'debug',
            'trace': 'debug'
        }

        # Handle numeric syslog severities
        numeric_map = {
            '0': 'critical',
            '1': 'critical',
            '2': 'critical',
            '3': 'error',
            '4': 'warning',
            '5': 'info',
            '6': 'info',
            '7': 'debug'
        }

        if severity in severity_map:
            return severity_map[severity]
        elif severity in numeric_map:
            return numeric_map[severity]
        else:
            return 'info'
