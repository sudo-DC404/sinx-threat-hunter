"""
sinX Threat Hunter - Log Enrichment
Add context to logs: GeoIP, DNS, WHOIS, IOC lookups
"""

import logging
import socket
from typing import Dict, Any, Optional
import asyncio

logger = logging.getLogger(__name__)


class Enricher:
    """
    Enrich log data with additional context
    """

    def __init__(self):
        # GeoIP database would be initialized here
        # For now, using mock implementation
        self.geoip_enabled = False
        try:
            import geoip2.database
            # self.geoip_reader = geoip2.database.Reader('/path/to/GeoLite2-City.mmdb')
            # self.geoip_enabled = True
        except ImportError:
            logger.warning("GeoIP2 not available, geolocation enrichment disabled")

    async def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Enrich IP address with geolocation and reverse DNS
        """
        enrichment = {
            'ip': ip_address,
            'geolocation': None,
            'reverse_dns': None,
            'is_private': self.is_private_ip(ip_address),
            'is_tor': False,  # TODO: Check against Tor exit node list
        }

        # GeoIP lookup
        if self.geoip_enabled and not enrichment['is_private']:
            try:
                response = self.geoip_reader.city(ip_address)
                enrichment['geolocation'] = {
                    'country': response.country.name,
                    'country_code': response.country.iso_code,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'timezone': response.location.time_zone,
                }
            except Exception as e:
                logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")

        # Reverse DNS lookup
        if not enrichment['is_private']:
            try:
                hostname = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: socket.gethostbyaddr(ip_address)[0]
                )
                enrichment['reverse_dns'] = hostname
            except Exception as e:
                logger.debug(f"Reverse DNS failed for {ip_address}: {e}")

        return enrichment

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if IP is private/internal
        """
        try:
            parts = list(map(int, ip.split('.')))
            if len(parts) != 4:
                return False

            # RFC 1918 private addresses
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True

            # Loopback
            if parts[0] == 127:
                return True

            # Link-local
            if parts[0] == 169 and parts[1] == 254:
                return True

            return False

        except Exception:
            return False

    async def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """
        Enrich domain with DNS and WHOIS info
        """
        enrichment = {
            'domain': domain,
            'ip_addresses': [],
            'whois': None,
        }

        # DNS lookup
        try:
            ip_addresses = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: socket.gethostbyname_ex(domain)[2]
            )
            enrichment['ip_addresses'] = ip_addresses
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")

        # WHOIS lookup (basic implementation)
        try:
            import whois
            w = whois.whois(domain)
            enrichment['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
            }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")

        return enrichment

    async def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Enrich file hash with threat intelligence
        """
        enrichment = {
            'hash': file_hash,
            'hash_type': self.detect_hash_type(file_hash),
            'virustotal': None,
            'is_malicious': False,
        }

        # VirusTotal lookup would go here
        # Requires API key and implementation
        # enrichment['virustotal'] = await self.virustotal_lookup(file_hash)

        return enrichment

    @staticmethod
    def detect_hash_type(hash_string: str) -> Optional[str]:
        """
        Detect hash algorithm based on length
        """
        hash_len = len(hash_string)

        if hash_len == 32:
            return 'md5'
        elif hash_len == 40:
            return 'sha1'
        elif hash_len == 64:
            return 'sha256'
        elif hash_len == 128:
            return 'sha512'
        else:
            return None

    async def enrich_user(self, username: str) -> Dict[str, Any]:
        """
        Enrich user information
        """
        enrichment = {
            'username': username,
            'is_privileged': username in ['root', 'admin', 'administrator'],
            'is_service_account': username.endswith('$') or username.startswith('svc'),
        }

        return enrichment

    async def enrich_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich entire log entry with all available context
        """
        enrichment = {}

        # Enrich source IP
        if 'source_ip' in log_data and log_data['source_ip']:
            try:
                enrichment['source_ip_info'] = await self.enrich_ip(
                    log_data['source_ip']
                )
            except Exception as e:
                logger.error(f"Error enriching source IP: {e}")

        # Enrich destination IP
        if 'dest_ip' in log_data and log_data['dest_ip']:
            try:
                enrichment['dest_ip_info'] = await self.enrich_ip(
                    log_data['dest_ip']
                )
            except Exception as e:
                logger.error(f"Error enriching dest IP: {e}")

        # Enrich username
        if 'username' in log_data and log_data['username']:
            try:
                enrichment['user_info'] = await self.enrich_user(
                    log_data['username']
                )
            except Exception as e:
                logger.error(f"Error enriching user: {e}")

        # Add reputation scores (placeholder)
        enrichment['reputation'] = {
            'source_score': 50,  # 0-100, higher is more trustworthy
            'threat_level': 'low'  # low, medium, high, critical
        }

        return enrichment


# Global enricher instance
enricher = Enricher()
