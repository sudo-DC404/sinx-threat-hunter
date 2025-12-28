"""
sinX Threat Hunter - Threat Intelligence Engine
IOC management, feed processing, and enrichment
"""

import logging
import re
import httpx
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..models.iocs import IOC, ThreatFeed

logger = logging.getLogger(__name__)


class IntelEngine:
    """Threat Intelligence processing engine"""

    def __init__(self):
        self.feed_processors = {
            "alienvault": self.process_alienvault_feed,
            "abuseipdb": self.process_abuseipdb_feed,
            "tor_exits": self.process_tor_exits,
            "csv": self.process_csv_feed,
            "json": self.process_json_feed,
            "stix": self.process_stix_feed,
        }

    async def update_feed(self, feed: ThreatFeed, db: AsyncSession) -> int:
        """
        Update threat feed and import new IOCs

        Returns:
            Number of new IOCs imported
        """
        logger.info(f"Updating threat feed: {feed.name}")

        processor = self.feed_processors.get(feed.feed_type, self.process_generic_feed)

        try:
            iocs = await processor(feed)
            new_count = await self.import_iocs(iocs, feed.name, db)

            # Update feed statistics
            feed.last_update = datetime.utcnow()
            feed.ioc_count = new_count
            feed.last_error = None
            await db.commit()

            logger.info(f"Feed {feed.name} updated: {new_count} new IOCs")
            return new_count

        except Exception as e:
            logger.error(f"Error updating feed {feed.name}: {e}")
            feed.last_error = str(e)
            await db.commit()
            return 0

    async def process_alienvault_feed(self, feed: ThreatFeed) -> List[Dict]:
        """Process AlienVault OTX feed"""
        if not feed.api_key:
            raise ValueError("AlienVault API key required")

        # Placeholder - actual implementation would use OTX API
        logger.info("Processing AlienVault OTX feed (placeholder)")
        return []

    async def process_abuseipdb_feed(self, feed: ThreatFeed) -> List[Dict]:
        """Process AbuseIPDB feed"""
        if not feed.api_key:
            raise ValueError("AbuseIPDB API key required")

        # Placeholder - actual implementation would use AbuseIPDB API
        logger.info("Processing AbuseIPDB feed (placeholder)")
        return []

    async def process_tor_exits(self, feed: ThreatFeed) -> List[Dict]:
        """Process Tor exit nodes feed"""
        url = "https://check.torproject.org/torbulkexitlist"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()

                iocs = []
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Validate IP
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                            iocs.append({
                                "ioc_type": "ip",
                                "value": line,
                                "threat_type": "tor_exit",
                                "severity": "low",
                                "confidence": 100,
                                "tags": ["tor", "anonymization"],
                            })

                return iocs
        except Exception as e:
            logger.error(f"Error fetching Tor exits: {e}")
            return []

    async def process_csv_feed(self, feed: ThreatFeed) -> List[Dict]:
        """Process CSV formatted feed"""
        if not feed.url:
            raise ValueError("Feed URL required")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(feed.url, timeout=30.0)
                response.raise_for_status()

                # Simple CSV parser (would use proper CSV library in production)
                iocs = []
                for line in response.text.splitlines()[1:]:  # Skip header
                    fields = line.split(',')
                    if len(fields) >= 2:
                        iocs.append({
                            "ioc_type": fields[0].strip(),
                            "value": fields[1].strip(),
                            "threat_type": fields[2].strip() if len(fields) > 2 else "unknown",
                            "severity": "medium",
                            "confidence": 70,
                        })

                return iocs
        except Exception as e:
            logger.error(f"Error processing CSV feed: {e}")
            return []

    async def process_json_feed(self, feed: ThreatFeed) -> List[Dict]:
        """Process JSON formatted feed"""
        if not feed.url:
            raise ValueError("Feed URL required")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(feed.url, timeout=30.0)
                response.raise_for_status()

                data = response.json()

                # Assuming format: [{"type": "ip", "value": "1.2.3.4", ...}, ...]
                iocs = []
                for item in data if isinstance(data, list) else data.get("indicators", []):
                    iocs.append({
                        "ioc_type": item.get("type"),
                        "value": item.get("value"),
                        "threat_type": item.get("threat_type", "unknown"),
                        "severity": item.get("severity", "medium"),
                        "confidence": item.get("confidence", 50),
                        "tags": item.get("tags", []),
                    })

                return iocs
        except Exception as e:
            logger.error(f"Error processing JSON feed: {e}")
            return []

    async def process_stix_feed(self, feed: ThreatFeed) -> List[Dict]:
        """Process STIX formatted feed"""
        # Placeholder - would use stix2 library
        logger.info("Processing STIX feed (placeholder)")
        return []

    async def process_generic_feed(self, feed: ThreatFeed) -> List[Dict]:
        """Generic feed processor"""
        logger.warning(f"No specific processor for feed type: {feed.feed_type}")
        return []

    async def import_iocs(self, iocs: List[Dict], source: str, db: AsyncSession) -> int:
        """
        Import IOCs into database

        Returns:
            Number of new IOCs imported
        """
        new_count = 0

        for ioc_data in iocs:
            if not ioc_data.get("value"):
                continue

            # Check if IOC exists
            result = await db.execute(
                select(IOC).where(IOC.value == ioc_data["value"])
            )
            existing_ioc = result.scalar_one_or_none()

            if existing_ioc:
                # Update last_seen
                existing_ioc.last_seen = datetime.utcnow()
            else:
                # Create new IOC
                new_ioc = IOC(
                    ioc_type=ioc_data.get("ioc_type", "unknown"),
                    value=ioc_data["value"],
                    threat_type=ioc_data.get("threat_type"),
                    confidence=ioc_data.get("confidence", 50),
                    severity=ioc_data.get("severity", "medium"),
                    tags=ioc_data.get("tags", []),
                    source=source,
                    ioc_metadata=ioc_data.get("metadata", {}),
                    active=True,
                )
                db.add(new_ioc)
                new_count += 1

        await db.commit()
        return new_count

    async def check_ioc(self, value: str, db: AsyncSession) -> Optional[IOC]:
        """
        Check if a value is a known IOC

        Returns:
            IOC object if found, None otherwise
        """
        result = await db.execute(
            select(IOC).where(IOC.value == value, IOC.active == True)
        )
        return result.scalar_one_or_none()

    def extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extract potential IOCs from text

        Returns:
            Dictionary of IOC type to list of values
        """
        iocs = {
            "ip": [],
            "domain": [],
            "url": [],
            "email": [],
            "hash": [],
        }

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs["ip"] = re.findall(ip_pattern, text)

        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs["domain"] = re.findall(domain_pattern, text)

        # URLs
        url_pattern = r'https?://[^\s<>"]+'
        iocs["url"] = re.findall(url_pattern, text)

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs["email"] = re.findall(email_pattern, text)

        # Hashes (MD5, SHA1, SHA256)
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

        iocs["hash"] = (
            re.findall(md5_pattern, text) +
            re.findall(sha1_pattern, text) +
            re.findall(sha256_pattern, text)
        )

        return iocs
