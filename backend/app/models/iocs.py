"""
sinX Threat Hunter - Threat Intelligence Models
IOCs, Threat Feeds, and Threat Actor tracking
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, TIMESTAMP, JSON, CheckConstraint
from datetime import datetime
from ..core.database import Base


class IOC(Base):
    """Indicator of Compromise storage"""
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # IOC identification
    ioc_type = Column(String(50), nullable=False, index=True)  # ip, domain, hash, url, email
    value = Column(Text, nullable=False, unique=True, index=True)

    # Classification
    threat_type = Column(String(100), index=True)  # malware, c2, phishing, scanner, etc
    confidence = Column(Integer, CheckConstraint('confidence >= 0 AND confidence <= 100'))
    severity = Column(String(20), index=True)  # low, medium, high, critical

    # Temporal data
    first_seen = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    last_seen = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    expires_at = Column(TIMESTAMP(timezone=True))

    # Context (JSON for cross-database compatibility)
    tags = Column(JSON)  # Array stored as JSON
    source = Column(String(100), index=True)  # Feed name or "manual"
    ioc_metadata = Column(JSON)  # Additional context (renamed from metadata - reserved keyword)

    # MITRE ATT&CK mapping (JSON for cross-database compatibility)
    mitre_tactics = Column(JSON)  # Array stored as JSON
    mitre_techniques = Column(JSON)  # Array stored as JSON

    # Status
    active = Column(Boolean, default=True, index=True)
    false_positive = Column(Boolean, default=False)

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "tags": self.tags,
            "source": self.source,
            "metadata": self.ioc_metadata,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "active": self.active,
            "false_positive": self.false_positive,
        }


class ThreatFeed(Base):
    """Threat intelligence feed configuration"""
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Feed identification
    name = Column(String(100), unique=True, nullable=False)
    url = Column(Text)
    feed_type = Column(String(50))  # stix, csv, json, api

    # Configuration
    enabled = Column(Boolean, default=True, index=True)
    update_interval = Column(Integer, default=60)  # minutes
    api_key = Column(Text)  # Encrypted storage recommended

    # Statistics
    last_update = Column(TIMESTAMP(timezone=True))
    ioc_count = Column(Integer, default=0)
    last_error = Column(Text)

    # Metadata
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "feed_type": self.feed_type,
            "enabled": self.enabled,
            "update_interval": self.update_interval,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "ioc_count": self.ioc_count,
            "last_error": self.last_error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ThreatActor(Base):
    """Threat actor profiles and tracking"""
    __tablename__ = "threat_actors"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Identification
    name = Column(String(100), unique=True, nullable=False)
    aliases = Column(JSON)  # Array stored as JSON

    # Attribution
    country = Column(String(50))
    motivation = Column(Text)  # Financial, espionage, hacktivism, etc

    # Capabilities
    capabilities = Column(JSON)  # Tools, techniques, sophistication

    # Relationships
    associated_iocs = Column(JSON)  # Array of IOC IDs stored as JSON
    campaigns = Column(JSON)  # Array stored as JSON

    # MITRE ATT&CK
    mitre_groups = Column(JSON)  # Array stored as JSON (APT28, Lazarus, etc)

    # Metadata
    first_observed = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    last_activity = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "aliases": self.aliases,
            "country": self.country,
            "motivation": self.motivation,
            "capabilities": self.capabilities,
            "associated_iocs": self.associated_iocs,
            "campaigns": self.campaigns,
            "mitre_groups": self.mitre_groups,
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
        }
