"""
sinX Threat Hunter - Log Storage Model
Time-series optimized log storage with PostgreSQL + TimescaleDB
"""

from sqlalchemy import Column, Integer, String, Text, Index, TIMESTAMP, JSON
from datetime import datetime
from ..core.database import Base


class Log(Base):
    """
    Core log storage table - optimized for time-series data
    Works with both SQLite and PostgreSQL
    """
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=False, index=True, default=datetime.utcnow)

    # Network information (String for SQLite compatibility)
    source_ip = Column(String(45), index=True)  # IPv4 or IPv6
    source_port = Column(Integer)
    dest_ip = Column(String(45), index=True)  # IPv4 or IPv6
    dest_port = Column(Integer)

    # Event classification
    event_type = Column(String(100), index=True)  # auth, network, web, system, etc
    severity = Column(String(20), index=True)  # low, medium, high, critical

    # Message content
    message = Column(Text)
    raw_log = Column(Text)

    # Structured data (JSON for cross-database compatibility)
    parsed_data = Column(JSON)  # Parsed log fields
    enrichment = Column(JSON)  # GeoIP, reverse DNS, WHOIS, etc

    # Metadata
    log_source = Column(String(100), index=True)  # syslog, file, api, agent
    hostname = Column(String(255), index=True)

    # Indexes for high-performance queries
    __table_args__ = (
        Index('idx_timestamp_desc', timestamp.desc()),
        Index('idx_source_ip_timestamp', source_ip, timestamp.desc()),
        Index('idx_event_type_timestamp', event_type, timestamp.desc()),
        Index('idx_severity_timestamp', severity, timestamp.desc()),
        Index('idx_hostname_timestamp', hostname, timestamp.desc()),
    )

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": str(self.source_ip) if self.source_ip else None,
            "source_port": self.source_port,
            "dest_ip": str(self.dest_ip) if self.dest_ip else None,
            "dest_port": self.dest_port,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "parsed_data": self.parsed_data,
            "enrichment": self.enrichment,
            "log_source": self.log_source,
            "hostname": self.hostname,
        }
