"""
sinX Threat Hunter - Threat Hunting Session Model
"""

from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON
from datetime import datetime
from ..core.database import Base


class HuntSession(Base):
    """Threat hunting sessions for tracking investigations"""
    __tablename__ = "hunt_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Session identification
    name = Column(String(200), nullable=False)
    hypothesis = Column(Text)  # What are we hunting for?

    # Status
    status = Column(String(50), default="active", index=True)  # active, completed, archived

    # Data
    queries = Column(JSON)  # Saved queries and filters
    findings = Column(JSON)  # Evidence collected

    # Relationships
    iocs_found = Column(JSON)  # Array of IOC IDs discovered
    alerts_related = Column(JSON)  # Related alerts
    logs_examined = Column(Integer, default=0)  # Count of logs reviewed

    # Conclusion
    conclusion = Column(Text)
    recommendations = Column(Text)

    # Metadata
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow, index=True)
    updated_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(TIMESTAMP(timezone=True))
    created_by = Column(String(100), index=True)

    # Tags
    tags = Column(JSON)

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "hypothesis": self.hypothesis,
            "status": self.status,
            "queries": self.queries,
            "findings": self.findings,
            "iocs_found": self.iocs_found,
            "alerts_related": self.alerts_related,
            "logs_examined": self.logs_examined,
            "conclusion": self.conclusion,
            "recommendations": self.recommendations,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
            "tags": self.tags,
        }
