"""
sinX Threat Hunter - SOAR Playbook Models
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, TIMESTAMP, ForeignKey, JSON
from datetime import datetime
from ..core.database import Base


class Playbook(Base):
    """Automated response playbooks"""
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Playbook identification
    name = Column(String(200), nullable=False, unique=True)
    description = Column(Text)

    # Configuration
    enabled = Column(Boolean, default=True, index=True)

    # Trigger configuration
    trigger_type = Column(String(50), index=True)  # alert, manual, scheduled, webhook
    trigger_conditions = Column(JSON)  # Conditions for auto-execution

    # Workflow definition
    workflow = Column(JSON, nullable=False)  # DAG of actions

    # Approval settings
    requires_approval = Column(Boolean, default=False)
    approvers = Column(JSON)  # List of user IDs who can approve

    # Metadata
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    updated_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(100))

    # Statistics
    execution_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "trigger_type": self.trigger_type,
            "trigger_conditions": self.trigger_conditions,
            "workflow": self.workflow,
            "requires_approval": self.requires_approval,
            "approvers": self.approvers,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": self.created_by,
            "execution_count": self.execution_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
        }


class PlaybookExecution(Base):
    """Playbook execution history and logs"""
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Relationship
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="CASCADE"), index=True)

    # Execution info
    triggered_by = Column(String(100))
    triggered_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow, index=True)

    # Status
    status = Column(String(50), default="running", index=True)  # running, completed, failed, cancelled

    # Data
    input_data = Column(JSON)  # Input parameters
    execution_log = Column(JSON)  # Step-by-step execution log
    output_data = Column(JSON)  # Results
    error_message = Column(Text)

    # Timing
    completed_at = Column(TIMESTAMP(timezone=True))
    duration_seconds = Column(Integer)

    # Approval
    approval_status = Column(String(50))  # pending, approved, rejected
    approved_by = Column(String(100))
    approved_at = Column(TIMESTAMP(timezone=True))

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "playbook_id": self.playbook_id,
            "triggered_by": self.triggered_by,
            "triggered_at": self.triggered_at.isoformat() if self.triggered_at else None,
            "status": self.status,
            "input_data": self.input_data,
            "execution_log": self.execution_log,
            "output_data": self.output_data,
            "error_message": self.error_message,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "approval_status": self.approval_status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
        }
