"""
sinX Threat Hunter - Alert Management API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from ..core.database import get_db
from ..core.security import get_current_user
from ..models.alerts import Alert, DetectionRule
from ..models.users import User

router = APIRouter(prefix="/alerts")


class AlertResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    triggered_at: datetime
    assigned_to: Optional[str]


class DetectionRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    severity: str
    rule_type: str
    rule_definition: dict
    enabled: bool = True
    tags: Optional[list[str]] = []


@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    """List alerts with filters"""

    query = select(Alert)

    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if assigned_to:
        query = query.where(Alert.assigned_to == assigned_to)

    query = query.order_by(desc(Alert.triggered_at)).offset(skip).limit(limit)

    result = await db.execute(query)
    alerts = result.scalars().all()

    return alerts


@router.get("/{alert_id}")
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get alert details"""

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert.to_dict()


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: int,
    new_status: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update alert status"""

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = new_status
    if new_status == "investigating":
        alert.acknowledged_at = datetime.utcnow()
        alert.assigned_to = current_user.username
    elif new_status == "resolved":
        alert.resolved_at = datetime.utcnow()

    await db.commit()

    return {"status": "updated", "id": alert_id, "new_status": new_status}


@router.get("/stats/summary")
async def get_alert_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get alert statistics"""

    # Total alerts
    total_result = await db.execute(select(func.count(Alert.id)))
    total_alerts = total_result.scalar()

    # Count by status
    status_result = await db.execute(
        select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    )
    status_counts = {row[0]: row[1] for row in status_result.all()}

    # Count by severity
    severity_result = await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )
    severity_counts = {row[0]: row[1] for row in severity_result.all()}

    return {
        "total_alerts": total_alerts,
        "status_breakdown": status_counts,
        "severity_breakdown": severity_counts,
    }


@router.post("/rules", status_code=201)
async def create_detection_rule(
    rule_data: DetectionRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new detection rule"""

    new_rule = DetectionRule(
        name=rule_data.name,
        description=rule_data.description,
        severity=rule_data.severity,
        rule_type=rule_data.rule_type,
        rule_definition=rule_data.rule_definition,
        enabled=rule_data.enabled,
        tags=rule_data.tags,
        created_by=current_user.username,
    )

    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)

    return new_rule.to_dict()


@router.get("/rules")
async def list_detection_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    enabled_only: bool = True,
    skip: int = 0,
    limit: int = 100
):
    """List detection rules"""

    query = select(DetectionRule)

    if enabled_only:
        query = query.where(DetectionRule.enabled == True)

    query = query.order_by(desc(DetectionRule.created_at)).offset(skip).limit(limit)

    result = await db.execute(query)
    rules = result.scalars().all()

    return [rule.to_dict() for rule in rules]
