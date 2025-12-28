"""
sinX Threat Hunter - Threat Hunting API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from ..core.database import get_db
from ..core.security import get_current_user
from ..models.hunts import HuntSession
from ..models.users import User

router = APIRouter(prefix="/hunts")


class HuntSessionCreate(BaseModel):
    name: str
    hypothesis: Optional[str] = None
    tags: Optional[list[str]] = []


class HuntSessionUpdate(BaseModel):
    name: Optional[str] = None
    hypothesis: Optional[str] = None
    status: Optional[str] = None
    queries: Optional[dict] = None
    findings: Optional[dict] = None
    conclusion: Optional[str] = None
    recommendations: Optional[str] = None


@router.post("", status_code=201)
async def create_hunt_session(
    hunt_data: HuntSessionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new threat hunt session"""

    new_hunt = HuntSession(
        name=hunt_data.name,
        hypothesis=hunt_data.hypothesis,
        status="active",
        created_by=current_user.username,
        tags=hunt_data.tags,
        queries={},
        findings={},
    )

    db.add(new_hunt)
    await db.commit()
    await db.refresh(new_hunt)

    return new_hunt.to_dict()


@router.get("")
async def list_hunt_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    status: Optional[str] = None,
    created_by: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    """List threat hunt sessions"""

    query = select(HuntSession)

    if status:
        query = query.where(HuntSession.status == status)
    if created_by:
        query = query.where(HuntSession.created_by == created_by)

    query = query.order_by(desc(HuntSession.created_at)).offset(skip).limit(limit)

    result = await db.execute(query)
    hunts = result.scalars().all()

    return [hunt.to_dict() for hunt in hunts]


@router.get("/{hunt_id}")
async def get_hunt_session(
    hunt_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get hunt session details"""

    result = await db.execute(select(HuntSession).where(HuntSession.id == hunt_id))
    hunt = result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt session not found")

    return hunt.to_dict()


@router.patch("/{hunt_id}")
async def update_hunt_session(
    hunt_id: int,
    hunt_update: HuntSessionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update hunt session"""

    result = await db.execute(select(HuntSession).where(HuntSession.id == hunt_id))
    hunt = result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt session not found")

    # Update fields
    if hunt_update.name:
        hunt.name = hunt_update.name
    if hunt_update.hypothesis is not None:
        hunt.hypothesis = hunt_update.hypothesis
    if hunt_update.status:
        hunt.status = hunt_update.status
        if hunt_update.status == "completed":
            hunt.completed_at = datetime.utcnow()
    if hunt_update.queries is not None:
        hunt.queries = hunt_update.queries
    if hunt_update.findings is not None:
        hunt.findings = hunt_update.findings
    if hunt_update.conclusion is not None:
        hunt.conclusion = hunt_update.conclusion
    if hunt_update.recommendations is not None:
        hunt.recommendations = hunt_update.recommendations

    hunt.updated_at = datetime.utcnow()
    await db.commit()

    return hunt.to_dict()


@router.delete("/{hunt_id}")
async def delete_hunt_session(
    hunt_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete hunt session"""

    result = await db.execute(select(HuntSession).where(HuntSession.id == hunt_id))
    hunt = result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt session not found")

    await db.delete(hunt)
    await db.commit()

    return {"status": "deleted", "id": hunt_id}
