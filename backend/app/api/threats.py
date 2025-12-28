"""
sinX Threat Hunter - Threat Management API
Threat actor profiles and campaign tracking
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import Optional

from ..core.database import get_db
from ..core.security import get_current_user
from ..models.iocs import ThreatActor
from ..models.users import User

router = APIRouter(prefix="/threats")


class ThreatActorCreate(BaseModel):
    name: str
    aliases: Optional[list[str]] = []
    country: Optional[str] = None
    motivation: Optional[str] = None
    capabilities: Optional[dict] = None
    campaigns: Optional[list[str]] = []
    mitre_groups: Optional[list[str]] = []


@router.post("/actors", status_code=201)
async def create_threat_actor(
    actor_data: ThreatActorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new threat actor profile"""

    # Check if exists
    result = await db.execute(select(ThreatActor).where(ThreatActor.name == actor_data.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Threat actor already exists")

    new_actor = ThreatActor(
        name=actor_data.name,
        aliases=actor_data.aliases,
        country=actor_data.country,
        motivation=actor_data.motivation,
        capabilities=actor_data.capabilities,
        campaigns=actor_data.campaigns,
        mitre_groups=actor_data.mitre_groups,
    )

    db.add(new_actor)
    await db.commit()
    await db.refresh(new_actor)

    return new_actor.to_dict()


@router.get("/actors")
async def list_threat_actors(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    country: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    """List threat actors"""

    query = select(ThreatActor)

    if country:
        query = query.where(ThreatActor.country == country)

    query = query.order_by(desc(ThreatActor.last_activity)).offset(skip).limit(limit)

    result = await db.execute(query)
    actors = result.scalars().all()

    return [actor.to_dict() for actor in actors]


@router.get("/actors/{actor_id}")
async def get_threat_actor(
    actor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat actor details"""

    result = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    actor = result.scalar_one_or_none()

    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")

    return actor.to_dict()
