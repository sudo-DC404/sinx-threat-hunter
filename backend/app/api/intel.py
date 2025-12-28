"""
sinX Threat Hunter - Threat Intelligence API
IOC management, threat feeds, and enrichment
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, or_
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from ..core.database import get_db
from ..core.security import get_current_user
from ..models.iocs import IOC, ThreatFeed, ThreatActor
from ..models.users import User

router = APIRouter(prefix="/intel")


# Pydantic schemas
class IOCCreate(BaseModel):
    ioc_type: str  # ip, domain, hash, url, email
    value: str
    threat_type: Optional[str] = None
    confidence: Optional[int] = 50
    severity: Optional[str] = "medium"
    tags: Optional[list[str]] = []
    source: str = "manual"
    metadata: Optional[dict] = None
    mitre_tactics: Optional[list[str]] = []
    mitre_techniques: Optional[list[str]] = []


class IOCResponse(BaseModel):
    id: int
    ioc_type: str
    value: str
    threat_type: Optional[str]
    confidence: Optional[int]
    severity: Optional[str]
    first_seen: datetime
    last_seen: datetime
    tags: Optional[list[str]]
    source: str
    active: bool


class ThreatFeedCreate(BaseModel):
    name: str
    url: Optional[str] = None
    feed_type: str  # stix, csv, json, api
    update_interval: int = 60
    api_key: Optional[str] = None
    enabled: bool = True


@router.post("/iocs", response_model=IOCResponse, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    ioc_data: IOCCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new IOC"""

    # Check if IOC already exists
    result = await db.execute(select(IOC).where(IOC.value == ioc_data.value))
    existing_ioc = result.scalar_one_or_none()

    if existing_ioc:
        raise HTTPException(status_code=400, detail="IOC already exists")

    new_ioc = IOC(
        ioc_type=ioc_data.ioc_type,
        value=ioc_data.value,
        threat_type=ioc_data.threat_type,
        confidence=ioc_data.confidence,
        severity=ioc_data.severity,
        tags=ioc_data.tags,
        source=ioc_data.source,
        metadata=ioc_data.metadata,
        mitre_tactics=ioc_data.mitre_tactics,
        mitre_techniques=ioc_data.mitre_techniques,
        active=True,
    )

    db.add(new_ioc)
    await db.commit()
    await db.refresh(new_ioc)

    return new_ioc


@router.get("/iocs", response_model=list[IOCResponse])
async def list_iocs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    active_only: bool = True,
    skip: int = 0,
    limit: int = 100
):
    """List IOCs with filters"""

    query = select(IOC)

    if active_only:
        query = query.where(IOC.active == True)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if severity:
        query = query.where(IOC.severity == severity)
    if source:
        query = query.where(IOC.source == source)

    query = query.order_by(desc(IOC.last_seen)).offset(skip).limit(limit)

    result = await db.execute(query)
    iocs = result.scalars().all()

    return iocs


@router.get("/iocs/search")
async def search_iocs(
    value: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Search for an IOC by value"""

    result = await db.execute(
        select(IOC).where(IOC.value.ilike(f"%{value}%")).limit(50)
    )
    iocs = result.scalars().all()

    return {"count": len(iocs), "results": [ioc.to_dict() for ioc in iocs]}


@router.post("/iocs/batch", status_code=status.HTTP_201_CREATED)
async def create_iocs_batch(
    iocs: list[IOCCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Batch create IOCs"""

    new_iocs = []
    for ioc_data in iocs:
        # Skip if exists
        result = await db.execute(select(IOC).where(IOC.value == ioc_data.value))
        if result.scalar_one_or_none():
            continue

        new_ioc = IOC(
            ioc_type=ioc_data.ioc_type,
            value=ioc_data.value,
            threat_type=ioc_data.threat_type,
            confidence=ioc_data.confidence,
            severity=ioc_data.severity,
            tags=ioc_data.tags,
            source=ioc_data.source,
            metadata=ioc_data.metadata,
            mitre_tactics=ioc_data.mitre_tactics,
            mitre_techniques=ioc_data.mitre_techniques,
            active=True,
        )
        new_iocs.append(new_ioc)

    db.add_all(new_iocs)
    await db.commit()

    return {"count": len(new_iocs), "status": "created"}


@router.delete("/iocs/{ioc_id}")
async def delete_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete (deactivate) an IOC"""

    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()

    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.active = False
    await db.commit()

    return {"status": "deleted", "id": ioc_id}


@router.post("/feeds", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_feed(
    feed_data: ThreatFeedCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new threat feed"""

    new_feed = ThreatFeed(
        name=feed_data.name,
        url=feed_data.url,
        feed_type=feed_data.feed_type,
        update_interval=feed_data.update_interval,
        api_key=feed_data.api_key,
        enabled=feed_data.enabled,
    )

    db.add(new_feed)
    await db.commit()
    await db.refresh(new_feed)

    return new_feed.to_dict()


@router.get("/feeds")
async def list_feeds(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all threat feeds"""

    result = await db.execute(select(ThreatFeed))
    feeds = result.scalars().all()

    return [feed.to_dict() for feed in feeds]
