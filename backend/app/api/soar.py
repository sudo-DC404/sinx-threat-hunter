"""
sinX Threat Hunter - SOAR API
Playbook management and execution
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from ..core.database import get_db
from ..core.security import get_current_user
from ..models.playbooks import Playbook, PlaybookExecution
from ..models.users import User

router = APIRouter(prefix="/soar")


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: str  # alert, manual, scheduled, webhook
    trigger_conditions: Optional[dict] = None
    workflow: dict
    enabled: bool = True
    requires_approval: bool = False


class PlaybookExecutionCreate(BaseModel):
    playbook_id: int
    input_data: Optional[dict] = None


@router.post("/playbooks", status_code=201)
async def create_playbook(
    playbook_data: PlaybookCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new playbook"""

    new_playbook = Playbook(
        name=playbook_data.name,
        description=playbook_data.description,
        trigger_type=playbook_data.trigger_type,
        trigger_conditions=playbook_data.trigger_conditions,
        workflow=playbook_data.workflow,
        enabled=playbook_data.enabled,
        requires_approval=playbook_data.requires_approval,
        created_by=current_user.username,
    )

    db.add(new_playbook)
    await db.commit()
    await db.refresh(new_playbook)

    return new_playbook.to_dict()


@router.get("/playbooks")
async def list_playbooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    enabled_only: bool = True,
    skip: int = 0,
    limit: int = 100
):
    """List playbooks"""

    query = select(Playbook)

    if enabled_only:
        query = query.where(Playbook.enabled == True)

    query = query.order_by(desc(Playbook.created_at)).offset(skip).limit(limit)

    result = await db.execute(query)
    playbooks = result.scalars().all()

    return [pb.to_dict() for pb in playbooks]


@router.post("/playbooks/{playbook_id}/execute", status_code=201)
async def execute_playbook(
    playbook_id: int,
    execution_data: PlaybookExecutionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Execute a playbook"""

    # Get playbook
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if not playbook.enabled:
        raise HTTPException(status_code=400, detail="Playbook is disabled")

    # Create execution record
    execution = PlaybookExecution(
        playbook_id=playbook_id,
        triggered_by=current_user.username,
        input_data=execution_data.input_data,
        status="running",
    )

    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    # TODO: Actual playbook execution logic would go here
    # For now, just mark as completed
    execution.status = "completed"
    execution.completed_at = datetime.utcnow()
    execution.execution_log = {"steps": ["Playbook execution placeholder"]}

    await db.commit()

    return execution.to_dict()


@router.get("/executions")
async def list_executions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    playbook_id: Optional[int] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100
):
    """List playbook executions"""

    query = select(PlaybookExecution)

    if playbook_id:
        query = query.where(PlaybookExecution.playbook_id == playbook_id)
    if status:
        query = query.where(PlaybookExecution.status == status)

    query = query.order_by(desc(PlaybookExecution.triggered_at)).offset(skip).limit(limit)

    result = await db.execute(query)
    executions = result.scalars().all()

    return [exec.to_dict() for exec in executions]


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get playbook execution details"""

    result = await db.execute(
        select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
    )
    execution = result.scalar_one_or_none()

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    return execution.to_dict()
