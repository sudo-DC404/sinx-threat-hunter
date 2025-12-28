"""
sinX Threat Hunter - Alert Dispatcher Worker
Background worker for sending alert notifications
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.alerts import Alert
from app.utils.notifications import notification_manager

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """
    Background worker that dispatches alert notifications
    """

    def __init__(self, interval: int = 5):
        """
        Args:
            interval: Check interval in seconds
        """
        self.interval = interval
        self.running = False

        # Notification configuration
        self.notification_config = {
            'slack': {
                'webhook_url': None  # Set from environment or config
            },
            'discord': {
                'webhook_url': None  # Set from environment or config
            },
            'email': {
                'recipients': [],
                'smtp': {
                    'smtp_host': 'localhost',
                    'smtp_port': 25
                }
            }
        }

    def configure(self, config: Dict[str, Any]):
        """
        Configure notification channels
        """
        self.notification_config.update(config)
        logger.info("Alert dispatcher configured")

    async def dispatch_pending_alerts(self):
        """
        Find and dispatch pending alerts
        """
        async with AsyncSessionLocal() as db:
            # Find new alerts that haven't been dispatched
            result = await db.execute(
                select(Alert)
                .where(Alert.status == 'new')
                .limit(100)
            )
            alerts = result.scalars().all()

            if not alerts:
                return 0

            logger.info(f"Dispatching {len(alerts)} alerts")

            for alert in alerts:
                try:
                    await self.dispatch_alert(db, alert)
                except Exception as e:
                    logger.error(f"Error dispatching alert {alert.id}: {e}")

            await db.commit()

            return len(alerts)

    async def dispatch_alert(self, db: AsyncSession, alert: Alert):
        """
        Dispatch a single alert via configured channels
        """
        try:
            # Prepare alert data
            alert_data = {
                'id': alert.id,
                'title': alert.title,
                'description': alert.description,
                'severity': alert.severity,
                'triggered_at': alert.triggered_at.isoformat(),
                'rule_id': alert.rule_id,
                'source_ip': alert.alert_metadata.get('source_ip') if alert.alert_metadata else None,
                'dest_ip': alert.alert_metadata.get('dest_ip') if alert.alert_metadata else None,
                'event_type': alert.alert_metadata.get('event_type') if alert.alert_metadata else None,
                'mitre_tactics': alert.mitre_tactics or [],
                'mitre_techniques': alert.mitre_techniques or [],
                'dashboard_url': f'http://localhost:8000/alerts/{alert.id}'
            }

            # Determine which channels to use based on severity
            channels = self._get_channels_for_severity(alert.severity)

            # Send notifications
            results = await notification_manager.send_alert(
                alert_data=alert_data,
                channels=channels,
                config=self.notification_config
            )

            # Update alert status
            alert.status = 'investigating'

            # Log results
            successful = sum(1 for r in results if r is True)
            logger.info(
                f"Alert {alert.id} dispatched via {successful}/{len(results)} channels"
            )

        except Exception as e:
            logger.error(f"Error dispatching alert {alert.id}: {e}")
            raise

    def _get_channels_for_severity(self, severity: str) -> List[str]:
        """
        Determine which notification channels to use based on severity
        """
        channels = []

        # Always use webhook for logging
        if self.notification_config.get('webhook'):
            channels.append('webhook')

        # Critical and high severity alerts
        if severity in ['critical', 'high']:
            if self.notification_config.get('email', {}).get('recipients'):
                channels.append('email')
            if self.notification_config.get('slack', {}).get('webhook_url'):
                channels.append('slack')
            if self.notification_config.get('discord', {}).get('webhook_url'):
                channels.append('discord')

        # Medium severity - Slack and Discord only
        elif severity == 'medium':
            if self.notification_config.get('slack', {}).get('webhook_url'):
                channels.append('slack')
            if self.notification_config.get('discord', {}).get('webhook_url'):
                channels.append('discord')

        # Low severity - Discord only (if configured)
        elif severity == 'low':
            if self.notification_config.get('discord', {}).get('webhook_url'):
                channels.append('discord')

        return channels

    async def process_alert_escalation(self):
        """
        Check for alerts that need escalation
        (e.g., unresolved alerts older than X minutes)
        """
        from datetime import timedelta

        async with AsyncSessionLocal() as db:
            # Find alerts in 'investigating' status for > 30 minutes
            cutoff_time = datetime.utcnow() - timedelta(minutes=30)

            result = await db.execute(
                select(Alert)
                .where(Alert.status == 'investigating')
                .where(Alert.triggered_at < cutoff_time)
                .where(Alert.severity.in_(['critical', 'high']))
            )
            stale_alerts = result.scalars().all()

            for alert in stale_alerts:
                logger.warning(
                    f"Alert {alert.id} has been investigating for >30 min - escalating"
                )

                # Send escalation notification
                escalation_data = {
                    'id': alert.id,
                    'title': f"[ESCALATION] {alert.title}",
                    'description': f"This {alert.severity} alert has been unresolved for 30+ minutes.\n\n{alert.description}",
                    'severity': 'critical',
                    'triggered_at': alert.triggered_at.isoformat(),
                    'dashboard_url': f'http://localhost:8000/alerts/{alert.id}'
                }

                await notification_manager.send_alert(
                    alert_data=escalation_data,
                    channels=['email', 'slack'],
                    config=self.notification_config
                )

            await db.commit()

    async def run(self):
        """
        Run the alert dispatcher worker
        """
        self.running = True
        logger.info(f"Alert dispatcher started (interval: {self.interval}s)")

        while self.running:
            try:
                # Dispatch pending alerts
                await self.dispatch_pending_alerts()

                # Check for escalations (every 5 minutes)
                if datetime.utcnow().minute % 5 == 0:
                    await self.process_alert_escalation()

                await asyncio.sleep(self.interval)

            except Exception as e:
                logger.error(f"Error in alert dispatcher: {e}")
                await asyncio.sleep(self.interval)

    async def stop(self):
        """Stop the worker"""
        logger.info("Stopping alert dispatcher")
        self.running = False
