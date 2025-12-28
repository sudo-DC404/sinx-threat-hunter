"""
sinX Threat Hunter - Notification Manager
Send alerts via email, Slack, Discord, webhooks
"""

import logging
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import httpx
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class NotificationManager:
    """
    Manages notifications across multiple channels
    """

    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=30.0)

    async def send_email(
        self,
        to_addresses: List[str],
        subject: str,
        body: str,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        from_address: str = "sinx-threat-hunter@localhost"
    ):
        """
        Send email notification
        """
        try:
            message = MIMEMultipart()
            message['From'] = from_address
            message['To'] = ', '.join(to_addresses)
            message['Subject'] = subject

            message.attach(MIMEText(body, 'html'))

            if smtp_user and smtp_password:
                await aiosmtplib.send(
                    message,
                    hostname=smtp_host,
                    port=smtp_port,
                    username=smtp_user,
                    password=smtp_password,
                    use_tls=True
                )
            else:
                await aiosmtplib.send(
                    message,
                    hostname=smtp_host,
                    port=smtp_port
                )

            logger.info(f"Email sent to {to_addresses}")
            return True

        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False

    async def send_slack(
        self,
        webhook_url: str,
        message: str,
        title: Optional[str] = None,
        severity: str = "info"
    ):
        """
        Send Slack notification
        """
        try:
            # Color based on severity
            color_map = {
                'info': '#36a64f',
                'warning': '#ff9900',
                'error': '#ff0000',
                'critical': '#8b0000'
            }
            color = color_map.get(severity, '#36a64f')

            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": title or "sinX Threat Hunter Alert",
                        "text": message,
                        "footer": "sinX Threat Hunter",
                        "ts": int(datetime.utcnow().timestamp())
                    }
                ]
            }

            response = await self.http_client.post(webhook_url, json=payload)

            if response.status_code == 200:
                logger.info("Slack notification sent")
                return True
            else:
                logger.error(f"Slack returned status {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False

    async def send_discord(
        self,
        webhook_url: str,
        message: str,
        title: Optional[str] = None,
        severity: str = "info"
    ):
        """
        Send Discord notification
        """
        try:
            # Color based on severity (decimal format for Discord)
            color_map = {
                'info': 3447003,    # Blue
                'warning': 16776960, # Yellow
                'error': 16711680,   # Red
                'critical': 9109504  # Dark red
            }
            color = color_map.get(severity, 3447003)

            payload = {
                "embeds": [
                    {
                        "title": title or "🛡️ sinX Threat Hunter Alert",
                        "description": message,
                        "color": color,
                        "footer": {
                            "text": "sinX Threat Hunter"
                        },
                        "timestamp": datetime.utcnow().isoformat()
                    }
                ]
            }

            response = await self.http_client.post(webhook_url, json=payload)

            if response.status_code == 204:
                logger.info("Discord notification sent")
                return True
            else:
                logger.error(f"Discord returned status {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error sending Discord notification: {e}")
            return False

    async def send_webhook(
        self,
        webhook_url: str,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None
    ):
        """
        Send generic webhook notification
        """
        try:
            if headers is None:
                headers = {'Content-Type': 'application/json'}

            response = await self.http_client.post(
                webhook_url,
                json=data,
                headers=headers
            )

            if response.status_code < 400:
                logger.info(f"Webhook sent to {webhook_url}")
                return True
            else:
                logger.error(f"Webhook returned status {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
            return False

    async def send_alert(
        self,
        alert_data: Dict[str, Any],
        channels: List[str],
        config: Dict[str, Any]
    ):
        """
        Send alert to multiple channels
        """
        tasks = []

        # Format alert message
        title = f"[{alert_data.get('severity', 'INFO').upper()}] {alert_data.get('title', 'Security Alert')}"
        message = self._format_alert_message(alert_data)

        for channel in channels:
            if channel == 'email' and config.get('email'):
                task = self.send_email(
                    to_addresses=config['email']['recipients'],
                    subject=title,
                    body=message,
                    **config['email'].get('smtp', {})
                )
                tasks.append(task)

            elif channel == 'slack' and config.get('slack'):
                task = self.send_slack(
                    webhook_url=config['slack']['webhook_url'],
                    message=message,
                    title=title,
                    severity=alert_data.get('severity', 'info')
                )
                tasks.append(task)

            elif channel == 'discord' and config.get('discord'):
                task = self.send_discord(
                    webhook_url=config['discord']['webhook_url'],
                    message=message,
                    title=title,
                    severity=alert_data.get('severity', 'info')
                )
                tasks.append(task)

            elif channel == 'webhook' and config.get('webhook'):
                task = self.send_webhook(
                    webhook_url=config['webhook']['url'],
                    data=alert_data,
                    headers=config['webhook'].get('headers')
                )
                tasks.append(task)

        # Send all notifications in parallel
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results
        else:
            logger.warning("No notification channels configured")
            return []

    def _format_alert_message(self, alert_data: Dict[str, Any]) -> str:
        """
        Format alert data into human-readable message
        """
        message = f"""
<strong>Alert Details:</strong>

<b>Title:</b> {alert_data.get('title', 'N/A')}
<b>Severity:</b> {alert_data.get('severity', 'N/A').upper()}
<b>Description:</b> {alert_data.get('description', 'N/A')}
<b>Time:</b> {alert_data.get('triggered_at', datetime.utcnow())}

<b>Source IP:</b> {alert_data.get('source_ip', 'N/A')}
<b>Destination IP:</b> {alert_data.get('dest_ip', 'N/A')}
<b>Event Type:</b> {alert_data.get('event_type', 'N/A')}

<b>Detection Rule:</b> {alert_data.get('rule_name', 'N/A')}

<b>MITRE ATT&CK:</b>
{', '.join(alert_data.get('mitre_tactics', ['N/A']))}

<b>Recommended Actions:</b>
{alert_data.get('recommended_actions', 'Investigate the alert in sinX Threat Hunter dashboard')}

---
View full details: {alert_data.get('dashboard_url', 'http://localhost:8000/alerts')}
        """.strip()

        return message

    async def close(self):
        """Close HTTP client"""
        await self.http_client.aclose()


# Global notification manager
notification_manager = NotificationManager()
