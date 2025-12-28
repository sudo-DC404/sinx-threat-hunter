"""
sinX Threat Hunter - SOAR Engine
Security Orchestration, Automation, and Response
"""

import logging
import subprocess
import smtplib
import httpx
from datetime import datetime
from typing import Dict, List, Any, Optional
from email.mime.text import MIMEText
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.playbooks import Playbook, PlaybookExecution
from ..models.alerts import Alert

logger = logging.getLogger(__name__)


class SOAREngine:
    """SOAR automation and orchestration engine"""

    def __init__(self):
        self.action_handlers = {
            "block_ip": self.action_block_ip,
            "send_email": self.action_send_email,
            "send_webhook": self.action_send_webhook,
            "run_script": self.action_run_script,
            "create_ticket": self.action_create_ticket,
            "isolate_host": self.action_isolate_host,
            "quarantine_file": self.action_quarantine_file,
            "add_to_blocklist": self.action_add_to_blocklist,
            "notify": self.action_notify,
        }

    async def execute_playbook(
        self,
        playbook: Playbook,
        trigger_data: Dict[str, Any],
        db: AsyncSession,
        triggered_by: str = "system"
    ) -> PlaybookExecution:
        """
        Execute a playbook with given trigger data

        Args:
            playbook: Playbook object to execute
            trigger_data: Input data for playbook (alert details, etc.)
            db: Database session
            triggered_by: User or system that triggered execution

        Returns:
            PlaybookExecution object with results
        """
        logger.info(f"Executing playbook: {playbook.name}")

        # Create execution record
        execution = PlaybookExecution(
            playbook_id=playbook.id,
            triggered_by=triggered_by,
            input_data=trigger_data,
            status="running",
        )

        db.add(execution)
        await db.commit()
        await db.refresh(execution)

        execution_log = []
        start_time = datetime.utcnow()

        try:
            # Check if approval required
            if playbook.requires_approval:
                execution.approval_status = "pending"
                execution.status = "awaiting_approval"
                await db.commit()

                logger.info(f"Playbook {playbook.name} requires approval")
                execution_log.append({
                    "step": "approval_check",
                    "status": "pending",
                    "message": "Awaiting approval",
                    "timestamp": datetime.utcnow().isoformat(),
                })
                execution.execution_log = execution_log
                await db.commit()
                return execution

            # Execute workflow steps
            workflow = playbook.workflow
            steps = workflow.get("steps", [])

            for idx, step in enumerate(steps):
                step_result = await self.execute_step(step, trigger_data)

                execution_log.append({
                    "step": idx + 1,
                    "action": step.get("action"),
                    "status": step_result.get("status"),
                    "message": step_result.get("message"),
                    "output": step_result.get("output"),
                    "timestamp": datetime.utcnow().isoformat(),
                })

                # Stop on failure if configured
                if step_result.get("status") == "failed" and not step.get("continue_on_error"):
                    raise Exception(f"Step {idx + 1} failed: {step_result.get('message')}")

            # Success
            execution.status = "completed"
            execution.execution_log = execution_log
            execution.output_data = {"status": "success", "steps_completed": len(steps)}

            # Update playbook statistics
            playbook.execution_count = (playbook.execution_count or 0) + 1
            playbook.success_count = (playbook.success_count or 0) + 1

        except Exception as e:
            logger.error(f"Playbook execution failed: {e}")
            execution.status = "failed"
            execution.error_message = str(e)
            execution.execution_log = execution_log

            # Update playbook statistics
            playbook.execution_count = (playbook.execution_count or 0) + 1
            playbook.failure_count = (playbook.failure_count or 0) + 1

        finally:
            execution.completed_at = datetime.utcnow()
            execution.duration_seconds = int((datetime.utcnow() - start_time).total_seconds())
            await db.commit()

        return execution

    async def execute_step(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single playbook step"""

        action = step.get("action")
        parameters = step.get("parameters", {})

        # Variable substitution in parameters
        parameters = self.substitute_variables(parameters, context)

        handler = self.action_handlers.get(action)

        if not handler:
            return {
                "status": "failed",
                "message": f"Unknown action: {action}",
            }

        try:
            result = await handler(parameters)
            return {
                "status": "success",
                "message": f"Action {action} completed",
                "output": result,
            }
        except Exception as e:
            logger.error(f"Action {action} failed: {e}")
            return {
                "status": "failed",
                "message": str(e),
            }

    def substitute_variables(self, obj: Any, context: Dict[str, Any]) -> Any:
        """Substitute variables in parameters using context"""
        if isinstance(obj, str):
            # Replace {{variable}} with context value
            import re
            pattern = r'\{\{(\w+)\}\}'
            matches = re.findall(pattern, obj)
            for var in matches:
                value = context.get(var, f"{{{{ {var} }}}}")
                obj = obj.replace(f"{{{{{var}}}}}", str(value))
            return obj
        elif isinstance(obj, dict):
            return {k: self.substitute_variables(v, context) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.substitute_variables(item, context) for item in obj]
        else:
            return obj

    # Action Handlers

    async def action_block_ip(self, params: Dict[str, Any]) -> str:
        """Block an IP address using iptables"""
        ip = params.get("ip")
        duration = params.get("duration")  # minutes

        if not ip:
            raise ValueError("IP address required")

        # Placeholder - actual implementation would use iptables
        logger.info(f"Blocking IP: {ip} for {duration} minutes")

        # Example command (requires appropriate permissions):
        # subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)

        return f"IP {ip} blocked"

    async def action_send_email(self, params: Dict[str, Any]) -> str:
        """Send email notification"""
        to = params.get("to")
        subject = params.get("subject")
        body = params.get("body")

        if not all([to, subject, body]):
            raise ValueError("Email requires to, subject, and body")

        # Placeholder - would configure SMTP settings
        logger.info(f"Sending email to {to}: {subject}")

        # Example:
        # msg = MIMEText(body)
        # msg['Subject'] = subject
        # msg['From'] = "sinx-threat-hunter@example.com"
        # msg['To'] = to
        #
        # with smtplib.SMTP('localhost') as smtp:
        #     smtp.send_message(msg)

        return f"Email sent to {to}"

    async def action_send_webhook(self, params: Dict[str, Any]) -> str:
        """Send webhook notification"""
        url = params.get("url")
        data = params.get("data", {})
        method = params.get("method", "POST")

        if not url:
            raise ValueError("Webhook URL required")

        async with httpx.AsyncClient() as client:
            if method == "POST":
                response = await client.post(url, json=data, timeout=30.0)
            else:
                response = await client.get(url, params=data, timeout=30.0)

            response.raise_for_status()

        return f"Webhook sent to {url}: {response.status_code}"

    async def action_run_script(self, params: Dict[str, Any]) -> str:
        """Run a custom script"""
        script = params.get("script")
        args = params.get("args", [])

        if not script:
            raise ValueError("Script path required")

        # Security: Only allow scripts from approved directory
        # This is a placeholder - implement proper security checks

        logger.info(f"Running script: {script} with args {args}")

        # Example:
        # result = subprocess.run([script] + args, capture_output=True, text=True, check=True)
        # return result.stdout

        return f"Script {script} executed"

    async def action_create_ticket(self, params: Dict[str, Any]) -> str:
        """Create ticket in external system"""
        title = params.get("title")
        description = params.get("description")
        priority = params.get("priority", "medium")

        # Placeholder - would integrate with ticketing system API
        logger.info(f"Creating ticket: {title} [{priority}]")

        return f"Ticket created: {title}"

    async def action_isolate_host(self, params: Dict[str, Any]) -> str:
        """Isolate a host from the network"""
        hostname = params.get("hostname")
        ip = params.get("ip")

        # Placeholder - would integrate with network management or EDR
        logger.info(f"Isolating host: {hostname} ({ip})")

        return f"Host {hostname} isolated"

    async def action_quarantine_file(self, params: Dict[str, Any]) -> str:
        """Quarantine a file"""
        file_path = params.get("file_path")
        hash_value = params.get("hash")

        # Placeholder - would integrate with EDR or file system
        logger.info(f"Quarantining file: {file_path}")

        return f"File {file_path} quarantined"

    async def action_add_to_blocklist(self, params: Dict[str, Any]) -> str:
        """Add IOC to blocklist"""
        ioc_value = params.get("value")
        ioc_type = params.get("type")

        # Placeholder - would add to firewall/proxy blocklist
        logger.info(f"Adding to blocklist: {ioc_value} ({ioc_type})")

        return f"Added {ioc_value} to blocklist"

    async def action_notify(self, params: Dict[str, Any]) -> str:
        """Send notification (Slack, Discord, etc.)"""
        message = params.get("message")
        channel = params.get("channel")

        logger.info(f"Notification to {channel}: {message}")

        return f"Notification sent"


# Built-in playbooks
BUILTIN_PLAYBOOKS = [
    {
        "name": "Brute Force Response",
        "description": "Automatically respond to brute force attacks by blocking source IP",
        "trigger_type": "alert",
        "trigger_conditions": {"alert_title": "SSH Brute Force Attack"},
        "workflow": {
            "steps": [
                {
                    "action": "block_ip",
                    "parameters": {
                        "ip": "{{source_ip}}",
                        "duration": 60,
                    },
                },
                {
                    "action": "send_email",
                    "parameters": {
                        "to": "soc@example.com",
                        "subject": "Brute Force Attack Blocked",
                        "body": "IP {{source_ip}} has been blocked due to brute force attack",
                    },
                },
                {
                    "action": "add_to_blocklist",
                    "parameters": {
                        "value": "{{source_ip}}",
                        "type": "ip",
                    },
                },
            ]
        },
        "enabled": True,
    },
    {
        "name": "Malware Detection Response",
        "description": "Response to malware detection",
        "trigger_type": "alert",
        "trigger_conditions": {"severity": "critical"},
        "workflow": {
            "steps": [
                {
                    "action": "isolate_host",
                    "parameters": {
                        "hostname": "{{hostname}}",
                        "ip": "{{source_ip}}",
                    },
                },
                {
                    "action": "create_ticket",
                    "parameters": {
                        "title": "Critical Malware Detection",
                        "description": "Malware detected on {{hostname}}",
                        "priority": "high",
                    },
                },
                {
                    "action": "notify",
                    "parameters": {
                        "channel": "#security",
                        "message": "🚨 CRITICAL: Malware detected and host isolated: {{hostname}}",
                    },
                },
            ]
        },
        "enabled": True,
        "requires_approval": True,
    },
]
