"""
sinX Threat Hunter - Detection Engine
Threat detection, rule matching, and alert generation
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from ..models.logs import Log
from ..models.iocs import IOC
from ..models.alerts import Alert, DetectionRule

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Threat detection and alert generation engine"""

    def __init__(self):
        self.rule_processors = {
            "signature": self.process_signature_rule,
            "anomaly": self.process_anomaly_rule,
            "ioc": self.process_ioc_rule,
            "correlation": self.process_correlation_rule,
            "threshold": self.process_threshold_rule,
        }

        # Cache for threshold tracking
        self.threshold_cache = defaultdict(list)

    async def process_log(self, log: Log, db: AsyncSession) -> List[Alert]:
        """
        Process a log entry against all detection rules

        Returns:
            List of generated alerts
        """
        alerts = []

        # Get enabled detection rules
        result = await db.execute(
            select(DetectionRule).where(DetectionRule.enabled == True)
        )
        rules = result.scalars().all()

        for rule in rules:
            processor = self.rule_processors.get(rule.rule_type, self.process_generic_rule)

            try:
                if await processor(log, rule, db):
                    alert = await self.create_alert(log, rule, db)
                    if alert:
                        alerts.append(alert)
            except Exception as e:
                logger.error(f"Error processing rule {rule.name}: {e}")

        # Check against IOC database
        ioc_alert = await self.check_ioc_match(log, db)
        if ioc_alert:
            alerts.append(ioc_alert)

        return alerts

    async def process_signature_rule(self, log: Log, rule: DetectionRule, db: AsyncSession) -> bool:
        """
        Process signature-based detection rule

        Rule definition format:
        {
            "patterns": ["regex1", "regex2"],
            "field": "message",  # Field to match against
            "match_type": "any"  # any or all
        }
        """
        definition = rule.rule_definition
        patterns = definition.get("patterns", [])
        field = definition.get("field", "message")
        match_type = definition.get("match_type", "any")

        # Get field value from log
        field_value = getattr(log, field, None)
        if field_value is None and log.parsed_data:
            field_value = log.parsed_data.get(field)

        if field_value is None:
            return False

        field_value = str(field_value)

        # Check patterns
        matches = [re.search(pattern, field_value, re.IGNORECASE) for pattern in patterns]

        if match_type == "any":
            return any(matches)
        else:  # all
            return all(matches)

    async def process_threshold_rule(self, log: Log, rule: DetectionRule, db: AsyncSession) -> bool:
        """
        Process threshold-based detection rule

        Rule definition format:
        {
            "condition": {"event_type": "auth_failure"},
            "threshold": {
                "count": 5,
                "timeframe": 60,  # seconds
                "group_by": "source_ip"
            }
        }
        """
        definition = rule.rule_definition
        condition = definition.get("condition", {})
        threshold = definition.get("threshold", {})

        # Check if log matches condition
        matches = all(
            getattr(log, key, None) == value
            for key, value in condition.items()
        )

        if not matches:
            return False

        # Track for threshold
        count = threshold.get("count", 5)
        timeframe = threshold.get("timeframe", 60)
        group_by = threshold.get("group_by", "source_ip")

        group_value = getattr(log, group_by, "default")
        cache_key = f"{rule.id}:{group_value}"

        # Add to cache
        now = datetime.utcnow()
        self.threshold_cache[cache_key].append(now)

        # Remove old entries
        cutoff = now - timedelta(seconds=timeframe)
        self.threshold_cache[cache_key] = [
            ts for ts in self.threshold_cache[cache_key]
            if ts > cutoff
        ]

        # Check threshold
        if len(self.threshold_cache[cache_key]) >= count:
            self.threshold_cache[cache_key] = []  # Reset after triggering
            return True

        return False

    async def process_anomaly_rule(self, log: Log, rule: DetectionRule, db: AsyncSession) -> bool:
        """
        Process anomaly-based detection rule (statistical deviation)

        Placeholder - would implement statistical analysis
        """
        logger.debug(f"Anomaly detection not yet implemented for rule {rule.name}")
        return False

    async def process_ioc_rule(self, log: Log, rule: DetectionRule, db: AsyncSession) -> bool:
        """
        Process IOC matching rule

        Checks if any IOCs appear in the log
        """
        # Extract potential IOCs from log
        from ..engines.intel_engine import IntelEngine
        intel_engine = IntelEngine()

        text = f"{log.message} {log.raw_log or ''}"
        extracted_iocs = intel_engine.extract_iocs_from_text(text)

        # Check each extracted IOC
        for ioc_type, values in extracted_iocs.items():
            for value in values:
                ioc = await intel_engine.check_ioc(value, db)
                if ioc:
                    return True

        return False

    async def process_correlation_rule(self, log: Log, rule: DetectionRule, db: AsyncSession) -> bool:
        """
        Process correlation rule (multi-event pattern)

        Placeholder - would implement complex event correlation
        """
        logger.debug(f"Correlation detection not yet implemented for rule {rule.name}")
        return False

    async def process_generic_rule(self, log: Log, rule: DetectionRule, db: AsyncSession) -> bool:
        """Generic rule processor fallback"""
        logger.warning(f"No specific processor for rule type: {rule.rule_type}")
        return False

    async def create_alert(self, log: Log, rule: DetectionRule, db: AsyncSession) -> Optional[Alert]:
        """Create an alert from a matched rule"""

        alert = Alert(
            title=rule.name,
            description=rule.description or f"Detection rule triggered: {rule.name}",
            severity=rule.severity,
            rule_id=rule.id,
            status="new",
            related_logs=[log.id],
            metadata={
                "rule_name": rule.name,
                "log_id": log.id,
                "log_message": log.message,
                "source_ip": str(log.source_ip) if log.source_ip else None,
                "hostname": log.hostname,
            },
            mitre_tactics=rule.mitre_tactics,
            mitre_techniques=rule.mitre_techniques,
        )

        db.add(alert)

        # Update rule statistics
        rule.trigger_count = (rule.trigger_count or 0) + 1

        await db.commit()
        await db.refresh(alert)

        logger.info(f"Alert created: {alert.title} (ID: {alert.id})")
        return alert

    async def check_ioc_match(self, log: Log, db: AsyncSession) -> Optional[Alert]:
        """Check log against IOC database"""

        # Check source IP
        if log.source_ip:
            result = await db.execute(
                select(IOC).where(
                    IOC.value == str(log.source_ip),
                    IOC.ioc_type == "ip",
                    IOC.active == True
                )
            )
            ioc = result.scalar_one_or_none()

            if ioc:
                alert = Alert(
                    title=f"IOC Detected: {ioc.threat_type or 'Known Malicious IP'}",
                    description=f"Known malicious IP {log.source_ip} detected in logs",
                    severity=ioc.severity or "high",
                    status="new",
                    related_logs=[log.id],
                    related_iocs=[ioc.id],
                    metadata={
                        "ioc_value": str(log.source_ip),
                        "ioc_type": "ip",
                        "threat_type": ioc.threat_type,
                        "source": ioc.source,
                        "confidence": ioc.confidence,
                    },
                    mitre_tactics=ioc.mitre_tactics,
                    mitre_techniques=ioc.mitre_techniques,
                )

                db.add(alert)
                await db.commit()
                await db.refresh(alert)

                logger.warning(f"IOC match: {log.source_ip} - {ioc.threat_type}")
                return alert

        # Could extend to check domains, hashes, etc. in parsed_data

        return None

    async def get_detection_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get detection engine statistics"""

        # Total alerts
        total_result = await db.execute(select(func.count(Alert.id)))
        total_alerts = total_result.scalar()

        # Alerts by severity
        severity_result = await db.execute(
            select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        )
        severity_counts = {row[0]: row[1] for row in severity_result.all()}

        # Top triggered rules
        rule_result = await db.execute(
            select(DetectionRule.name, DetectionRule.trigger_count)
            .where(DetectionRule.trigger_count > 0)
            .order_by(DetectionRule.trigger_count.desc())
            .limit(10)
        )
        top_rules = [{"name": row[0], "count": row[1]} for row in rule_result.all()]

        return {
            "total_alerts": total_alerts,
            "severity_breakdown": severity_counts,
            "top_triggered_rules": top_rules,
        }


# Built-in detection rules that can be imported
BUILTIN_RULES = [
    {
        "name": "SSH Brute Force Attack",
        "description": "Detect multiple failed SSH login attempts from same source",
        "severity": "high",
        "rule_type": "threshold",
        "rule_definition": {
            "condition": {
                "event_type": "auth_failure",
                "dest_port": 22,
            },
            "threshold": {
                "count": 5,
                "timeframe": 300,  # 5 minutes
                "group_by": "source_ip",
            },
        },
        "enabled": True,
        "tags": ["brute_force", "ssh", "authentication"],
        "mitre_techniques": ["T1110"],  # Brute Force
    },
    {
        "name": "Port Scan Detection",
        "description": "Detect port scanning activity",
        "severity": "medium",
        "rule_type": "threshold",
        "rule_definition": {
            "condition": {
                "event_type": "network",
            },
            "threshold": {
                "count": 20,
                "timeframe": 60,
                "group_by": "source_ip",
            },
        },
        "enabled": True,
        "tags": ["port_scan", "reconnaissance"],
        "mitre_techniques": ["T1046"],  # Network Service Discovery
    },
    {
        "name": "SQL Injection Attempt",
        "description": "Detect SQL injection patterns in web requests",
        "severity": "high",
        "rule_type": "signature",
        "rule_definition": {
            "patterns": [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL metacharacters
                r"(union.*select)|(select.*from)|(insert.*into)",  # SQL commands
                r"(drop.*table)|(exec.*xp_)"
            ],
            "field": "message",
            "match_type": "any",
        },
        "enabled": True,
        "tags": ["sql_injection", "web", "attack"],
        "mitre_techniques": ["T1190"],  # Exploit Public-Facing Application
    },
]
