"""
sinX Threat Hunter - Log Processor Worker
Background worker for log enrichment and analysis
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.logs import Log
from app.utils.enrichment import enricher
from app.utils.parsers import LogParser
from app.engines.detection_engine import DetectionEngine

logger = logging.getLogger(__name__)


class LogProcessor:
    """
    Background worker that enriches and analyzes logs
    """

    def __init__(self, batch_size: int = 100, interval: int = 10):
        """
        Args:
            batch_size: Number of logs to process per batch
            interval: Processing interval in seconds
        """
        self.batch_size = batch_size
        self.interval = interval
        self.running = False
        self.detection_engine = DetectionEngine()
        self.parser = LogParser()

    async def process_batch(self):
        """
        Process a batch of unenriched logs
        """
        async with AsyncSessionLocal() as db:
            # Find logs that need enrichment
            # (logs without enrichment data from the last minute)
            cutoff_time = datetime.utcnow() - timedelta(minutes=1)

            result = await db.execute(
                select(Log)
                .where(Log.timestamp >= cutoff_time)
                .where(Log.enrichment == None)
                .limit(self.batch_size)
            )
            logs = result.scalars().all()

            if not logs:
                return 0

            logger.info(f"Processing {len(logs)} logs for enrichment")

            for log in logs:
                try:
                    await self.enrich_log(db, log)
                except Exception as e:
                    logger.error(f"Error enriching log {log.id}: {e}")

            await db.commit()

            return len(logs)

    async def enrich_log(self, db: AsyncSession, log: Log):
        """
        Enrich a single log entry
        """
        try:
            # Extract IOCs from log
            iocs_found = self.parser.extract_iocs(log.raw_log)

            # Enrich log data
            enrichment = await enricher.enrich_log({
                'source_ip': log.source_ip,
                'dest_ip': log.dest_ip,
                'message': log.message,
                'parsed_data': log.parsed_data
            })

            # Detect attack patterns
            attacks = self.parser.detect_attack_patterns(log.raw_log)
            if attacks:
                enrichment['detected_attacks'] = attacks
                logger.warning(
                    f"Attack patterns detected in log {log.id}: {attacks}"
                )

            # Add IOCs to enrichment
            if any(iocs_found.values()):
                enrichment['iocs_found'] = iocs_found

            # Update log with enrichment
            log.enrichment = enrichment

            # Run detection engine on this log
            await self.detection_engine.evaluate_log(db, log)

        except Exception as e:
            logger.error(f"Error enriching log {log.id}: {e}")
            raise

    async def cleanup_old_logs(self, retention_days: int = 30):
        """
        Archive or delete old logs based on retention policy
        """
        async with AsyncSessionLocal() as db:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            # Delete old logs
            from sqlalchemy import delete
            result = await db.execute(
                delete(Log).where(Log.timestamp < cutoff_date)
            )

            deleted_count = result.rowcount
            await db.commit()

            if deleted_count > 0:
                logger.info(f"Deleted {deleted_count} logs older than {retention_days} days")

            return deleted_count

    async def run(self):
        """
        Run the log processor worker
        """
        self.running = True
        logger.info(f"Log processor started (interval: {self.interval}s)")

        while self.running:
            try:
                processed = await self.process_batch()

                # If we processed a full batch, there might be more
                # Process immediately
                if processed >= self.batch_size:
                    continue

                # Otherwise, wait for the interval
                await asyncio.sleep(self.interval)

            except Exception as e:
                logger.error(f"Error in log processor: {e}")
                await asyncio.sleep(self.interval)

    async def stop(self):
        """Stop the worker"""
        logger.info("Stopping log processor")
        self.running = False
