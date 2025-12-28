"""
sinX Threat Hunter - Threat Feed Updater
Background worker to update threat intelligence feeds
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal
from app.engines.intel_engine import ThreatIntelEngine
from app.models.iocs import IOC, ThreatFeed

logger = logging.getLogger(__name__)


class FeedUpdater:
    """
    Background worker that periodically updates threat intelligence feeds
    """

    def __init__(self, update_interval: int = 3600):
        """
        Args:
            update_interval: Update interval in seconds (default: 1 hour)
        """
        self.update_interval = update_interval
        self.intel_engine = ThreatIntelEngine()
        self.running = False

    async def update_all_feeds(self):
        """
        Update all enabled threat feeds
        """
        logger.info("Starting threat feed update cycle")

        async with AsyncSessionLocal() as db:
            # Get all enabled feeds
            from sqlalchemy import select
            result = await db.execute(
                select(ThreatFeed).where(ThreatFeed.enabled == True)
            )
            feeds = result.scalars().all()

            logger.info(f"Found {len(feeds)} enabled feeds to update")

            for feed in feeds:
                try:
                    await self.update_feed(db, feed)
                except Exception as e:
                    logger.error(f"Error updating feed {feed.name}: {e}")

            await db.commit()

        logger.info("Threat feed update cycle completed")

    async def update_feed(self, db: AsyncSession, feed: ThreatFeed):
        """
        Update a single threat feed
        """
        logger.info(f"Updating feed: {feed.name}")

        try:
            # Use the intel engine to fetch IOCs
            iocs = await self.intel_engine.fetch_feed_data(
                feed_url=feed.url,
                feed_type=feed.feed_type,
                api_key=feed.api_key
            )

            # Store or update IOCs
            new_count = 0
            updated_count = 0

            for ioc_data in iocs:
                from sqlalchemy import select

                # Check if IOC already exists
                result = await db.execute(
                    select(IOC).where(IOC.value == ioc_data['value'])
                )
                existing_ioc = result.scalar_one_or_none()

                if existing_ioc:
                    # Update existing IOC
                    existing_ioc.last_seen = datetime.utcnow()
                    existing_ioc.threat_type = ioc_data.get('threat_type', existing_ioc.threat_type)
                    existing_ioc.confidence = ioc_data.get('confidence', existing_ioc.confidence)
                    updated_count += 1
                else:
                    # Create new IOC
                    new_ioc = IOC(
                        ioc_type=ioc_data['ioc_type'],
                        value=ioc_data['value'],
                        threat_type=ioc_data.get('threat_type', 'unknown'),
                        confidence=ioc_data.get('confidence', 50),
                        severity=ioc_data.get('severity', 'medium'),
                        source=feed.name,
                        tags=ioc_data.get('tags', []),
                        ioc_metadata=ioc_data.get('metadata', {})
                    )
                    db.add(new_ioc)
                    new_count += 1

            # Update feed metadata
            feed.last_update = datetime.utcnow()
            feed.ioc_count = new_count + updated_count

            logger.info(
                f"Feed {feed.name} updated: {new_count} new, {updated_count} updated"
            )

        except Exception as e:
            logger.error(f"Error updating feed {feed.name}: {e}")
            raise

    async def run(self):
        """
        Run the feed updater worker
        """
        self.running = True
        logger.info(f"Feed updater started (interval: {self.update_interval}s)")

        # Initial update
        await self.update_all_feeds()

        # Periodic updates
        while self.running:
            await asyncio.sleep(self.update_interval)
            if self.running:
                await self.update_all_feeds()

    async def stop(self):
        """Stop the worker"""
        logger.info("Stopping feed updater")
        self.running = False
