"""
sinX Threat Hunter - File Collector
Tails log files and ingests them into SIEM
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal
from app.engines.siem_engine import SIEMEngine
from app.models.logs import Log

logger = logging.getLogger(__name__)


class FileCollector:
    """
    Monitors log files and ingests new lines
    Similar to 'tail -f' functionality
    """

    def __init__(self, file_paths: List[str], log_format: str = "auto"):
        self.file_paths = file_paths
        self.log_format = log_format
        self.siem_engine = SIEMEngine()
        self.running = False
        self.file_positions = {}  # Track file positions

    async def tail_file(self, file_path: str):
        """
        Tail a single file and process new lines
        """
        logger.info(f"Starting to tail file: {file_path}")

        # Initialize file position
        if os.path.exists(file_path):
            # Start from end of file
            self.file_positions[file_path] = os.path.getsize(file_path)
        else:
            logger.warning(f"File does not exist: {file_path}")
            return

        while self.running:
            try:
                if not os.path.exists(file_path):
                    logger.warning(f"File disappeared: {file_path}")
                    await asyncio.sleep(5)
                    continue

                current_size = os.path.getsize(file_path)
                last_position = self.file_positions.get(file_path, 0)

                # Check if file was truncated/rotated
                if current_size < last_position:
                    logger.info(f"File rotated: {file_path}")
                    last_position = 0

                # Read new lines
                if current_size > last_position:
                    with open(file_path, 'r', errors='ignore') as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        self.file_positions[file_path] = f.tell()

                        # Process each new line
                        for line in new_lines:
                            line = line.strip()
                            if line:
                                await self.process_log_line(line, file_path)

                await asyncio.sleep(1)  # Check every second

            except Exception as e:
                logger.error(f"Error tailing file {file_path}: {e}")
                await asyncio.sleep(5)

    async def process_log_line(self, line: str, source_file: str):
        """
        Parse and store a log line
        """
        try:
            # Auto-detect format based on file name
            if "auth.log" in source_file or "secure" in source_file:
                format_hint = "syslog"
            elif "apache" in source_file or "access.log" in source_file:
                format_hint = "apache"
            elif "nginx" in source_file:
                format_hint = "nginx"
            else:
                format_hint = self.log_format

            # Parse the log
            parsed = self.siem_engine.parse_log(line, log_format=format_hint)

            # Add metadata
            parsed['raw_log'] = line
            parsed['source_file'] = source_file
            parsed['timestamp'] = parsed.get('timestamp', datetime.utcnow())

            # Store in database
            async with AsyncSessionLocal() as db:
                log_entry = Log(
                    timestamp=parsed.get('timestamp'),
                    source_ip=parsed.get('source_ip'),
                    source_port=parsed.get('source_port'),
                    dest_ip=parsed.get('dest_ip'),
                    dest_port=parsed.get('dest_port'),
                    event_type=parsed.get('event_type', 'file_log'),
                    severity=parsed.get('severity', 'info'),
                    message=parsed.get('message', ''),
                    raw_log=parsed.get('raw_log'),
                    parsed_data=parsed,
                )
                db.add(log_entry)
                await db.commit()

        except Exception as e:
            logger.error(f"Error processing log line: {e}")

    async def start(self):
        """
        Start tailing all configured files
        """
        self.running = True
        logger.info(f"Starting file collector for {len(self.file_paths)} files")

        # Create tasks for each file
        tasks = [self.tail_file(fp) for fp in self.file_paths]
        await asyncio.gather(*tasks)

    async def stop(self):
        """Stop the collector"""
        self.running = False
        logger.info("Stopping file collector...")


# Common log file paths for quick start
COMMON_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
]
