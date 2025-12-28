"""
sinX Threat Hunter - Syslog Collector
Receives logs via Syslog protocol (UDP/TCP)
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal
from app.engines.siem_engine import SIEMEngine
from app.models.logs import Log

logger = logging.getLogger(__name__)


class SyslogCollector:
    """
    Collects logs via Syslog protocol
    Supports both UDP (514) and TCP (601)
    """

    def __init__(self, udp_port: int = 514, tcp_port: int = 601):
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.siem_engine = SIEMEngine()
        self.running = False

    async def handle_syslog_message(self, data: bytes, source_addr: tuple):
        """Process incoming syslog message"""
        try:
            message = data.decode('utf-8').strip()

            # Parse the syslog message
            parsed = self.siem_engine.parse_log(message, log_format="syslog")

            # Add source information
            parsed['source_ip'] = source_addr[0]
            parsed['source_port'] = source_addr[1]
            parsed['raw_log'] = message
            parsed['timestamp'] = datetime.utcnow()

            # Store in database
            async with AsyncSessionLocal() as db:
                log_entry = Log(
                    timestamp=parsed.get('timestamp'),
                    source_ip=parsed.get('source_ip'),
                    source_port=parsed.get('source_port'),
                    dest_ip=parsed.get('dest_ip'),
                    dest_port=parsed.get('dest_port'),
                    event_type=parsed.get('event_type', 'syslog'),
                    severity=parsed.get('severity', 'info'),
                    message=parsed.get('message', ''),
                    raw_log=parsed.get('raw_log'),
                    parsed_data=parsed,
                )
                db.add(log_entry)
                await db.commit()

            logger.debug(f"Syslog message from {source_addr[0]}: {message[:100]}")

        except Exception as e:
            logger.error(f"Error processing syslog message: {e}")

    async def udp_server(self):
        """UDP syslog server"""
        class SyslogProtocol(asyncio.DatagramProtocol):
            def __init__(self, collector):
                self.collector = collector

            def datagram_received(self, data, addr):
                asyncio.create_task(self.collector.handle_syslog_message(data, addr))

        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self),
            local_addr=('0.0.0.0', self.udp_port)
        )

        logger.info(f"Syslog UDP collector listening on port {self.udp_port}")

        try:
            while self.running:
                await asyncio.sleep(1)
        finally:
            transport.close()

    async def tcp_server(self):
        """TCP syslog server"""
        async def handle_client(reader, writer):
            addr = writer.get_extra_info('peername')
            try:
                while True:
                    data = await reader.readline()
                    if not data:
                        break
                    await self.handle_syslog_message(data, addr)
            except Exception as e:
                logger.error(f"TCP client error: {e}")
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(
            handle_client,
            '0.0.0.0',
            self.tcp_port
        )

        logger.info(f"Syslog TCP collector listening on port {self.tcp_port}")

        async with server:
            while self.running:
                await asyncio.sleep(1)

    async def start(self):
        """Start both UDP and TCP collectors"""
        self.running = True
        logger.info("Starting Syslog collectors...")

        await asyncio.gather(
            self.udp_server(),
            self.tcp_server()
        )

    async def stop(self):
        """Stop collectors"""
        self.running = False
        logger.info("Stopping Syslog collectors...")
