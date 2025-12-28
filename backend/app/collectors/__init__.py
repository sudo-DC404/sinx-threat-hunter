"""
sinX Threat Hunter - Data Collectors
Log collection from multiple sources
"""

from .syslog_collector import SyslogCollector
from .file_collector import FileCollector
from .api_collector import APICollector

__all__ = ['SyslogCollector', 'FileCollector', 'APICollector']
