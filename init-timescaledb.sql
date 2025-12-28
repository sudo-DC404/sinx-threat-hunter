-- sinX Threat Hunter - TimescaleDB Initialization

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- This script will run after tables are created by SQLAlchemy
-- The hypertable conversion will be done in a migration script
