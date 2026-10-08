"""Validated request contracts shared by the dashboard and remote agents."""
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator

class AlertConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    cpu_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    memory_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    disk_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    network_io_threshold_mbps: Optional[int] = Field(default=None, ge=0)
    tcp_reset_threshold: Optional[int] = Field(default=None, ge=0)
    server_error_threshold: Optional[int] = Field(default=None, ge=0)
    alert_cooldown_seconds: Optional[int] = Field(default=None, ge=0, le=86400)

class PortScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253, pattern=r'^[a-zA-Z0-9._-]+$')
    ports: Optional[str] = None

    @field_validator('ports')
    @classmethod
    def validate_ports(cls, value):
        if value is None:
            return value
        items = value.split(',')
        if not 1 <= len(items) <= 128 or any(not p.strip().isdigit() or not 1 <= int(p) <= 65535 for p in items):
            raise ValueError('Use 1–128 comma-separated ports between 1 and 65535')
        return ','.join(str(int(p)) for p in items)

class KillRequest(BaseModel):
    pid: int = Field(gt=1)
    kill_tree: bool = False

class AgentMetrics(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)
    hostname: str = Field(min_length=1, max_length=253)
    cpu_percent: float = Field(default=0, ge=0, le=100)
    memory_percent: float = Field(default=0, ge=0, le=100)
    disk_usage: float = Field(default=0, ge=0, le=100)
    disk_read_rate: float = Field(default=0, ge=0)
    disk_write_rate: float = Field(default=0, ge=0)
    network_sent_rate: float = Field(default=0, ge=0)
    network_recv_rate: float = Field(default=0, ge=0)
    uptime: int = Field(default=0, ge=0, le=2**63-1)
    total_connections: int = Field(default=0, ge=0, le=2**63-1)


from pydantic import AwareDatetime

class AgentRequest(BaseModel):
    """Validate the entire traffic batch before any database write."""
    model_config = ConfigDict(allow_inf_nan=False, extra='forbid')
    timestamp: AwareDatetime
    hostname: str = Field(min_length=1, max_length=253)
    method: str = Field(default='-', max_length=32)
    path: str = Field(default='-', max_length=8192)
    status_code: int = Field(default=200, ge=0, le=599)
    response_time: float = Field(default=0, ge=0, le=1e12)
    size: int = Field(default=0, ge=0, le=2**63-1)
    src_ip: str = Field(default='', max_length=64)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = Field(default='TCP', max_length=32)
