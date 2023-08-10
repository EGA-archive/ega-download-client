from datetime import datetime
from dataclasses import dataclass
from typing import Optional


@dataclass
class Stats:
    session_id: str
    client_download_started_at: datetime
    client_stats_created_at: datetime
    file_id: str
    number_of_attempts: int
    file_size_in_bytes: int
    number_of_connections: int
    status: str
    error_reason: Optional[str] = None
