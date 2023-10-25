from datetime import datetime
from typing import Optional


class Stats:
    def __init__(self, client_download_started_at: datetime, client_stats_created_at: datetime, file_id: str,
                 number_of_attempts: int, file_size_in_bytes: int, number_of_connections: int, status: str,
                 error_reason: Optional[str] = None, error_details: Optional[str] = None,
                 session_id: Optional[str] = None, user_id: Optional[str] = None):
        self.client_download_started_at = client_download_started_at
        self.client_stats_created_at = client_stats_created_at
        self.file_id = file_id
        self.number_of_attempts = number_of_attempts
        self.file_size_in_bytes = file_size_in_bytes
        self.number_of_connections = number_of_connections
        self.status = status
        self.error_reason = error_reason
        self.error_details = error_details
        self.session_id = session_id
        self.user_id = user_id

    @classmethod
    def succeeded(cls, client_download_started_at: datetime, client_stats_created_at: datetime, file_id: str,
                number_of_attempts: int, file_size_in_bytes: int, number_of_connections: int):
        return cls(client_download_started_at, client_stats_created_at, file_id, number_of_attempts, file_size_in_bytes,
                   number_of_connections, "Succeeded")

    @classmethod
    def failed(cls, client_download_started_at: datetime, client_stats_created_at: datetime, file_id: str,
              number_of_attempts: int, file_size_in_bytes: int, number_of_connections: int,
              error_reason, error_details):
        return cls(client_download_started_at, client_stats_created_at, file_id, number_of_attempts, file_size_in_bytes,
                   number_of_connections, "Failed", error_reason, error_details)
