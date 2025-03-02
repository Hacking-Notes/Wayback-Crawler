from typing import Optional, List
from pydantic import BaseModel, HttpUrl, Field
from datetime import datetime

class Subdomain(BaseModel):
    url: str
    status: Optional[int] = None
    last_checked: Optional[datetime] = None
    is_active: Optional[bool] = None
    response_length: Optional[int] = None
    server: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)

class VulnerableParameter(BaseModel):
    parameter: str
    url: str
    method: str = "GET"
    discovered_at: datetime = Field(default_factory=datetime.now)

class ScanConfig(BaseModel):
    target_domain: str
    check_active: bool = False
    check_vulnerable: bool = False
    custom_wordlist: Optional[str] = None
    max_concurrent_requests: int = 50
    timeout: float = 10.0
    user_agent: str = "WaybackCrawler/2.0"
    output_format: str = "json"
    proxy: Optional[str] = None
    verify_ssl: bool = True
    max_retries: int = 3
    delay_between_requests: float = 0.1

class ScanResult(BaseModel):
    config: ScanConfig
    subdomains: List[Subdomain] = Field(default_factory=list)
    vulnerable_parameters: List[VulnerableParameter] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    total_requests: int = 0
    errors: List[str] = Field(default_factory=list) 