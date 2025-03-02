import asyncio
import aiohttp
import json
import os
import sys
from datetime import datetime
from typing import Set, Dict, List, Optional
from rich.console import Console

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from models import ScanConfig, ScanResult, Subdomain, VulnerableParameter
from helpers import (
    clean_domain,
    extract_subdomains,
    extract_parameters,
    create_progress,
    rate_limited_task,
    load_wordlist
)

console = Console()

class WaybackCrawler:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult(config=config)
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        
    async def __aenter__(self):
        """Set up async context."""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": self.config.user_agent},
        )
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up async context."""
        if self.session:
            await self.session.close()
            
    async def fetch_crtsh_subdomains(self) -> Set[str]:
        """Fetch subdomains from crt.sh."""
        url = f'https://crt.sh/?q=%25.{self.config.target_domain}&output=json'
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if not data:
                            console.print("[yellow]No data returned from crt.sh[/yellow]")
                            return set()
                        subdomains = set()
                        for entry in data:
                            name = entry['name_value'].lower()
                            subdomains.update(extract_subdomains(name, self.config.target_domain))
                        if not subdomains:
                            console.print("[yellow]No subdomains found in crt.sh data[/yellow]")
                        return subdomains
                    except json.JSONDecodeError as e:
                        console.print(f"[red]Error parsing crt.sh response: {e}[/red]")
                        return set()
                else:
                    console.print(f"[red]crt.sh returned status code: {response.status}[/red]")
                    return set()
        except Exception as e:
            console.print(f"[red]Error fetching from crt.sh: {str(e)}[/red]")
            return set()
        
    async def fetch_wayback_urls(self) -> Set[str]:
        """Fetch URLs from Wayback Machine."""
        url = f'https://web.archive.org/cdx/search/cdx'
        params = {
            'url': self.config.target_domain,
            'matchType': 'domain',
            'output': 'json',
            'collapse': 'urlkey'
        }
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if not data:
                            console.print("[yellow]No data returned from Wayback Machine[/yellow]")
                            return set()
                        if len(data) < 2:  # First row is header
                            console.print("[yellow]No URLs found in Wayback Machine data[/yellow]")
                            return set()
                        urls = {row[2] for row in data[1:]}  # Skip header row
                        if not urls:
                            console.print("[yellow]No valid URLs found in Wayback Machine data[/yellow]")
                        return urls
                    except json.JSONDecodeError as e:
                        console.print(f"[red]Error parsing Wayback Machine response: {e}[/red]")
                        return set()
                else:
                    console.print(f"[red]Wayback Machine returned status code: {response.status}[/red]")
                    return set()
        except Exception as e:
            console.print(f"[red]Error fetching from Wayback Machine: {str(e)}[/red]")
            return set()
        
    async def check_subdomain_status(self, subdomain: str) -> Subdomain:
        """Check if a subdomain is active and gather information."""
        # Properly format the full URL with the parent domain
        full_domain = f"{subdomain}.{self.config.target_domain}" if not subdomain.endswith(self.config.target_domain) else subdomain
        url = f"https://{full_domain}"
        
        try:
            async with self.session.get(url, ssl=self.config.verify_ssl, allow_redirects=True) as response:
                try:
                    content = await response.read()
                    content_length = len(content)
                except:
                    content_length = 0
                    
                return Subdomain(
                    url=full_domain,
                    status=response.status,
                    last_checked=datetime.now(),
                    is_active=response.status == 200,
                    response_length=content_length,
                    server=response.headers.get('Server', 'N/A')
                )
        except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
            # Silently handle all connection errors
            return Subdomain(
                url=full_domain,
                status=None,
                last_checked=datetime.now(),
                is_active=False,
                response_length=None,
                server=None
            )
            
    async def check_parameter_vulnerability(self, url: str, parameters: List[str]) -> List[VulnerableParameter]:
        """Check for potentially vulnerable parameters."""
        vulnerable = []
        wordlist = (load_wordlist(self.config.custom_wordlist) 
                   if self.config.custom_wordlist 
                   else ["id", "page", "file", "dir", "search", "cmd", "exec"])
                   
        for param in parameters:
            if any(keyword in param.lower() for keyword in wordlist):
                vulnerable.append(VulnerableParameter(
                    parameter=param,
                    url=url
                ))
        return vulnerable
        
    async def scan(self) -> ScanResult:
        """Perform the complete scan."""
        progress = create_progress()
        with progress:
            # Fetch subdomains
            task1 = progress.add_task("[cyan]Fetching subdomains from crt.sh...", total=1)
            task2 = progress.add_task("[cyan]Fetching URLs from Wayback Machine...", total=1)
            
            crtsh_subdomains, wayback_urls = await asyncio.gather(
                self.fetch_crtsh_subdomains(),
                self.fetch_wayback_urls()
            )
            
            progress.update(task1, completed=1)
            progress.update(task2, completed=1)
            
            # Extract subdomains from wayback URLs
            wayback_subdomains = set()
            for url in wayback_urls:
                wayback_subdomains.update(
                    extract_subdomains(url, self.config.target_domain)
                )
                
            # Combine all discovered subdomains
            all_subdomains = crtsh_subdomains | wayback_subdomains
            
            # Check subdomain status if requested
            if self.config.check_active:
                task3 = progress.add_task(
                    "[cyan]Checking subdomain status...",
                    total=len(all_subdomains)
                )
                
                async def check_with_progress(subdomain: str):
                    result = await self.check_subdomain_status(subdomain)
                    progress.update(task3, advance=1)
                    return result
                
                tasks = [
                    rate_limited_task(
                        check_with_progress(subdomain),
                        self.semaphore
                    )
                    for subdomain in all_subdomains
                ]
                
                self.result.subdomains = await asyncio.gather(*tasks)
            else:
                self.result.subdomains = [
                    Subdomain(url=subdomain)
                    for subdomain in all_subdomains
                ]
                
            # Check for vulnerable parameters if requested
            if self.config.check_vulnerable:
                task4 = progress.add_task(
                    "[cyan]Checking for vulnerable parameters...",
                    total=len(wayback_urls)
                )
                
                for url in wayback_urls:
                    params = extract_parameters(url)
                    if params:
                        vulns = await self.check_parameter_vulnerability(url, params)
                        self.result.vulnerable_parameters.extend(vulns)
                    progress.update(task4, advance=1)
                    
        self.result.end_time = datetime.now()
        return self.result 