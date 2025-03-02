import re
import asyncio
from typing import List, Set
from urllib.parse import urlparse, parse_qs
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

def clean_domain(domain: str) -> str:
    """Clean and normalize a domain name."""
    domain = domain.lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    return domain.strip('/')

def extract_subdomains(url: str, base_domain: str) -> Set[str]:
    """Extract subdomains from a URL."""
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        hostname = parsed.netloc or parsed.path
        hostname = hostname.split(':')[0]  # Remove port if present
        
        if not hostname.endswith(base_domain):
            return set()
            
        parts = hostname.split('.')
        if len(parts) <= 2:
            return set()
            
        return {'.'.join(parts[:-2])}
    except Exception:
        return set()

def extract_parameters(url: str) -> List[str]:
    """Extract GET parameters from a URL."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    except Exception:
        return []

def create_progress() -> Progress:
    """Create a rich progress bar."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True  # This will make the progress bars disappear after completion
    )

async def rate_limited_task(coro, semaphore: asyncio.Semaphore):
    """Execute a coroutine with rate limiting."""
    async with semaphore:
        return await coro

def format_status_code(status: int) -> str:
    """Format HTTP status code with color."""
    if status == 200:
        return f"[green]{status}[/green]"
    elif status == 403:
        return f"[yellow]{status}[/yellow]"
    elif status == 404:
        return f"[red]{status}[/red]"
    else:
        return f"[grey]{status}[/grey]"

def load_wordlist(path: str) -> List[str]:
    """Load and clean a wordlist file."""
    try:
        with open(path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[red]Error loading wordlist: {e}[/red]")
        return [] 