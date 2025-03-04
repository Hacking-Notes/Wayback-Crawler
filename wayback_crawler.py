import asyncio
import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table
from typing import Optional
from models import ScanConfig
from crawler import WaybackCrawler

app = typer.Typer(help="Wayback Machine Crawler - Discover and analyze subdomains")
console = Console()

def print_banner():
    console.print("""
[bold blue]
██╗    ██╗ █████╗ ██╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗     ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
██║    ██║██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝    ██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██║ █╗ ██║███████║ ╚████╔╝ ██████╔╝███████║██║     █████╔╝     ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║███╗██║██╔══██║  ╚██╔╝  ██╔══██╗██╔══██║██║     ██╔═██╗     ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
╚███╔███╔╝██║  ██║   ██║   ██████╔╝██║  ██║╚██████╗██║  ██╗    ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
[/bold blue]
    """)

def load_wordlist(path=None):
    """Load wordlist from file or return default list."""
    if path:
        try:
            with open(path) as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load wordlist from {path}: {e}[/yellow]")
    
    # Try to load default keywords.txt from same directory
    try:
        with open("keywords.txt") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        # Fallback to default list if no file is found
        return ["id", "page", "file", "dir", "search", "cmd", "exec", "url", "path", "width"]

def display_results(result):
    """Display scan results in a formatted table."""
    # Display subdomains
    if result.subdomains:
        table = Table(
            title="Discovered Subdomains",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            padding=(0, 1),
            expand=True
        )
        
        # Define columns with proper widths and styles
        table.add_column("Subdomain", style="cyan", width=50)
        table.add_column("Status", style="green", justify="center", width=10)
        table.add_column("Response Length", style="blue", justify="right", width=15)
        table.add_column("Server", style="magenta", width=20)
        
        # Process and deduplicate subdomains
        processed_subdomains = set()
        for subdomain in result.subdomains:
            # Split concatenated subdomains
            parts = subdomain.url.split(result.config.target_domain)
            for part in parts:
                # Clean up the part and create full domain if needed
                part = part.strip('.*')  # Remove wildcards and dots
                if part:
                    if not part.endswith(result.config.target_domain):
                        full_domain = f"{part}.{result.config.target_domain}"
                    else:
                        full_domain = part
                    processed_subdomains.add(full_domain)
        
        # Sort and display unique subdomains
        for domain in sorted(processed_subdomains):
            # Find the corresponding subdomain object
            subdomain_obj = next((s for s in result.subdomains if s.url == domain), None)
            
            if subdomain_obj:
                # Use the original subdomain object's data
                status = subdomain_obj.status
                response_length = subdomain_obj.response_length
                server = subdomain_obj.server
            else:
                # Use default values for split subdomains
                status = None
                response_length = None
                server = None
            
            # Status column
            if status == 200:
                status_str = "[green]200[/green]"
            elif status is None:
                status_str = "[dim]N/A[/dim]"
            elif status >= 400:
                status_str = f"[yellow]{status}[/yellow]"
            else:
                status_str = f"[blue]{status}[/blue]"
            
            # Response length column
            if response_length:
                length_str = f"{response_length:,}"
            else:
                length_str = "[dim]N/A[/dim]"
            
            # Server column
            server_str = server if server else "[dim]N/A[/dim]"
            
            table.add_row(
                domain,
                status_str,
                length_str,
                server_str
            )
        
        console.print("\n")  # Add some spacing
        console.print(table)
        console.print("\n")  # Add some spacing
    else:
        console.print("\n[yellow]No subdomains were discovered.[/yellow]")
        console.print("[yellow]Try the following:[/yellow]")
        console.print("1. Check if the domain name is correct")
        console.print("2. Try using --no-verify-ssl if the target uses an invalid SSL certificate")
        console.print("3. Increase the timeout with --timeout if the servers are slow")
        console.print("4. Check your internet connection")
        
    # Display vulnerable parameters
    if result.vulnerable_parameters:
        vuln_table = Table(
            title="Potentially Vulnerable Parameters",
            show_header=True,
            header_style="bold red",
            show_lines=True,
            expand=True
        )
        vuln_table.add_column("Parameter", style="red", width=20)
        vuln_table.add_column("URL", style="yellow", no_wrap=False)
        
        # Load keywords from file or use defaults
        wordlist = load_wordlist(result.config.custom_wordlist)
        
        # Group URLs and check for interesting parameters
        url_params = {}
        for vuln in result.vulnerable_parameters:
            if vuln.url not in url_params:
                # Check URL against all interesting parameters
                found_params = set()
                for param in wordlist:
                    if f"{param}=" in vuln.url.lower():
                        found_params.add(param)
                if found_params:  # Only add if we found interesting parameters
                    url_params[vuln.url] = found_params
        
        # Display URLs with parameter info
        for url in sorted(url_params.keys()):
            params = url_params[url]
            param_display = "[red]multiples[/red]" if len(params) > 1 else next(iter(params))
            vuln_table.add_row(param_display, url)
            
        console.print(vuln_table)
    elif result.config.check_vulnerable:
        console.print("\n[yellow]No vulnerable parameters were found.[/yellow]")
        
    # Display summary with active subdomains count
    active_subdomains = sum(1 for s in result.subdomains if s.is_active)
    console.print(f"\n[bold green]Scan Summary:[/bold green]")
    console.print(f"Total subdomains found: {len(result.subdomains)}")
    console.print(f"Active subdomains: {active_subdomains}")
    console.print(f"Total vulnerable parameters found: {len(result.vulnerable_parameters)}")
    console.print(f"Scan duration: {(result.end_time - result.start_time).total_seconds():.2f} seconds")

@app.command()
def main(
    domain: str = typer.Argument(..., help="Target domain (e.g., example.com)"),
    check_active: bool = typer.Option(False, "--active", "-a", help="Check if subdomains are active"),
    check_vulnerable: bool = typer.Option(False, "--vulnerable", "-v", help="Check for vulnerable parameters"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", "-w", help="Custom wordlist for parameter checking"),
    output: str = typer.Option("json", "--output", "-o", help="Output format (json/text)"),
    concurrent: int = typer.Option(50, "--concurrent", "-c", help="Maximum concurrent requests"),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Request timeout in seconds"),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="Disable SSL verification")
):
    """
    Scan a domain for subdomains and vulnerabilities using Wayback Machine data.
    """
    print_banner()
    
    config = ScanConfig(
        target_domain=domain,
        check_active=check_active,
        check_vulnerable=check_vulnerable,
        custom_wordlist=str(wordlist) if wordlist else None,
        output_format=output,
        max_concurrent_requests=concurrent,
        timeout=timeout,
        verify_ssl=not no_verify_ssl
    )
    
    async def run_scan():
        async with WaybackCrawler(config) as crawler:
            result = await crawler.scan()
            display_results(result)
            
            if output == "json":
                output_file = f"{domain}_scan_results.json"
                with open(output_file, "w") as f:
                    json_data = result.model_dump_json(indent=2)
                    f.write(json_data)
                console.print(f"\n[green]Results saved to {output_file}[/green]")
    
    try:
        asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/red]")

if __name__ == "__main__":
    app() 
