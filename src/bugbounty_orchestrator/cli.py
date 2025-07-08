"""
Command-line interface for the Bug Bounty Orchestrator
"""

import asyncio
import typer
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional, List
from pathlib import Path

from .core.orchestrator import BugBountyOrchestrator
from .core.config import config, platform_config
from .core.config_manager import config_manager
from .core.tool_orchestrator import tool_orchestrator
from .dashboard.app import run_dashboard

app = typer.Typer(
    name="bugbounty-orchestrator",
    help="Comprehensive automated bug bounty platform",
    add_completion=False
)
console = Console()

# Global orchestrator instance
orchestrator: Optional[BugBountyOrchestrator] = None

async def get_orchestrator() -> BugBountyOrchestrator:
    """Get or create orchestrator instance"""
    global orchestrator
    if orchestrator is None:
        orchestrator = BugBountyOrchestrator()
        await orchestrator.initialize()
    return orchestrator

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or URL to scan"),
    workflow: str = typer.Option("comprehensive_scan", "--workflow", "-w", help="Workflow to use"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results"),
    format: str = typer.Option("json", "--format", "-f", help="Output format (json, yaml, table)"),
    severity: Optional[List[str]] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    passive: bool = typer.Option(False, "--passive", help="Use passive scanning only"),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Use headless browser"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Verify discovered assets")
):
    """Start a comprehensive vulnerability scan"""
    
    async def run_scan():
        orch = await get_orchestrator()
        
        # Prepare scan options
        options = {
            'severity': severity or ['critical', 'high', 'medium', 'low', 'info'],
            'passive': passive,
            'headless': headless,
            'verify': verify
        }
        
        console.print(f"[bold blue]Starting {workflow} scan for: {target}[/bold blue]")
        
        # Start scan
        scan_id = await orch.start_scan(target, workflow, options)
        
        # Monitor scan progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task(f"Scanning {target}...", total=None)
            
            while True:
                scan_status = await orch.get_scan_status(scan_id)
                if not scan_status:
                    break
                
                status = scan_status['status']
                progress.update(task, description=f"Status: {status}")
                
                if status in ['completed', 'failed', 'cancelled']:
                    break
                
                await asyncio.sleep(2)
        
        # Get final results
        final_status = await orch.get_scan_status(scan_id)
        
        if final_status:
            console.print(f"\n[bold green]Scan completed with status: {final_status['status']}[/bold green]")
            
            # Display results
            _display_scan_results(final_status, format)
            
            # Save output if requested
            if output:
                _save_results(final_status, output, format)
                console.print(f"Results saved to: {output}")
        
        await orch.shutdown()
    
    asyncio.run(run_scan())

@app.command()
def list_scans(
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status"),
    limit: int = typer.Option(10, "--limit", "-l", help="Limit number of results")
):
    """List recent scans"""
    
    async def run_list():
        orch = await get_orchestrator()
        
        scans = await orch.list_scans(status)
        scans = scans[-limit:]  # Get most recent
        
        if not scans:
            console.print("[yellow]No scans found[/yellow]")
            return
        
        # Create table
        table = Table(title="Recent Scans")
        table.add_column("ID", style="cyan")
        table.add_column("Target", style="green")
        table.add_column("Workflow", style="blue")
        table.add_column("Status", style="magenta")
        table.add_column("Started", style="yellow")
        table.add_column("Duration")
        
        for scan in scans:
            started = scan.get('started_at', 'N/A')
            if started != 'N/A':
                started = started.split('T')[0]  # Just date
            
            duration = "N/A"
            if scan.get('completed_at') and scan.get('started_at'):
                # Calculate duration (simplified)
                duration = "Completed"
            elif scan['status'] == 'running':
                duration = "Running"
            
            table.add_row(
                scan['id'][:8],
                scan['target'],
                scan['workflow'],
                scan['status'],
                started,
                duration
            )
        
        console.print(table)
        await orch.shutdown()
    
    asyncio.run(run_list())

@app.command()
def status(
    scan_id: str = typer.Argument(..., help="Scan ID to check")
):
    """Get detailed status of a specific scan"""
    
    async def run_status():
        orch = await get_orchestrator()
        
        scan_status = await orch.get_scan_status(scan_id)
        
        if not scan_status:
            console.print(f"[red]Scan {scan_id} not found[/red]")
            return
        
        # Display detailed status
        _display_scan_details(scan_status)
        
        await orch.shutdown()
    
    asyncio.run(run_status())

@app.command()
def tools():
    """List available tools and their status"""
    
    async def run_tools():
        orch = await get_orchestrator()
        
        available_tools = orch.get_available_tools()
        
        table = Table(title="Available Tools")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Type", style="blue")
        
        # MCP Tools
        mcp_tools = platform_config.get_mcp_tools()
        for tool_name, tool_config in mcp_tools.items():
            status = "Available" if tool_name in available_tools else "Disabled"
            table.add_row(tool_name, status, "MCP Tool")
        
        # Modern Tools
        modern_tools = platform_config.get_modern_tools()
        for tool_name, tool_config in modern_tools.items():
            status = "Enabled" if tool_config.get('enabled', False) else "Disabled"
            table.add_row(tool_name, status, "Modern Tool")
        
        console.print(table)
        await orch.shutdown()
    
    asyncio.run(run_tools())

@app.command()
def workflows():
    """List available workflows"""
    
    async def run_workflows():
        orch = await get_orchestrator()
        
        workflows = orch.get_available_workflows()
        workflow_configs = platform_config.get_workflows()
        
        table = Table(title="Available Workflows")
        table.add_column("Workflow", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Steps", style="blue")
        
        for workflow_name in workflows:
            workflow_config = workflow_configs.get(workflow_name, {})
            description = workflow_config.get('description', 'No description')
            steps = len(workflow_config.get('steps', []))
            
            table.add_row(workflow_name, description, str(steps))
        
        console.print(table)
        await orch.shutdown()
    
    asyncio.run(run_workflows())

@app.command()
def test_tool(
    tool_name: str = typer.Argument(..., help="Tool name to test"),
    target: str = typer.Argument(..., help="Target to test against")
):
    """Test a specific tool"""
    
    async def run_test():
        orch = await get_orchestrator()
        
        console.print(f"[blue]Testing {tool_name} against {target}...[/blue]")
        
        result = await orch.test_tool(tool_name, target)
        
        if result['status'] == 'success':
            console.print(f"[green]✓ {tool_name} test successful[/green]")
            if 'results' in result:
                console.print(json.dumps(result['results'], indent=2))
        else:
            console.print(f"[red]✗ {tool_name} test failed: {result.get('message', 'Unknown error')}[/red]")
        
        await orch.shutdown()
    
    asyncio.run(run_test())

@app.command()
def cancel(
    scan_id: str = typer.Argument(..., help="Scan ID to cancel")
):
    """Cancel a running scan"""
    
    async def run_cancel():
        orch = await get_orchestrator()
        
        success = await orch.cancel_scan(scan_id)
        
        if success:
            console.print(f"[green]Scan {scan_id} cancelled successfully[/green]")
        else:
            console.print(f"[red]Failed to cancel scan {scan_id} (not found or not running)[/red]")
        
        await orch.shutdown()
    
    asyncio.run(run_cancel())

@app.command()
def check_scope(
    target: str = typer.Argument(..., help="Target to check scope for")
):
    """Check if target is in scope for bug bounty programs"""
    
    async def run_scope_check():
        orch = await get_orchestrator()
        
        console.print(f"[blue]Checking scope for: {target}[/blue]")
        
        scope_results = await orch.check_target_scope(target)
        
        table = Table(title="Scope Check Results")
        table.add_column("Platform", style="cyan")
        table.add_column("In Scope", style="green")
        table.add_column("Program", style="blue")
        
        for platform, result in scope_results.items():
            in_scope = "✓" if result.get('in_scope', False) else "✗"
            program = result.get('program', 'N/A')
            
            table.add_row(platform.title(), in_scope, program)
        
        console.print(table)
        await orch.shutdown()
    
    asyncio.run(run_scope_check())

@app.command()
def system_status():
    """Display system status"""
    
    async def run_system_status():
        orch = await get_orchestrator()
        
        status = orch.get_system_status()
        
        panel_content = f"""
[bold]Active Scans:[/bold] {status['active_scans']}
[bold]Completed Scans:[/bold] {status['total_scans_completed']}
[bold]Available Tools:[/bold] {status['available_tools']}
[bold]Available Workflows:[/bold] {status['available_workflows']}
[bold]Version:[/bold] {status['version']}
        """
        
        console.print(Panel(panel_content.strip(), title="System Status", border_style="blue"))
        
        await orch.shutdown()
    
    asyncio.run(run_system_status())

@app.command()
def dashboard(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host to bind the dashboard to"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind the dashboard to"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug mode"),
    auto_open: bool = typer.Option(True, "--auto-open/--no-auto-open", help="Auto-open browser")
):
    """Launch the web dashboard"""
    
    console.print(f"[bold blue]Starting Bug Bounty Orchestrator Dashboard[/bold blue]")
    console.print(f"[green]Dashboard will be available at: http://{host}:{port}[/green]")
    
    if auto_open:
        import webbrowser
        import threading
        
        def open_browser():
            import time
            time.sleep(2)  # Wait for server to start
            webbrowser.open(f"http://localhost:{port}")
        
        # Open browser in separate thread
        threading.Thread(target=open_browser, daemon=True).start()
    
    # Run the dashboard
    run_dashboard(host=host, port=port, debug=debug)

@app.command()
def cleanup(
    days: int = typer.Option(30, "--days", "-d", help="Delete scan data older than N days"),
    reports: bool = typer.Option(False, "--reports", help="Also cleanup old reports"),
    logs: bool = typer.Option(False, "--logs", help="Also cleanup old logs"),
    confirm: bool = typer.Option(False, "--confirm", "-y", help="Skip confirmation prompt")
):
    """Clean up old scan data and reports"""
    
    async def run_cleanup():
        if not confirm:
            proceed = typer.confirm(f"This will delete scan data older than {days} days. Continue?")
            if not proceed:
                console.print("[yellow]Cleanup cancelled[/yellow]")
                return
        
        orch = await get_orchestrator()
        
        # Cleanup scan history
        cleaned_scans = await orch.cleanup_old_scans(days)
        console.print(f"[green]Cleaned up {cleaned_scans} old scan records[/green]")
        
        # Cleanup reports if requested
        if reports:
            from .dashboard.utils import DashboardUtils
            reports_dir = Path('reports')
            if reports_dir.exists():
                cleaned_reports = await DashboardUtils.cleanup_old_files(reports_dir, days)
                console.print(f"[green]Cleaned up {cleaned_reports} old report files[/green]")
        
        # Cleanup logs if requested
        if logs:
            from .dashboard.utils import DashboardUtils
            logs_dir = Path('data')
            if logs_dir.exists():
                # Only cleanup .log files
                log_files = list(logs_dir.glob('*.log'))
                from datetime import datetime, timedelta
                cutoff_date = datetime.now() - timedelta(days=days)
                cleaned_logs = 0
                
                for log_file in log_files:
                    if datetime.fromtimestamp(log_file.stat().st_mtime) < cutoff_date:
                        log_file.unlink()
                        cleaned_logs += 1
                
                console.print(f"[green]Cleaned up {cleaned_logs} old log files[/green]")
        
        await orch.shutdown()
    
    asyncio.run(run_cleanup())

@app.command()
def export(
    scan_id: str = typer.Argument(..., help="Scan ID to export"),
    format: str = typer.Option("html", "--format", "-f", help="Export format (html, json, pdf, csv)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    findings_only: bool = typer.Option(False, "--findings-only", help="Export only vulnerability findings")
):
    """Export scan results in various formats"""
    
    async def run_export():
        orch = await get_orchestrator()
        
        scan_data = await orch.get_scan_status(scan_id)
        if not scan_data:
            console.print(f"[red]Scan {scan_id} not found[/red]")
            return
        
        console.print(f"[blue]Exporting scan {scan_id[:8]} in {format} format...[/blue]")
        
        try:
            from .modules.report_generator import ReportGenerator
            report_generator = ReportGenerator()
            
            # Create a mock scan job object for the report generator
            class MockScanJob:
                def __init__(self, scan_data):
                    self.id = scan_data['id']
                    self.target = scan_data['target']
                    self.workflow = scan_data['workflow']
                    self.status = scan_data['status']
                    self.results = scan_data['results']
                    self.errors = scan_data['errors']
                    self.started_at = scan_data.get('started_at')
                    self.completed_at = scan_data.get('completed_at')
            
            mock_job = MockScanJob(scan_data)
            
            if findings_only and format == 'csv':
                # Export only findings as CSV
                from .dashboard.utils import DashboardUtils
                findings = scan_data.get('results', {}).get('vulnerability_scanning', {}).get('findings', [])
                csv_content = DashboardUtils.export_findings_csv(findings)
                
                output_file = output or f"findings_{scan_id[:8]}.csv"
                with open(output_file, 'w') as f:
                    f.write(csv_content)
                
                console.print(f"[green]Findings exported to: {output_file}[/green]")
            else:
                # Generate full report
                report_path = await report_generator.generate_report(mock_job, [format])
                
                if output and report_path != Path(output):
                    # Move to specified location
                    Path(output).parent.mkdir(parents=True, exist_ok=True)
                    report_path.rename(output)
                    report_path = Path(output)
                
                console.print(f"[green]Report exported to: {report_path}[/green]")
                
        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")
        
        await orch.shutdown()
    
    asyncio.run(run_export())

@app.command()
def config_get(
    config_type: str = typer.Argument(..., help="Configuration type (main, tools, workflows, platforms)"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="Specific configuration key")
):
    """Get configuration values"""
    
    try:
        config_value = config_manager.get_config(config_type, key)
        
        if config_value is None:
            console.print(f"[red]Configuration {config_type}.{key or '*'} not found[/red]")
            return
        
        if isinstance(config_value, dict):
            console.print(json.dumps(config_value, indent=2, default=str))
        else:
            console.print(str(config_value))
            
    except Exception as e:
        console.print(f"[red]Error getting configuration: {e}[/red]")

@app.command()
def config_set(
    config_type: str = typer.Argument(..., help="Configuration type"),
    key: str = typer.Argument(..., help="Configuration key"),
    value: str = typer.Argument(..., help="Configuration value (JSON string for complex values)")
):
    """Set configuration values"""
    
    try:
        # Try to parse as JSON first
        try:
            parsed_value = json.loads(value)
        except json.JSONDecodeError:
            # Use as string if not valid JSON
            parsed_value = value
        
        success = config_manager.set_config(config_type, key, parsed_value)
        
        if success:
            console.print(f"[green]Configuration {config_type}.{key} set successfully[/green]")
        else:
            console.print(f"[red]Failed to set configuration {config_type}.{key}[/red]")
            
    except Exception as e:
        console.print(f"[red]Error setting configuration: {e}[/red]")

@app.command()
def config_export(
    output_path: str = typer.Argument(..., help="Output file path"),
    include_secrets: bool = typer.Option(False, "--include-secrets", help="Include encrypted secrets")
):
    """Export all configuration to file"""
    
    try:
        success = config_manager.export_config(output_path, include_secrets)
        
        if success:
            console.print(f"[green]Configuration exported to {output_path}[/green]")
        else:
            console.print("[red]Failed to export configuration[/red]")
            
    except Exception as e:
        console.print(f"[red]Error exporting configuration: {e}[/red]")

@app.command()
def config_import(
    config_path: str = typer.Argument(..., help="Configuration file path"),
    merge: bool = typer.Option(True, "--merge/--replace", help="Merge with existing config or replace")
):
    """Import configuration from file"""
    
    try:
        success = config_manager.import_config(config_path, merge)
        
        if success:
            action = "merged" if merge else "replaced"
            console.print(f"[green]Configuration {action} successfully[/green]")
        else:
            console.print("[red]Failed to import configuration[/red]")
            
    except Exception as e:
        console.print(f"[red]Error importing configuration: {e}[/red]")

@app.command()
def config_health():
    """Check configuration health"""
    
    async def run_health_check():
        try:
            health_results = await config_manager.health_check()
            
            # Display overall status
            status_color = "green" if health_results['overall_status'] == 'healthy' else "yellow" if health_results['overall_status'] == 'degraded' else "red"
            console.print(f"[bold {status_color}]Overall Status: {health_results['overall_status'].upper()}[/bold {status_color}]")
            
            # Display checks
            checks = health_results.get('checks', {})
            
            # Tools check
            tools_check = checks.get('tools', {})
            console.print(f"\n[bold]Tools:[/bold] {tools_check.get('available', 0)}/{tools_check.get('total', 0)} available ({tools_check.get('percentage', 0):.1f}%)")
            
            # Workflows check
            workflows_check = checks.get('workflows', {})
            console.print(f"[bold]Workflows:[/bold] {workflows_check.get('valid', 0)}/{workflows_check.get('total', 0)} valid ({workflows_check.get('percentage', 0):.1f}%)")
            
            # Platforms check
            platforms_check = checks.get('platforms', {})
            console.print(f"[bold]Platforms:[/bold] {platforms_check.get('configured', 0)}/{platforms_check.get('total', 0)} configured")
            
            # Display issues
            issues = health_results.get('issues', [])
            if issues:
                console.print(f"\n[bold red]Issues:[/bold red]")
                for issue in issues:
                    console.print(f"  • {issue}")
            
            # Display warnings
            warnings = health_results.get('warnings', [])
            if warnings:
                console.print(f"\n[bold yellow]Warnings:[/bold yellow]")
                for warning in warnings:
                    console.print(f"  • {warning}")
                    
        except Exception as e:
            console.print(f"[red]Error checking configuration health: {e}[/red]")
    
    asyncio.run(run_health_check())

@app.command()
def config_validate(
    config_type: Optional[str] = typer.Option(None, "--type", "-t", help="Specific config type to validate")
):
    """Validate configuration"""
    
    if config_type:
        if config_type == "tools":
            tools = config_manager.get_config('tools')
            for tool_name in tools:
                is_valid = config_manager.validate_tool_config(tool_name)
                status = "✅" if is_valid else "❌"
                console.print(f"{status} {tool_name}")
        
        elif config_type == "workflows":
            workflows = config_manager.get_config('workflows')
            for workflow_name in workflows:
                is_valid = config_manager.validate_workflow_config(workflow_name)
                status = "✅" if is_valid else "❌"
                console.print(f"{status} {workflow_name}")
        
        else:
            console.print(f"[yellow]Validation not implemented for {config_type}[/yellow]")
    
    else:
        # Validate all
        console.print("[bold]Validating all configurations...[/bold]")
        
        # Validate tools
        console.print("\n[bold]Tools:[/bold]")
        tools = config_manager.get_config('tools')
        for tool_name in tools:
            is_valid = config_manager.validate_tool_config(tool_name)
            status = "✅" if is_valid else "❌"
            console.print(f"  {status} {tool_name}")
        
        # Validate workflows
        console.print("\n[bold]Workflows:[/bold]")
        workflows = config_manager.get_config('workflows')
        for workflow_name in workflows:
            is_valid = config_manager.validate_workflow_config(workflow_name)
            status = "✅" if is_valid else "❌"
            console.print(f"  {status} {workflow_name}")

@app.command()
def orchestrator_status():
    """Get tool orchestrator status"""
    
    async def run_orchestrator_status():
        try:
            health = await tool_orchestrator.health_check()
            stats = tool_orchestrator.get_execution_stats()
            active = tool_orchestrator.get_active_executions()
            
            # Display status
            status_color = "green" if health['status'] == 'healthy' else "yellow" if health['status'] == 'degraded' else "red"
            console.print(f"[bold {status_color}]Orchestrator Status: {health['status'].upper()}[/bold {status_color}]")
            
            # Display statistics
            console.print(f"\n[bold]Execution Statistics:[/bold]")
            console.print(f"  Total Executions: {stats['total_executions']}")
            console.print(f"  Successful: {stats['successful_executions']}")
            console.print(f"  Failed: {stats['failed_executions']}")
            console.print(f"  Success Rate: {stats['success_rate']:.1f}%")
            console.print(f"  Average Duration: {stats['avg_execution_time']:.1f}s")
            
            # Display active executions
            console.print(f"\n[bold]Active Executions ({len(active)}):[/bold]")
            if active:
                for execution in active:
                    console.print(f"  • {execution['tool_name']} - {execution['runtime_seconds']:.1f}s")
            else:
                console.print("  None")
            
            # Display issues
            issues = health.get('issues', [])
            if issues:
                console.print(f"\n[bold red]Issues:[/bold red]")
                for issue in issues:
                    console.print(f"  • {issue}")
                    
        except Exception as e:
            console.print(f"[red]Error getting orchestrator status: {e}[/red]")
    
    asyncio.run(run_orchestrator_status())

@app.command()
def telegram_bot(
    start: bool = typer.Option(False, "--start", help="Start Telegram bot"),
    stop: bool = typer.Option(False, "--stop", help="Stop Telegram bot"),
    status: bool = typer.Option(False, "--status", help="Check bot status"),
    config: bool = typer.Option(False, "--config", help="Show bot configuration")
):
    """Manage Telegram bot integration"""
    
    async def run_telegram_bot():
        from .integrations.telegram_bot import get_telegram_bot
        
        try:
            if start:
                orch = await get_orchestrator()
                bot = get_telegram_bot(orch)
                
                console.print("[blue]Starting Telegram bot...[/blue]")
                console.print("[green]Bot is running. Press Ctrl+C to stop.[/green]")
                
                await bot.start_bot()
                
            elif stop:
                # Implementation for stopping running bot
                console.print("[yellow]Telegram bot stop command sent[/yellow]")
                
            elif status:
                # Check if bot is configured
                from .core.config_manager import config_manager
                telegram_config = config_manager.get_config('platforms', 'telegram') or {}
                
                if not telegram_config.get('bot_token'):
                    console.print("[red]❌ Telegram bot not configured[/red]")
                    console.print("[yellow]💡 Configure bot_token, api_id, and api_hash in platforms config[/yellow]")
                else:
                    console.print("[green]✅ Telegram bot configured[/green]")
                    console.print(f"[blue]📱 Bot Token: {telegram_config.get('bot_token', '')[:10]}...[/blue]")
                    console.print(f"[blue]👥 Authorized Users: {len(telegram_config.get('authorized_users', []))}[/blue]")
                    
            elif config:
                from .core.config_manager import config_manager
                telegram_config = config_manager.get_config('platforms', 'telegram') or {}
                
                console.print("[bold]Telegram Bot Configuration:[/bold]")
                console.print(json.dumps(telegram_config, indent=2, default=str))
                
            else:
                console.print("[yellow]Please specify an action: --start, --stop, --status, or --config[/yellow]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Telegram bot stopped by user[/yellow]")
        except Exception as e:
            console.print(f"[red]Telegram bot error: {e}[/red]")
    
    asyncio.run(run_telegram_bot())

def _display_scan_results(scan_data: dict, format: str):
    """Display scan results in specified format"""
    
    if format == "json":
        console.print(json.dumps(scan_data, indent=2))
    elif format == "table":
        # Create summary table
        _display_scan_summary(scan_data)
    else:
        console.print("[yellow]Unsupported format, defaulting to JSON[/yellow]")
        console.print(json.dumps(scan_data, indent=2))

def _display_scan_summary(scan_data: dict):
    """Display scan summary in table format"""
    
    # Summary panel
    results = scan_data.get('results', {})
    vuln_results = results.get('vulnerability_scanning', {})
    summary = vuln_results.get('summary', {})
    
    summary_content = f"""
[bold]Target:[/bold] {scan_data['target']}
[bold]Workflow:[/bold] {scan_data['workflow']}
[bold]Status:[/bold] {scan_data['status']}
[bold]Total Findings:[/bold] {summary.get('total_findings', 0)}
[bold]Critical:[/bold] {summary.get('critical', 0)}
[bold]High:[/bold] {summary.get('high', 0)}
[bold]Medium:[/bold] {summary.get('medium', 0)}
[bold]Low:[/bold] {summary.get('low', 0)}
    """
    
    console.print(Panel(summary_content.strip(), title="Scan Summary", border_style="green"))

def _display_scan_details(scan_data: dict):
    """Display detailed scan information"""
    
    console.print(f"[bold blue]Scan Details for {scan_data['id'][:8]}[/bold blue]")
    
    # Basic info
    info_table = Table(title="Basic Information")
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="green")
    
    info_table.add_row("ID", scan_data['id'])
    info_table.add_row("Target", scan_data['target'])
    info_table.add_row("Workflow", scan_data['workflow'])
    info_table.add_row("Status", scan_data['status'])
    info_table.add_row("Progress", f"{scan_data['progress']:.1f}%")
    
    console.print(info_table)
    
    # Display summary if available
    _display_scan_summary(scan_data)

def _save_results(scan_data: dict, output_path: str, format: str):
    """Save scan results to file"""
    
    output_file = Path(output_path)
    
    if format == "json":
        with open(output_file, 'w') as f:
            json.dump(scan_data, f, indent=2)
    elif format == "yaml":
        import yaml
        with open(output_file, 'w') as f:
            yaml.dump(scan_data, f, default_flow_style=False)
    else:
        # Default to JSON
        with open(output_file, 'w') as f:
            json.dump(scan_data, f, indent=2)

def main():
    """Main CLI entry point"""
    app()

if __name__ == "__main__":
    main()