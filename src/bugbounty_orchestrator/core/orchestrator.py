"""
Main orchestrator for coordinating all bug bounty tools and workflows
"""

import asyncio
import logging
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import httpx
from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from .config import config, platform_config
from .scanner import ScanEngine
from .workflow import WorkflowEngine
from ..modules.subdomain_discovery import SubdomainDiscovery
from ..modules.port_scanner import PortScanner
from ..modules.web_crawler import WebCrawler
from ..modules.vulnerability_scanner import VulnerabilityScanner
from ..modules.modern_tools import ModernToolsIntegrator
from ..integrations.platform_manager import PlatformManager
from ..integrations.notification_manager import NotificationManager

logger = logging.getLogger(__name__)
console = Console()

class ScanJob:
    """Represents a scanning job with all its metadata"""
    
    def __init__(self, target: str, workflow: str, options: Dict[str, Any] = None):
        self.id = str(uuid.uuid4())
        self.target = target
        self.workflow = workflow
        self.options = options or {}
        self.status = "initialized"
        self.created_at = datetime.now()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.results: Dict[str, Any] = {}
        self.errors: List[str] = []
        self.progress = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan job to dictionary"""
        return {
            'id': self.id,
            'target': self.target,
            'workflow': self.workflow,
            'options': self.options,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'results': self.results,
            'errors': self.errors,
            'progress': self.progress
        }

class BugBountyOrchestrator:
    """Main orchestrator class for managing bug bounty operations"""
    
    def __init__(self):
        self.scan_engine = ScanEngine()
        self.workflow_engine = WorkflowEngine()
        self.subdomain_discovery = SubdomainDiscovery()
        self.port_scanner = PortScanner()
        self.web_crawler = WebCrawler()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.modern_tools = ModernToolsIntegrator()
        self.platform_manager = PlatformManager()
        self.notification_manager = NotificationManager()
        
        self.active_scans: Dict[str, ScanJob] = {}
        self.scan_history: List[ScanJob] = []
        
        # Initialize logging
        self._setup_logging()
        
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO if not config.debug else logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('data/orchestrator.log'),
                logging.StreamHandler()
            ]
        )
    
    async def initialize(self) -> None:
        """Initialize the orchestrator and all components"""
        logger.info("Initializing Bug Bounty Orchestrator...")
        
        # Initialize scan engine and MCP tools
        await self.scan_engine.initialize()
        
        # Create necessary directories
        Path('data').mkdir(exist_ok=True)
        Path('reports').mkdir(exist_ok=True)
        
        logger.info("Bug Bounty Orchestrator initialized successfully")
    
    async def shutdown(self) -> None:
        """Shutdown the orchestrator and cleanup resources"""
        logger.info("Shutting down Bug Bounty Orchestrator...")
        
        # Cancel all active scans
        for scan_id in list(self.active_scans.keys()):
            await self.cancel_scan(scan_id)
        
        # Shutdown scan engine
        await self.scan_engine.shutdown()
        
        logger.info("Bug Bounty Orchestrator shutdown complete")
    
    async def start_scan(self, target: str, workflow: str = "comprehensive_scan", 
                        options: Dict[str, Any] = None) -> str:
        """Start a new scanning job"""
        
        # Validate target
        if not self._validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        # Check concurrent scan limit
        if len(self.active_scans) >= config.max_concurrent_scans:
            raise RuntimeError("Maximum concurrent scans limit reached")
        
        # Create scan job
        scan_job = ScanJob(target, workflow, options)
        self.active_scans[scan_job.id] = scan_job
        
        console.print(f"[green]Starting scan job {scan_job.id} for target: {target}[/green]")
        
        # Start scan in background
        asyncio.create_task(self._execute_scan(scan_job))
        
        return scan_job.id
    
    async def _execute_scan(self, scan_job: ScanJob) -> None:
        """Execute a scanning job"""
        try:
            scan_job.status = "running"
            scan_job.started_at = datetime.now()
            
            logger.info(f"Starting scan {scan_job.id} for target {scan_job.target}")
            
            # Execute workflow
            workflow_result = await self.workflow_engine.execute_workflow(
                scan_job.workflow, 
                scan_job.target, 
                scan_job.options
            )
            
            # Store workflow results
            scan_job.results = workflow_result.results
            scan_job.errors = workflow_result.errors
            scan_job.progress = 100.0
            
            # Generate report
            await self._generate_report(scan_job)
            
            # Submit to platforms if configured
            await self._submit_to_platforms(scan_job)
            
            # Send notifications
            await self._send_notifications(scan_job)
            
            scan_job.status = "completed" if workflow_result.status == "completed" else "failed"
            scan_job.completed_at = datetime.now()
            
            console.print(f"[green]Scan {scan_job.id} completed successfully[/green]")
            
        except Exception as e:
            scan_job.status = "failed"
            scan_job.completed_at = datetime.now()
            error_msg = f"Scan failed: {str(e)}"
            logger.error(error_msg)
            scan_job.errors.append(error_msg)
            console.print(f"[red]Scan {scan_job.id} failed: {error_msg}[/red]")
            
        finally:
            # Move to history and clean up
            self.scan_history.append(scan_job)
            if scan_job.id in self.active_scans:
                del self.active_scans[scan_job.id]
    
    async def _generate_report(self, scan_job: ScanJob) -> None:
        """Generate scan report"""
        try:
            from ..modules.report_generator import ReportGenerator
            report_generator = ReportGenerator()
            
            report_path = await report_generator.generate_report(scan_job)
            scan_job.results['report_path'] = str(report_path)
            
            logger.info(f"Report generated for scan {scan_job.id}: {report_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate report for scan {scan_job.id}: {e}")
    
    async def _submit_to_platforms(self, scan_job: ScanJob) -> None:
        """Submit findings to bug bounty platforms"""
        try:
            # Extract high/critical findings
            critical_findings = self._extract_critical_findings(scan_job.results)
            
            if critical_findings:
                submission_results = await self.platform_manager.submit_findings(
                    scan_job.target, critical_findings
                )
                scan_job.results['platform_submissions'] = submission_results
                
        except Exception as e:
            logger.error(f"Failed to submit to platforms for scan {scan_job.id}: {e}")
    
    async def _send_notifications(self, scan_job: ScanJob) -> None:
        """Send scan completion notifications"""
        try:
            await self.notification_manager.send_scan_completion(scan_job)
            
            # Send critical findings notification
            critical_findings = self._extract_critical_findings(scan_job.results)
            if critical_findings:
                await self.notification_manager.send_critical_findings(
                    scan_job.target, critical_findings
                )
                
        except Exception as e:
            logger.error(f"Failed to send notifications for scan {scan_job.id}: {e}")
    
    def _extract_critical_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract critical and high severity findings from scan results"""
        critical_findings = []
        
        # Extract from vulnerability scan results
        vuln_results = results.get('vulnerability_scanning', {})
        findings = vuln_results.get('findings', [])
        
        for finding in findings:
            if finding.get('severity') in ['critical', 'high']:
                critical_findings.append(finding)
        
        return critical_findings
    
    def _validate_target(self, target: str) -> bool:
        """Validate scan target"""
        import re
        
        # Basic URL/domain validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        domain_pattern = re.compile(
            r'^(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?$', 
            re.IGNORECASE
        )
        
        return bool(url_pattern.match(target) or domain_pattern.match(target))
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific scan"""
        
        # Check active scans
        if scan_id in self.active_scans:
            return self.active_scans[scan_id].to_dict()
        
        # Check scan history
        for scan in self.scan_history:
            if scan.id == scan_id:
                return scan.to_dict()
        
        return None
    
    async def list_scans(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all scans with optional status filter"""
        all_scans = list(self.active_scans.values()) + self.scan_history
        
        if status:
            all_scans = [scan for scan in all_scans if scan.status == status]
        
        return [scan.to_dict() for scan in all_scans]
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan"""
        if scan_id in self.active_scans:
            scan_job = self.active_scans[scan_id]
            scan_job.status = "cancelled"
            scan_job.completed_at = datetime.now()
            
            # Move to history
            self.scan_history.append(scan_job)
            del self.active_scans[scan_id]
            
            logger.info(f"Scan {scan_id} cancelled")
            return True
        
        return False
    
    async def cleanup_old_scans(self, days: int = 30) -> int:
        """Clean up old scan results"""
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        initial_count = len(self.scan_history)
        
        self.scan_history = [
            scan for scan in self.scan_history 
            if scan.completed_at and scan.completed_at > cutoff_date
        ]
        
        cleaned_count = initial_count - len(self.scan_history)
        logger.info(f"Cleaned up {cleaned_count} old scan records")
        
        return cleaned_count
    
    async def get_platform_info(self, target: str) -> Dict[str, Any]:
        """Get platform information for target"""
        return await self.platform_manager.get_program_info(target)
    
    async def check_target_scope(self, target: str) -> Dict[str, Any]:
        """Check if target is in scope for any bug bounty programs"""
        return await self.platform_manager.check_program_scope(target)
    
    def get_available_workflows(self) -> List[str]:
        """Get list of available workflows"""
        return self.workflow_engine.get_workflow_names()
    
    def get_available_tools(self) -> List[str]:
        """Get list of available MCP tools"""
        return self.scan_engine.get_available_tools()
    
    async def test_tool(self, tool_name: str, target: str) -> Dict[str, Any]:
        """Test a specific tool against a target"""
        if not self.scan_engine.is_tool_available(tool_name):
            return {'status': 'error', 'message': f'Tool {tool_name} not available'}
        
        try:
            result = await self.scan_engine.run_tool(tool_name, 'test', {'target': target})
            return result
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status information"""
        return {
            'active_scans': len(self.active_scans),
            'total_scans_completed': len(self.scan_history),
            'available_tools': len(self.get_available_tools()),
            'available_workflows': len(self.get_available_workflows()),
            'uptime': datetime.now().isoformat(),
            'version': '1.0.0'
        }