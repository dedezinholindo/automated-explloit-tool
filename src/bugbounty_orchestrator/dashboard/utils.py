"""
Utility functions for the dashboard
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import psutil

logger = logging.getLogger(__name__)

class DashboardUtils:
    """Utility functions for dashboard operations"""
    
    @staticmethod
    def format_duration(start_time: datetime, end_time: Optional[datetime] = None) -> str:
        """Format duration between two timestamps"""
        if not end_time:
            end_time = datetime.now()
        
        duration = end_time - start_time
        total_seconds = int(duration.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}m {seconds}s"
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    @staticmethod
    def get_system_stats() -> Dict[str, Any]:
        """Get current system statistics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'memory_total': memory.total,
                'memory_available': memory.available,
                'disk_usage': disk.percent,
                'disk_total': disk.total,
                'disk_free': disk.free,
                'uptime': DashboardUtils.get_system_uptime()
            }
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return {}
    
    @staticmethod
    def get_system_uptime() -> str:
        """Get system uptime"""
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = datetime.now().timestamp() - boot_time
            uptime_delta = timedelta(seconds=uptime_seconds)
            
            days = uptime_delta.days
            hours, remainder = divmod(uptime_delta.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            
            if days > 0:
                return f"{days}d {hours}h {minutes}m"
            elif hours > 0:
                return f"{hours}h {minutes}m"
            else:
                return f"{minutes}m"
        except Exception:
            return "Unknown"
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f}{size_names[i]}"
    
    @staticmethod
    def sanitize_target_name(target: str) -> str:
        """Sanitize target name for use in filenames"""
        import re
        # Remove protocol and special characters
        sanitized = re.sub(r'^https?://', '', target)
        sanitized = re.sub(r'[^\w\-.]', '_', sanitized)
        return sanitized
    
    @staticmethod
    def get_severity_color(severity: str) -> str:
        """Get color code for vulnerability severity"""
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#6c757d'
        }
        return severity_colors.get(severity.lower(), '#6c757d')
    
    @staticmethod
    def paginate_results(items: List[Any], page: int = 1, per_page: int = 20) -> Dict[str, Any]:
        """Paginate a list of items"""
        total_items = len(items)
        total_pages = (total_items + per_page - 1) // per_page
        
        start_index = (page - 1) * per_page
        end_index = start_index + per_page
        
        return {
            'items': items[start_index:end_index],
            'page': page,
            'per_page': per_page,
            'total_items': total_items,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages
        }
    
    @staticmethod
    def filter_findings_by_severity(findings: List[Dict[str, Any]], 
                                   severities: List[str] = None) -> List[Dict[str, Any]]:
        """Filter findings by severity levels"""
        if not severities:
            return findings
        
        return [f for f in findings if f.get('severity', '').lower() in severities]
    
    @staticmethod
    def search_findings(findings: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
        """Search findings by title, description, or URL"""
        if not query:
            return findings
        
        query = query.lower()
        filtered = []
        
        for finding in findings:
            searchable_text = ' '.join([
                finding.get('title', ''),
                finding.get('description', ''),
                finding.get('url', ''),
                finding.get('vulnerability_type', '')
            ]).lower()
            
            if query in searchable_text:
                filtered.append(finding)
        
        return filtered
    
    @staticmethod
    def export_findings_csv(findings: List[Dict[str, Any]]) -> str:
        """Export findings to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Title', 'Severity', 'URL', 'Type', 'Description'])
        
        # Write findings
        for finding in findings:
            writer.writerow([
                finding.get('title', ''),
                finding.get('severity', ''),
                finding.get('url', ''),
                finding.get('vulnerability_type', ''),
                finding.get('description', '')
            ])
        
        return output.getvalue()
    
    @staticmethod
    def export_subdomains_txt(subdomains: List[str]) -> str:
        """Export subdomains to text format"""
        return '\n'.join(subdomains)
    
    @staticmethod
    def validate_target_scope(target: str, allowed_domains: List[str] = None) -> bool:
        """Validate if target is within allowed scope"""
        if not allowed_domains:
            return True
        
        # Extract domain from target
        import re
        from urllib.parse import urlparse
        
        if target.startswith('http'):
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target
        
        # Check if domain or any parent domain is in allowed list
        for allowed in allowed_domains:
            if domain == allowed or domain.endswith('.' + allowed):
                return True
        
        return False
    
    @staticmethod
    def generate_scan_report_summary(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of scan results"""
        findings = scan_data.get('vulnerabilities', {}).get('all_findings', [])
        subdomains = scan_data.get('subdomains', {}).get('discovered', [])
        urls = scan_data.get('web_data', {}).get('urls', [])
        
        # Count findings by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate risk score
        risk_score = (
            severity_counts.get('critical', 0) * 10 +
            severity_counts.get('high', 0) * 7 +
            severity_counts.get('medium', 0) * 4 +
            severity_counts.get('low', 0) * 1
        )
        
        return {
            'total_findings': len(findings),
            'severity_distribution': severity_counts,
            'risk_score': risk_score,
            'subdomains_found': len(subdomains),
            'urls_discovered': len(urls),
            'has_critical': severity_counts.get('critical', 0) > 0,
            'completion_rate': 100.0  # Assume completed
        }
    
    @staticmethod
    async def cleanup_old_files(directory: Path, max_age_days: int = 30) -> int:
        """Clean up old files in a directory"""
        if not directory.exists():
            return 0
        
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        cleaned_count = 0
        
        try:
            for file_path in directory.iterdir():
                if file_path.is_file():
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_time < cutoff_date:
                        file_path.unlink()
                        cleaned_count += 1
                        logger.info(f"Cleaned up old file: {file_path}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
        
        return cleaned_count

class WebSocketManager:
    """Manage WebSocket connections and broadcasting"""
    
    def __init__(self):
        self.connections: List[Any] = []
    
    async def connect(self, websocket):
        """Add a new WebSocket connection"""
        await websocket.accept()
        self.connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.connections)}")
    
    def disconnect(self, websocket):
        """Remove a WebSocket connection"""
        if websocket in self.connections:
            self.connections.remove(websocket)
            logger.info(f"WebSocket disconnected. Total connections: {len(self.connections)}")
    
    async def broadcast_message(self, message: str):
        """Broadcast a message to all connected WebSockets"""
        if not self.connections:
            return
        
        disconnected = []
        for connection in self.connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.warning(f"Failed to send message to WebSocket: {e}")
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_scan_update(self, scan_id: str, status: str, progress: float = None):
        """Broadcast scan status update"""
        message_data = {
            'type': 'scan_update',
            'scan_id': scan_id,
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        
        if progress is not None:
            message_data['progress'] = progress
        
        await self.broadcast_message(json.dumps(message_data))
    
    async def broadcast_new_finding(self, finding: Dict[str, Any]):
        """Broadcast new vulnerability finding"""
        message_data = {
            'type': 'new_finding',
            'finding': finding,
            'timestamp': datetime.now().isoformat()
        }
        
        await self.broadcast_message(json.dumps(message_data))
    
    async def broadcast_system_alert(self, alert_type: str, message: str):
        """Broadcast system alert"""
        message_data = {
            'type': 'system_alert',
            'alert_type': alert_type,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        await self.broadcast_message(json.dumps(message_data))