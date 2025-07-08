"""
Notification manager for sending alerts about scan results
"""

import asyncio
import logging
import httpx
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..core.config import config, platform_config

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manager for sending notifications about scan results"""
    
    def __init__(self):
        self.notification_channels = {
            'slack': SlackNotifier(),
            'discord': DiscordNotifier(),
            'email': EmailNotifier()
        }
        
    async def send_scan_completion(self, scan_job: Any) -> None:
        """Send scan completion notification"""
        
        message = self._format_scan_completion_message(scan_job)
        
        await self._send_to_all_channels(message, 'scan_completion')
    
    async def send_critical_findings(self, target: str, findings: List[Dict[str, Any]]) -> None:
        """Send critical findings notification"""
        
        if not findings:
            return
        
        message = self._format_critical_findings_message(target, findings)
        
        await self._send_to_all_channels(message, 'critical_findings')
    
    async def send_platform_submission(self, target: str, submission_results: Dict[str, Any]) -> None:
        """Send platform submission notification"""
        
        message = self._format_platform_submission_message(target, submission_results)
        
        await self._send_to_all_channels(message, 'platform_submission')
    
    async def send_custom_alert(self, title: str, message: str, severity: str = 'info') -> None:
        """Send custom alert"""
        
        formatted_message = {
            'title': title,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        await self._send_to_all_channels(formatted_message, 'custom_alert')
    
    async def _send_to_all_channels(self, message: Dict[str, Any], notification_type: str) -> None:
        """Send message to all enabled notification channels"""
        
        notification_config = platform_config.get('notifications', {})
        
        # Check if this notification type is enabled
        if not notification_config.get(notification_type, True):
            return
        
        enabled_channels = notification_config.get('channels', ['slack', 'discord'])
        
        tasks = []
        for channel_name in enabled_channels:
            if channel_name in self.notification_channels:
                channel = self.notification_channels[channel_name]
                if channel.is_enabled():
                    tasks.append(channel.send_notification(message, notification_type))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def _format_scan_completion_message(self, scan_job: Any) -> Dict[str, Any]:
        """Format scan completion message"""
        
        duration = 0
        if scan_job.completed_at and scan_job.started_at:
            duration = (scan_job.completed_at - scan_job.started_at).total_seconds()
        
        # Extract summary from results
        total_findings = 0
        critical_count = 0
        high_count = 0
        
        vuln_results = scan_job.results.get('vulnerability_scanning', {})
        if 'summary' in vuln_results:
            summary = vuln_results['summary']
            total_findings = summary.get('total_findings', 0)
            critical_count = summary.get('critical', 0)
            high_count = summary.get('high', 0)
        
        severity = 'success'
        if critical_count > 0:
            severity = 'critical'
        elif high_count > 0:
            severity = 'warning'
        
        return {
            'title': f'Scan Completed: {scan_job.target}',
            'message': f'Scan completed in {duration:.0f} seconds',
            'severity': severity,
            'fields': {
                'Target': scan_job.target,
                'Workflow': scan_job.workflow,
                'Status': scan_job.status,
                'Duration': f'{duration:.0f}s',
                'Total Findings': total_findings,
                'Critical': critical_count,
                'High': high_count,
                'Errors': len(scan_job.errors)
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def _format_critical_findings_message(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Format critical findings message"""
        
        critical_findings = [f for f in findings if f.get('severity', '').lower() == 'critical']
        high_findings = [f for f in findings if f.get('severity', '').lower() == 'high']
        
        finding_summary = []
        for finding in (critical_findings + high_findings)[:5]:  # Limit to 5 findings
            finding_summary.append(
                f"• {finding.get('title', 'Unknown')}: {finding.get('url', 'N/A')}"
            )
        
        return {
            'title': f'🚨 Critical Findings Detected: {target}',
            'message': f'Found {len(critical_findings)} critical and {len(high_findings)} high severity vulnerabilities',
            'severity': 'critical',
            'fields': {
                'Target': target,
                'Critical': len(critical_findings),
                'High': len(high_findings),
                'Findings': '\n'.join(finding_summary[:3])
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def _format_platform_submission_message(self, target: str, submission_results: Dict[str, Any]) -> Dict[str, Any]:
        """Format platform submission message"""
        
        successful_submissions = 0
        total_submissions = 0
        platforms = []
        
        for platform, result in submission_results.items():
            if isinstance(result, dict):
                total_submitted = result.get('total_submitted', 0)
                total_submissions += total_submitted
                if total_submitted > 0:
                    successful_submissions += total_submitted
                    platforms.append(platform)
        
        return {
            'title': f'Platform Submissions: {target}',
            'message': f'Submitted {successful_submissions} findings to {len(platforms)} platforms',
            'severity': 'info',
            'fields': {
                'Target': target,
                'Platforms': ', '.join(platforms),
                'Successful Submissions': successful_submissions,
                'Total Attempts': total_submissions
            },
            'timestamp': datetime.now().isoformat()
        }

class BaseNotifier:
    """Base class for notification channels"""
    
    def __init__(self, channel_name: str):
        self.channel_name = channel_name
        
    def is_enabled(self) -> bool:
        """Check if notifier is enabled"""
        return True  # Override in subclasses
    
    async def send_notification(self, message: Dict[str, Any], notification_type: str) -> None:
        """Send notification - to be implemented by subclasses"""
        raise NotImplementedError

class SlackNotifier(BaseNotifier):
    """Slack notification channel"""
    
    def __init__(self):
        super().__init__('slack')
        self.webhook_url = config.slack_webhook_url
        
    def is_enabled(self) -> bool:
        """Check if Slack notifications are enabled"""
        return bool(self.webhook_url)
    
    async def send_notification(self, message: Dict[str, Any], notification_type: str) -> None:
        """Send notification to Slack"""
        
        if not self.webhook_url:
            return
        
        try:
            slack_message = self._format_slack_message(message)
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    self.webhook_url,
                    json=slack_message
                )
                
                if response.status_code != 200:
                    logger.error(f"Failed to send Slack notification: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
    
    def _format_slack_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Format message for Slack"""
        
        color_map = {
            'critical': '#FF0000',
            'warning': '#FFA500',
            'success': '#00FF00',
            'info': '#0066FF'
        }
        
        color = color_map.get(message.get('severity', 'info'), '#0066FF')
        
        slack_message = {
            'attachments': [{
                'color': color,
                'title': message.get('title', 'Bug Bounty Notification'),
                'text': message.get('message', ''),
                'timestamp': int(datetime.now().timestamp()),
                'fields': []
            }]
        }
        
        # Add fields
        fields = message.get('fields', {})
        for key, value in fields.items():
            slack_message['attachments'][0]['fields'].append({
                'title': key,
                'value': str(value),
                'short': True
            })
        
        return slack_message

class DiscordNotifier(BaseNotifier):
    """Discord notification channel"""
    
    def __init__(self):
        super().__init__('discord')
        self.webhook_url = config.discord_webhook_url
        
    def is_enabled(self) -> bool:
        """Check if Discord notifications are enabled"""
        return bool(self.webhook_url)
    
    async def send_notification(self, message: Dict[str, Any], notification_type: str) -> None:
        """Send notification to Discord"""
        
        if not self.webhook_url:
            return
        
        try:
            discord_message = self._format_discord_message(message)
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    self.webhook_url,
                    json=discord_message
                )
                
                if response.status_code not in [200, 204]:
                    logger.error(f"Failed to send Discord notification: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Error sending Discord notification: {e}")
    
    def _format_discord_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Format message for Discord"""
        
        color_map = {
            'critical': 16711680,  # Red
            'warning': 16753920,   # Orange
            'success': 65280,      # Green
            'info': 255           # Blue
        }
        
        color = color_map.get(message.get('severity', 'info'), 255)
        
        # Create embed
        embed = {
            'title': message.get('title', 'Bug Bounty Notification'),
            'description': message.get('message', ''),
            'color': color,
            'timestamp': datetime.now().isoformat(),
            'fields': []
        }
        
        # Add fields
        fields = message.get('fields', {})
        for key, value in fields.items():
            embed['fields'].append({
                'name': key,
                'value': str(value),
                'inline': True
            })
        
        return {'embeds': [embed]}

class EmailNotifier(BaseNotifier):
    """Email notification channel"""
    
    def __init__(self):
        super().__init__('email')
        # Email configuration would be loaded from config
        self.enabled = False  # Placeholder
        
    def is_enabled(self) -> bool:
        """Check if email notifications are enabled"""
        return self.enabled
    
    async def send_notification(self, message: Dict[str, Any], notification_type: str) -> None:
        """Send email notification"""
        
        # Email implementation would go here
        # Using SMTP or email service API
        
        logger.info(f"Email notification would be sent: {message.get('title', 'Notification')}")
        pass