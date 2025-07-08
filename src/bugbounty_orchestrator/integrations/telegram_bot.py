"""
Telegram Bot Integration for Bug Bounty Orchestrator
Receives domain targets and sends scan results via Telegram
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from pathlib import Path

from telethon import TelegramClient, events
from telethon.tl.types import User, Chat, Channel

from ..core.orchestrator import BugBountyOrchestrator
from ..core.config_manager import config_manager

logger = logging.getLogger(__name__)

class TelegramBotIntegration:
    """Telegram bot for receiving scan requests and sending results"""
    
    def __init__(self, orchestrator: BugBountyOrchestrator):
        self.orchestrator = orchestrator
        self.client: Optional[TelegramClient] = None
        self.authorized_users: List[int] = []
        self.authorized_chats: List[int] = []
        self.running = False
        
        # Get configuration
        self._load_config()
        
        # Scan tracking
        self.active_scan_requests: Dict[str, Dict[str, Any]] = {}
    
    def _load_config(self):
        """Load Telegram configuration"""
        self.config = config_manager.get_config('platforms', 'telegram') or {}
        
        # Required settings
        self.api_id = self.config.get('api_id')
        self.api_hash = self.config.get('api_hash')
        self.bot_token = self.config.get('bot_token')
        self.session_name = self.config.get('session_name', 'bb_orchestrator')
        
        # Authorization settings
        self.authorized_users = self.config.get('authorized_users', [])
        self.authorized_chats = self.config.get('authorized_chats', [])
        
        # Bot settings
        self.auto_scan = self.config.get('auto_scan', True)
        self.default_workflow = self.config.get('default_workflow', 'comprehensive_scan')
        self.send_progress_updates = self.config.get('send_progress_updates', True)
        self.max_message_length = self.config.get('max_message_length', 4000)
    
    async def initialize(self) -> bool:
        """Initialize Telegram client"""
        if not all([self.api_id, self.api_hash, self.bot_token]):
            logger.error("Telegram configuration incomplete. Check api_id, api_hash, and bot_token")
            return False
        
        try:
            # Create session directory
            session_dir = Path("data/telegram_sessions")
            session_dir.mkdir(parents=True, exist_ok=True)
            
            session_path = session_dir / f"{self.session_name}.session"
            
            # Initialize client
            self.client = TelegramClient(
                str(session_path),
                self.api_id,
                self.api_hash
            )
            
            # Start client with bot token
            await self.client.start(bot_token=self.bot_token)
            
            # Register event handlers
            self._register_handlers()
            
            logger.info("Telegram bot initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Telegram bot: {e}")
            return False
    
    def _register_handlers(self):
        """Register Telegram event handlers"""
        
        @self.client.on(events.NewMessage)
        async def handle_message(event):
            """Handle incoming messages"""
            try:
                await self._process_message(event)
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                await self._send_error_message(event.chat_id, f"Error processing message: {str(e)}")
        
        @self.client.on(events.CallbackQuery)
        async def handle_callback(event):
            """Handle callback queries from inline keyboards"""
            try:
                await self._process_callback(event)
            except Exception as e:
                logger.error(f"Error processing callback: {e}")
    
    async def _process_message(self, event):
        """Process incoming message"""
        # Check authorization
        if not await self._is_authorized(event):
            await event.reply("❌ Unauthorized. Contact administrator for access.")
            return
        
        message_text = event.message.message.strip()
        
        # Handle commands
        if message_text.startswith('/'):
            await self._handle_command(event, message_text)
        else:
            # Try to extract domains from message
            await self._handle_domain_message(event, message_text)
    
    async def _is_authorized(self, event) -> bool:
        """Check if user/chat is authorized"""
        sender = await event.get_sender()
        chat = await event.get_chat()
        
        # Check user authorization
        if isinstance(sender, User) and sender.id in self.authorized_users:
            return True
        
        # Check chat authorization
        if chat.id in self.authorized_chats:
            return True
        
        # If no specific authorization is set, allow all (for development)
        if not self.authorized_users and not self.authorized_chats:
            logger.warning("No Telegram authorization configured - allowing all users")
            return True
        
        return False
    
    async def _handle_command(self, event, command: str):
        """Handle bot commands"""
        cmd_parts = command.split()
        cmd = cmd_parts[0].lower()
        
        if cmd == '/start':
            await self._cmd_start(event)
        elif cmd == '/help':
            await self._cmd_help(event)
        elif cmd == '/scan':
            await self._cmd_scan(event, cmd_parts[1:])
        elif cmd == '/status':
            await self._cmd_status(event)
        elif cmd == '/scans':
            await self._cmd_list_scans(event)
        elif cmd == '/cancel':
            await self._cmd_cancel_scan(event, cmd_parts[1:])
        elif cmd == '/workflows':
            await self._cmd_list_workflows(event)
        elif cmd == '/config':
            await self._cmd_config(event)
        else:
            await event.reply(f"❓ Unknown command: {cmd}\nType /help for available commands.")
    
    async def _cmd_start(self, event):
        """Start command"""
        welcome_msg = """
🎯 **Bug Bounty Orchestrator Bot**

Welcome! I can help you manage security scans.

**Quick Start:**
• Send me domain names to scan
• Use /scan domain.com for manual scans
• Type /help for all commands

**Example:**
`example.com`
`https://target.com`
`scan these: domain1.com domain2.com`
        """
        await event.reply(welcome_msg)
    
    async def _cmd_help(self, event):
        """Help command"""
        help_msg = """
🔧 **Available Commands:**

**Scanning:**
• `/scan <domain>` - Start scan for specific domain
• `/scans` - List recent scans
• `/status` - Get system status
• `/cancel <scan_id>` - Cancel running scan

**Configuration:**
• `/workflows` - List available workflows
• `/config` - Show bot configuration

**Direct Usage:**
• Just send domain names in any message
• Supports multiple domains per message
• Auto-detects URLs and domain formats

**Examples:**
• `example.com`
• `/scan target.com`
• `Check these domains: site1.com site2.com`
        """
        await event.reply(help_msg)
    
    async def _cmd_scan(self, event, args: List[str]):
        """Manual scan command"""
        if not args:
            await event.reply("❌ Please provide a domain to scan.\nExample: `/scan example.com`")
            return
        
        target = args[0]
        workflow = args[1] if len(args) > 1 else self.default_workflow
        
        await self._start_scan_for_target(event, target, workflow)
    
    async def _cmd_status(self, event):
        """System status command"""
        try:
            status = self.orchestrator.get_system_status()
            
            status_msg = f"""
📊 **System Status**

🔄 Active Scans: {status['active_scans']}
✅ Completed Scans: {status['total_scans_completed']}
🛠️ Available Tools: {status['available_tools']}
📋 Workflows: {status['available_workflows']}
🕐 Uptime: {status['uptime']}
📌 Version: {status['version']}
            """
            await event.reply(status_msg)
            
        except Exception as e:
            await event.reply(f"❌ Error getting status: {str(e)}")
    
    async def _cmd_list_scans(self, event):
        """List recent scans"""
        try:
            scans = await self.orchestrator.list_scans()
            recent_scans = scans[-10:]  # Last 10 scans
            
            if not recent_scans:
                await event.reply("📝 No recent scans found.")
                return
            
            scans_msg = "📋 **Recent Scans:**\n\n"
            
            for scan in recent_scans:
                scan_id = scan['id'][:8]
                target = scan['target']
                status = scan['status']
                created = scan.get('created_at', 'Unknown')
                
                status_emoji = {
                    'running': '🔄',
                    'completed': '✅',
                    'failed': '❌',
                    'cancelled': '⏹️'
                }.get(status, '❓')
                
                scans_msg += f"{status_emoji} `{scan_id}` - {target} ({status})\n"
            
            await event.reply(scans_msg)
            
        except Exception as e:
            await event.reply(f"❌ Error listing scans: {str(e)}")
    
    async def _cmd_cancel_scan(self, event, args: List[str]):
        """Cancel scan command"""
        if not args:
            await event.reply("❌ Please provide scan ID to cancel.\nExample: `/cancel abc12345`")
            return
        
        scan_id_partial = args[0]
        
        try:
            # Find full scan ID
            scans = await self.orchestrator.list_scans('running')
            matching_scan = None
            
            for scan in scans:
                if scan['id'].startswith(scan_id_partial):
                    matching_scan = scan
                    break
            
            if not matching_scan:
                await event.reply(f"❌ No running scan found with ID starting with `{scan_id_partial}`")
                return
            
            success = await self.orchestrator.cancel_scan(matching_scan['id'])
            
            if success:
                await event.reply(f"⏹️ Scan cancelled: `{matching_scan['id'][:8]}` - {matching_scan['target']}")
            else:
                await event.reply(f"❌ Failed to cancel scan `{scan_id_partial}`")
                
        except Exception as e:
            await event.reply(f"❌ Error cancelling scan: {str(e)}")
    
    async def _cmd_list_workflows(self, event):
        """List available workflows"""
        try:
            workflows = self.orchestrator.get_available_workflows()
            
            workflows_msg = "📋 **Available Workflows:**\n\n"
            
            for workflow in workflows:
                workflows_msg += f"• `{workflow}`\n"
            
            workflows_msg += f"\n💡 Default: `{self.default_workflow}`"
            
            await event.reply(workflows_msg)
            
        except Exception as e:
            await event.reply(f"❌ Error listing workflows: {str(e)}")
    
    async def _cmd_config(self, event):
        """Show bot configuration"""
        config_msg = f"""
⚙️ **Bot Configuration**

🤖 Auto Scan: {'✅' if self.auto_scan else '❌'}
📋 Default Workflow: `{self.default_workflow}`
📊 Progress Updates: {'✅' if self.send_progress_updates else '❌'}
👥 Authorized Users: {len(self.authorized_users)}
💬 Authorized Chats: {len(self.authorized_chats)}
        """
        await event.reply(config_msg)
    
    async def _handle_domain_message(self, event, message_text: str):
        """Handle message containing domains"""
        domains = self._extract_domains(message_text)
        
        if not domains:
            # No domains found, send help
            await event.reply(
                "🤔 No domains detected in your message.\n\n"
                "**Supported formats:**\n"
                "• `example.com`\n"
                "• `https://example.com`\n"
                "• `subdomain.example.com`\n\n"
                "Type /help for more information."
            )
            return
        
        if len(domains) == 1:
            await self._start_scan_for_target(event, domains[0], self.default_workflow)
        else:
            await self._handle_multiple_domains(event, domains)
    
    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names from text"""
        domains = []
        
        # Remove common prefixes and clean text
        text = re.sub(r'https?://', '', text)
        text = re.sub(r'www\.', '', text)
        
        # Domain regex patterns
        patterns = [
            # Standard domain format
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            # IP addresses
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                # Basic validation
                if self._is_valid_domain(match):
                    domains.append(match.lower())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_domains = []
        for domain in domains:
            if domain not in seen:
                seen.add(domain)
                unique_domains.append(domain)
        
        return unique_domains
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        # Skip localhost and internal domains
        if domain in ['localhost', '127.0.0.1', '0.0.0.0']:
            return False
        
        # Skip domains with invalid characters
        if re.search(r'[^a-zA-Z0-9.-]', domain):
            return False
        
        # Must have at least one dot
        if '.' not in domain:
            return False
        
        # Must not start or end with dash or dot
        if domain.startswith('-') or domain.endswith('-'):
            return False
        
        if domain.startswith('.') or domain.endswith('.'):
            return False
        
        return True
    
    async def _start_scan_for_target(self, event, target: str, workflow: str):
        """Start scan for a single target"""
        try:
            # Validate target scope if enabled
            if config_manager.get_config('main', 'security', {}).get('validate_targets', True):
                scope_results = await self.orchestrator.check_target_scope(target)
                if not any(result.get('in_scope', False) for result in scope_results.values()):
                    logger.warning(f"Target {target} may not be in scope")
            
            # Start scan
            scan_id = await self.orchestrator.start_scan(target, workflow)
            
            # Track scan request
            self.active_scan_requests[scan_id] = {
                'chat_id': event.chat_id,
                'target': target,
                'workflow': workflow,
                'started_at': datetime.now(),
                'user_id': event.sender_id
            }
            
            # Send confirmation
            await event.reply(
                f"🚀 **Scan Started**\n\n"
                f"🎯 Target: `{target}`\n"
                f"📋 Workflow: `{workflow}`\n"
                f"🆔 Scan ID: `{scan_id[:8]}`\n\n"
                f"{'📊 Progress updates will be sent automatically.' if self.send_progress_updates else '💡 Use /scans to check progress.'}"
            )
            
            # Start monitoring this scan
            if self.send_progress_updates:
                asyncio.create_task(self._monitor_scan_progress(scan_id))
            
        except Exception as e:
            logger.error(f"Error starting scan for {target}: {e}")
            await event.reply(f"❌ Failed to start scan for `{target}`: {str(e)}")
    
    async def _handle_multiple_domains(self, event, domains: List[str]):
        """Handle multiple domains in one message"""
        if len(domains) > 10:
            await event.reply(
                f"⚠️ Too many domains ({len(domains)}). Maximum 10 domains per message.\n"
                f"Please split into smaller batches."
            )
            return
        
        await event.reply(
            f"🔍 **Found {len(domains)} domains:**\n" +
            "\n".join(f"• `{domain}`" for domain in domains) +
            f"\n\n🚀 Starting scans with workflow: `{self.default_workflow}`"
        )
        
        # Start scans for each domain
        scan_ids = []
        for domain in domains:
            try:
                scan_id = await self.orchestrator.start_scan(domain, self.default_workflow)
                scan_ids.append(scan_id)
                
                # Track scan request
                self.active_scan_requests[scan_id] = {
                    'chat_id': event.chat_id,
                    'target': domain,
                    'workflow': self.default_workflow,
                    'started_at': datetime.now(),
                    'user_id': event.sender_id,
                    'batch_scan': True
                }
                
            except Exception as e:
                logger.error(f"Error starting scan for {domain}: {e}")
                await self._send_message(
                    event.chat_id,
                    f"❌ Failed to start scan for `{domain}`: {str(e)}"
                )
        
        if scan_ids:
            await self._send_message(
                event.chat_id,
                f"✅ **{len(scan_ids)} scans started successfully**\n\n" +
                "📊 Results will be sent when scans complete."
            )
    
    async def _monitor_scan_progress(self, scan_id: str):
        """Monitor scan progress and send updates"""
        try:
            request_info = self.active_scan_requests.get(scan_id)
            if not request_info:
                return
            
            chat_id = request_info['chat_id']
            last_status = None
            
            while True:
                scan_status = await self.orchestrator.get_scan_status(scan_id)
                
                if not scan_status:
                    break
                
                current_status = scan_status['status']
                
                # Send update if status changed
                if current_status != last_status:
                    if current_status == 'completed':
                        await self._send_scan_results(scan_id, scan_status, chat_id)
                        break
                    elif current_status == 'failed':
                        await self._send_scan_failure(scan_id, scan_status, chat_id)
                        break
                    elif current_status == 'cancelled':
                        await self._send_message(
                            chat_id,
                            f"⏹️ Scan cancelled: `{scan_id[:8]}` - {request_info['target']}"
                        )
                        break
                
                last_status = current_status
                await asyncio.sleep(30)  # Check every 30 seconds
                
        except Exception as e:
            logger.error(f"Error monitoring scan {scan_id}: {e}")
        finally:
            # Clean up
            if scan_id in self.active_scan_requests:
                del self.active_scan_requests[scan_id]
    
    async def _send_scan_results(self, scan_id: str, scan_status: Dict[str, Any], chat_id: int):
        """Send scan results to Telegram"""
        try:
            request_info = self.active_scan_requests.get(scan_id, {})
            target = request_info.get('target', 'Unknown')
            
            results = scan_status.get('results', {})
            
            # Generate summary
            summary = self._generate_results_summary(results)
            
            message = f"""
✅ **Scan Completed**

🎯 **Target:** `{target}`
🆔 **Scan ID:** `{scan_id[:8]}`
⏱️ **Duration:** {self._calculate_duration(scan_status)}

{summary}
            """
            
            await self._send_message(chat_id, message)
            
            # Send detailed findings if any
            await self._send_detailed_findings(chat_id, results)
            
        except Exception as e:
            logger.error(f"Error sending scan results: {e}")
    
    def _generate_results_summary(self, results: Dict[str, Any]) -> str:
        """Generate summary of scan results"""
        summary_parts = []
        
        # Subdomain discovery
        subdomain_data = results.get('subdomain_discovery', {})
        total_subdomains = subdomain_data.get('total_subdomains', 0)
        if total_subdomains > 0:
            summary_parts.append(f"🌐 **Subdomains:** {total_subdomains} found")
        
        # Vulnerability findings
        vuln_data = results.get('vulnerability_scanning', {})
        findings = vuln_data.get('findings', [])
        
        if findings:
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'info').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            severity_summary = []
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    emoji = {
                        'critical': '🔴',
                        'high': '🟠', 
                        'medium': '🟡',
                        'low': '🔵',
                        'info': '⚪'
                    }.get(severity, '❓')
                    severity_summary.append(f"{emoji} {severity.title()}: {count}")
            
            if severity_summary:
                summary_parts.append(f"🚨 **Vulnerabilities:**\n" + "\n".join(severity_summary))
        
        # Web crawling
        web_data = results.get('web_crawling', {})
        total_urls = web_data.get('total_urls', 0)
        if total_urls > 0:
            summary_parts.append(f"🔗 **URLs:** {total_urls} discovered")
        
        return "\n\n".join(summary_parts) if summary_parts else "ℹ️ No significant findings detected."
    
    async def _send_detailed_findings(self, chat_id: int, results: Dict[str, Any]):
        """Send detailed vulnerability findings"""
        vuln_data = results.get('vulnerability_scanning', {})
        findings = vuln_data.get('findings', [])
        
        # Filter for high severity findings
        high_severity_findings = [
            f for f in findings 
            if f.get('severity', '').lower() in ['critical', 'high']
        ]
        
        if not high_severity_findings:
            return
        
        findings_message = "🚨 **High Severity Findings:**\n\n"
        
        for i, finding in enumerate(high_severity_findings[:5]):  # Limit to 5 findings
            severity = finding.get('severity', 'unknown').upper()
            title = finding.get('title', 'Unknown Vulnerability')
            url = finding.get('url', 'N/A')
            
            emoji = '🔴' if severity == 'CRITICAL' else '🟠'
            
            findings_message += f"{emoji} **{severity}** - {title}\n"
            findings_message += f"🔗 URL: `{url}`\n\n"
        
        if len(high_severity_findings) > 5:
            findings_message += f"... and {len(high_severity_findings) - 5} more findings\n"
        
        await self._send_message(chat_id, findings_message)
    
    async def _send_scan_failure(self, scan_id: str, scan_status: Dict[str, Any], chat_id: int):
        """Send scan failure notification"""
        try:
            request_info = self.active_scan_requests.get(scan_id, {})
            target = request_info.get('target', 'Unknown')
            
            errors = scan_status.get('errors', [])
            error_summary = errors[0] if errors else "Unknown error"
            
            message = f"""
❌ **Scan Failed**

🎯 **Target:** `{target}`
🆔 **Scan ID:** `{scan_id[:8]}`
⚠️ **Error:** {error_summary}
            """
            
            await self._send_message(chat_id, message)
            
        except Exception as e:
            logger.error(f"Error sending scan failure notification: {e}")
    
    def _calculate_duration(self, scan_status: Dict[str, Any]) -> str:
        """Calculate scan duration"""
        started_at = scan_status.get('started_at')
        completed_at = scan_status.get('completed_at')
        
        if not started_at or not completed_at:
            return "Unknown"
        
        try:
            from datetime import datetime
            start = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
            end = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
            
            duration = end - start
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
        except:
            return "Unknown"
    
    async def _send_message(self, chat_id: int, message: str):
        """Send message to Telegram chat"""
        try:
            if not self.client:
                return
            
            # Split long messages
            if len(message) > self.max_message_length:
                chunks = [
                    message[i:i+self.max_message_length] 
                    for i in range(0, len(message), self.max_message_length)
                ]
                
                for chunk in chunks:
                    await self.client.send_message(chat_id, chunk)
                    await asyncio.sleep(1)  # Rate limiting
            else:
                await self.client.send_message(chat_id, message)
                
        except Exception as e:
            logger.error(f"Error sending Telegram message: {e}")
    
    async def _send_error_message(self, chat_id: int, error: str):
        """Send error message"""
        await self._send_message(chat_id, f"❌ Error: {error}")
    
    async def start_bot(self):
        """Start the Telegram bot"""
        if not await self.initialize():
            return False
        
        self.running = True
        logger.info("Telegram bot started and listening for messages")
        
        try:
            # Send startup notification to authorized chats
            startup_msg = """
🤖 **Bug Bounty Orchestrator Bot Started**

✅ Ready to receive scan requests
📝 Send domain names to start scans
💡 Type /help for commands
            """
            
            for chat_id in self.authorized_chats:
                try:
                    await self._send_message(chat_id, startup_msg)
                except Exception as e:
                    logger.warning(f"Failed to send startup message to chat {chat_id}: {e}")
            
            # Keep the bot running
            await self.client.run_until_disconnected()
            
        except Exception as e:
            logger.error(f"Telegram bot error: {e}")
            return False
        finally:
            self.running = False
    
    async def stop_bot(self):
        """Stop the Telegram bot"""
        self.running = False
        
        if self.client:
            # Send shutdown notification
            shutdown_msg = "🔴 Bug Bounty Orchestrator Bot shutting down..."
            
            for chat_id in self.authorized_chats:
                try:
                    await self._send_message(chat_id, shutdown_msg)
                except:
                    pass
            
            await self.client.disconnect()
            
        logger.info("Telegram bot stopped")
    
    async def _process_callback(self, event):
        """Process callback queries from inline keyboards"""
        # Implementation for future interactive features
        await event.answer("Feature coming soon!")

# Global Telegram bot instance
telegram_bot: Optional[TelegramBotIntegration] = None

def get_telegram_bot(orchestrator: BugBountyOrchestrator) -> TelegramBotIntegration:
    """Get or create Telegram bot instance"""
    global telegram_bot
    if telegram_bot is None:
        telegram_bot = TelegramBotIntegration(orchestrator)
    return telegram_bot