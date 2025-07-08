"""
Bug bounty platform integration manager for HackerOne, Bugcrowd, Intigriti
"""

import asyncio
import logging
import httpx
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

from ..core.config import config, platform_config

logger = logging.getLogger(__name__)

class PlatformManager:
    """Manager for bug bounty platform integrations"""
    
    def __init__(self):
        self.platforms = {
            'hackerone': HackerOnePlatform(),
            'bugcrowd': BugcrowdPlatform(),
            'intigriti': IntigritiPlatform()
        }
        
    async def submit_findings(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submit findings to all configured platforms"""
        
        results = {}
        
        for platform_name, platform in self.platforms.items():
            if platform.is_enabled():
                try:
                    result = await platform.submit_findings(target, findings)
                    results[platform_name] = result
                except Exception as e:
                    logger.error(f"Failed to submit to {platform_name}: {e}")
                    results[platform_name] = {
                        'status': 'error',
                        'error': str(e)
                    }
        
        return results
    
    async def get_program_info(self, target: str) -> Dict[str, Any]:
        """Get program information from all platforms"""
        
        program_info = {}
        
        for platform_name, platform in self.platforms.items():
            if platform.is_enabled():
                try:
                    info = await platform.get_program_info(target)
                    if info:
                        program_info[platform_name] = info
                except Exception as e:
                    logger.error(f"Failed to get program info from {platform_name}: {e}")
        
        return program_info
    
    async def check_program_scope(self, target: str) -> Dict[str, Any]:
        """Check if target is in scope for any programs"""
        
        scope_results = {}
        
        for platform_name, platform in self.platforms.items():
            if platform.is_enabled():
                try:
                    in_scope = await platform.check_scope(target)
                    scope_results[platform_name] = in_scope
                except Exception as e:
                    logger.error(f"Failed to check scope on {platform_name}: {e}")
                    scope_results[platform_name] = {'in_scope': False, 'error': str(e)}
        
        return scope_results

class BasePlatform:
    """Base class for bug bounty platforms"""
    
    def __init__(self, platform_name: str):
        self.platform_name = platform_name
        self.config = platform_config.get_platform_integrations().get(platform_name, {})
        
    def is_enabled(self) -> bool:
        """Check if platform is enabled"""
        return self.config.get('enabled', False)
    
    async def submit_findings(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submit findings to platform - to be implemented by subclasses"""
        raise NotImplementedError
    
    async def get_program_info(self, target: str) -> Optional[Dict[str, Any]]:
        """Get program information - to be implemented by subclasses"""
        raise NotImplementedError
    
    async def check_scope(self, target: str) -> Dict[str, Any]:
        """Check if target is in scope - to be implemented by subclasses"""
        raise NotImplementedError

class HackerOnePlatform(BasePlatform):
    """HackerOne platform integration"""
    
    def __init__(self):
        super().__init__('hackerone')
        self.base_url = "https://api.hackerone.com/v1"
        self.api_key = config.hackerone_api_key
        
    async def submit_findings(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submit findings to HackerOne"""
        
        if not self.api_key:
            return {'status': 'error', 'error': 'No API key configured'}
        
        # Filter critical/high findings
        critical_findings = [
            f for f in findings 
            if f.get('severity', '').lower() in ['critical', 'high']
        ]
        
        if not critical_findings:
            return {'status': 'skipped', 'reason': 'No critical/high findings to submit'}
        
        submissions = []
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            for finding in critical_findings:
                # Check if program exists for target
                program = await self._find_program(target, client, headers)
                if not program:
                    continue
                
                # Create report
                report_data = self._format_report_for_hackerone(finding, target, program)
                
                try:
                    response = await client.post(
                        f"{self.base_url}/reports",
                        headers=headers,
                        json=report_data
                    )
                    
                    if response.status_code == 201:
                        submissions.append({
                            'finding_id': finding.get('title'),
                            'status': 'submitted',
                            'report_id': response.json().get('id')
                        })
                    else:
                        submissions.append({
                            'finding_id': finding.get('title'),
                            'status': 'failed',
                            'error': response.text
                        })
                        
                except Exception as e:
                    submissions.append({
                        'finding_id': finding.get('title'),
                        'status': 'error',
                        'error': str(e)
                    })
        
        return {
            'status': 'completed',
            'platform': 'hackerone',
            'submissions': submissions,
            'total_submitted': len([s for s in submissions if s['status'] == 'submitted'])
        }
    
    async def get_program_info(self, target: str) -> Optional[Dict[str, Any]]:
        """Get HackerOne program information"""
        
        if not self.api_key:
            return None
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {'Authorization': f'Bearer {self.api_key}'}
            
            try:
                # Search for programs
                response = await client.get(
                    f"{self.base_url}/programs",
                    headers=headers,
                    params={'filter[state]': 'active'}
                )
                
                if response.status_code == 200:
                    programs = response.json().get('data', [])
                    
                    for program in programs:
                        attributes = program.get('attributes', {})
                        scope = attributes.get('structured_scope', [])
                        
                        # Check if target matches scope
                        for scope_item in scope:
                            asset_identifier = scope_item.get('asset_identifier', '')
                            if target in asset_identifier or asset_identifier in target:
                                return {
                                    'id': program.get('id'),
                                    'name': attributes.get('name'),
                                    'handle': attributes.get('handle'),
                                    'state': attributes.get('state'),
                                    'scope': scope
                                }
                
            except Exception as e:
                logger.error(f"Failed to get HackerOne program info: {e}")
        
        return None
    
    async def check_scope(self, target: str) -> Dict[str, Any]:
        """Check if target is in HackerOne program scope"""
        
        program_info = await self.get_program_info(target)
        
        if program_info:
            return {
                'in_scope': True,
                'program': program_info['name'],
                'handle': program_info['handle']
            }
        
        return {'in_scope': False}
    
    async def _find_program(self, target: str, client: httpx.AsyncClient, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Find HackerOne program for target"""
        
        try:
            response = await client.get(
                f"{self.base_url}/programs",
                headers=headers,
                params={'filter[state]': 'active'}
            )
            
            if response.status_code == 200:
                programs = response.json().get('data', [])
                
                for program in programs:
                    attributes = program.get('attributes', {})
                    scope = attributes.get('structured_scope', [])
                    
                    for scope_item in scope:
                        asset_identifier = scope_item.get('asset_identifier', '')
                        if target in asset_identifier or asset_identifier in target:
                            return program
                            
        except Exception:
            pass
        
        return None
    
    def _format_report_for_hackerone(self, finding: Dict[str, Any], target: str, program: Dict[str, Any]) -> Dict[str, Any]:
        """Format finding for HackerOne report submission"""
        
        return {
            "data": {
                "type": "report",
                "attributes": {
                    "title": finding.get('title', 'Security Vulnerability'),
                    "vulnerability_information": self._format_vulnerability_info(finding),
                    "program": program.get('id'),
                    "severity_rating": self._map_severity_to_hackerone(finding.get('severity', 'medium'))
                }
            }
        }
    
    def _format_vulnerability_info(self, finding: Dict[str, Any]) -> str:
        """Format vulnerability information for HackerOne"""
        
        info = f"**Vulnerability Type:** {finding.get('vulnerability_type', 'Unknown')}\n\n"
        info += f"**Description:** {finding.get('description', 'No description provided')}\n\n"
        info += f"**URL:** {finding.get('url', 'N/A')}\n\n"
        
        if finding.get('payload'):
            info += f"**Payload:** `{finding['payload']}`\n\n"
        
        if finding.get('evidence'):
            info += f"**Evidence:** {finding['evidence']}\n\n"
        
        info += "**Steps to Reproduce:**\n"
        info += "1. Navigate to the affected URL\n"
        info += "2. Apply the provided payload\n"
        info += "3. Observe the vulnerability\n\n"
        
        info += "**Impact:**\n"
        info += f"This vulnerability could allow an attacker to {self._get_impact_description(finding)}\n"
        
        return info
    
    def _map_severity_to_hackerone(self, severity: str) -> str:
        """Map severity to HackerOne severity rating"""
        
        mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'none'
        }
        
        return mapping.get(severity.lower(), 'medium')
    
    def _get_impact_description(self, finding: Dict[str, Any]) -> str:
        """Get impact description based on vulnerability type"""
        
        vuln_type = finding.get('vulnerability_type', '').lower()
        
        impacts = {
            'sqli': 'execute arbitrary SQL queries and potentially access sensitive database information',
            'xss': 'execute malicious scripts in user browsers and steal sensitive information',
            'rce': 'execute arbitrary commands on the server',
            'ssrf': 'make requests to internal services and potentially access sensitive data',
            'directory_traversal': 'access sensitive files on the server filesystem',
            'open_redirect': 'redirect users to malicious websites for phishing attacks'
        }
        
        return impacts.get(vuln_type, 'compromise the security of the application')

class BugcrowdPlatform(BasePlatform):
    """Bugcrowd platform integration"""
    
    def __init__(self):
        super().__init__('bugcrowd')
        self.base_url = "https://api.bugcrowd.com"
        self.api_key = config.bugcrowd_api_key
        
    async def submit_findings(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submit findings to Bugcrowd"""
        
        # Placeholder implementation
        # Bugcrowd API integration would be implemented here
        
        return {
            'status': 'not_implemented',
            'platform': 'bugcrowd',
            'message': 'Bugcrowd integration not yet implemented'
        }
    
    async def get_program_info(self, target: str) -> Optional[Dict[str, Any]]:
        """Get Bugcrowd program information"""
        
        # Placeholder implementation
        return None
    
    async def check_scope(self, target: str) -> Dict[str, Any]:
        """Check if target is in Bugcrowd program scope"""
        
        return {'in_scope': False, 'reason': 'Not implemented'}

class IntigritiPlatform(BasePlatform):
    """Intigriti platform integration"""
    
    def __init__(self):
        super().__init__('intigriti')
        self.base_url = "https://api.intigriti.com"
        self.api_key = config.intigriti_api_key
        
    async def submit_findings(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submit findings to Intigriti"""
        
        # Placeholder implementation
        # Intigriti API integration would be implemented here
        
        return {
            'status': 'not_implemented',
            'platform': 'intigriti',
            'message': 'Intigriti integration not yet implemented'
        }
    
    async def get_program_info(self, target: str) -> Optional[Dict[str, Any]]:
        """Get Intigriti program information"""
        
        # Placeholder implementation
        return None
    
    async def check_scope(self, target: str) -> Dict[str, Any]:
        """Check if target is in Intigriti program scope"""
        
        return {'in_scope': False, 'reason': 'Not implemented'}