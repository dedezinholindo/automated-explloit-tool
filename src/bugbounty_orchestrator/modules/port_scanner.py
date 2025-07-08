"""
Port scanning module using Nmap and other tools
"""

import asyncio
import logging
import json
from typing import Dict, List, Any, Set
import socket
import subprocess

from ..core.config import platform_config, config
from ..core.scanner import ScanEngine

logger = logging.getLogger(__name__)

class PortScanner:
    """Comprehensive port scanning using multiple techniques"""
    
    def __init__(self, scan_engine: ScanEngine = None):
        self.scan_engine = scan_engine or ScanEngine()
        
    async def scan_ports(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive port scanning"""
        
        # Extract IPs/hosts from target
        hosts = await self._resolve_targets(target, options)
        
        logger.info(f"Starting port scan for {len(hosts)} hosts")
        
        results = {
            'scan_type': 'comprehensive',
            'targets': hosts,
            'total_hosts': len(hosts),
            'scan_results': {},
            'summary': {
                'total_open_ports': 0,
                'unique_services': set(),
                'hosts_with_open_ports': 0
            }
        }
        
        # Run multiple scanning techniques
        scan_tasks = []
        
        # Nmap scan if available
        if platform_config.is_tool_enabled('nmap'):
            scan_tasks.append(self._nmap_scan(hosts, options))
        
        # Masscan if available and many hosts
        if platform_config.is_tool_enabled('masscan') and len(hosts) > 5:
            scan_tasks.append(self._masscan_scan(hosts, options))
        
        # Custom TCP scan for specific ports
        scan_tasks.append(self._tcp_connect_scan(hosts, options))
        
        # Execute scanning tasks
        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Process and merge results
        merged_results = {}
        for i, result in enumerate(scan_results):
            if isinstance(result, Exception):
                logger.error(f"Scan method {i} failed: {result}")
                continue
                
            if isinstance(result, dict) and 'host_results' in result:
                for host, host_data in result['host_results'].items():
                    if host not in merged_results:
                        merged_results[host] = {
                            'ip': host,
                            'open_ports': [],
                            'services': {},
                            'scan_methods': []
                        }
                    
                    # Merge port data
                    if 'open_ports' in host_data:
                        existing_ports = {p['port'] for p in merged_results[host]['open_ports']}
                        for port_info in host_data['open_ports']:
                            if port_info['port'] not in existing_ports:
                                merged_results[host]['open_ports'].append(port_info)
                    
                    # Merge service data
                    if 'services' in host_data:
                        merged_results[host]['services'].update(host_data['services'])
                    
                    # Track scan methods
                    method = result.get('method', f'method_{i}')
                    merged_results[host]['scan_methods'].append(method)
        
        results['scan_results'] = merged_results
        
        # Calculate summary
        total_open_ports = 0
        unique_services = set()
        hosts_with_open_ports = 0
        
        for host_data in merged_results.values():
            open_ports = host_data.get('open_ports', [])
            if open_ports:
                hosts_with_open_ports += 1
                total_open_ports += len(open_ports)
                
                for port_info in open_ports:
                    service = port_info.get('service', 'unknown')
                    if service != 'unknown':
                        unique_services.add(service)
        
        results['summary'].update({
            'total_open_ports': total_open_ports,
            'unique_services': list(unique_services),
            'hosts_with_open_ports': hosts_with_open_ports
        })
        
        logger.info(f"Port scan completed: {total_open_ports} open ports on {hosts_with_open_ports} hosts")
        
        return results
    
    async def passive_scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Passive port discovery using external sources"""
        
        logger.info(f"Starting passive port discovery for: {target}")
        
        results = {
            'scan_type': 'passive',
            'target': target,
            'sources': {},
            'discovered_ports': [],
            'summary': {}
        }
        
        # Passive discovery methods
        passive_tasks = [
            self._shodan_port_discovery(target),
            self._censys_port_discovery(target),
            self._certificate_port_discovery(target)
        ]
        
        passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)
        
        all_ports = set()
        
        for i, result in enumerate(passive_results):
            source_name = f"source_{i}"
            
            if isinstance(result, Exception):
                logger.error(f"Passive source {source_name} failed: {result}")
                results['sources'][source_name] = {
                    'status': 'failed',
                    'error': str(result),
                    'ports': []
                }
            else:
                results['sources'][source_name] = result
                if 'ports' in result:
                    all_ports.update(result['ports'])
        
        results['discovered_ports'] = list(all_ports)
        results['summary'] = {
            'total_ports': len(all_ports),
            'sources_used': len(results['sources'])
        }
        
        return results
    
    async def _resolve_targets(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Resolve target to list of IP addresses/hostnames"""
        
        targets = []
        
        if isinstance(target, str):
            if ',' in target:
                # Multiple targets
                targets = [t.strip() for t in target.split(',')]
            else:
                targets = [target]
        elif isinstance(target, list):
            targets = target
        
        resolved_targets = []
        
        for t in targets:
            try:
                # Try to resolve hostname to IP
                if not self._is_ip_address(t):
                    try:
                        ip = socket.gethostbyname(t)
                        resolved_targets.append(ip)
                    except socket.gaierror:
                        # Keep original if resolution fails
                        resolved_targets.append(t)
                else:
                    resolved_targets.append(t)
            except Exception as e:
                logger.warning(f"Failed to resolve target {t}: {e}")
                continue
        
        return resolved_targets
    
    async def _nmap_scan(self, hosts: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Nmap scan via MCP"""
        
        try:
            if not self.scan_engine.is_tool_available('nmap'):
                raise RuntimeError("Nmap MCP tool not available")
            
            # Get scan parameters
            ports = options.get('ports', '1-1000')
            scan_type = options.get('scan_type', '-sS')
            
            result = await self.scan_engine.run_tool(
                'nmap',
                'scan',
                {
                    'targets': hosts,
                    'ports': ports,
                    'scan_type': scan_type,
                    'service_detection': True
                }
            )
            
            host_results = {}
            
            if result.get('status') == 'success':
                for host_data in result.get('results', []):
                    if 'ip' in host_data:
                        ip = host_data['ip']
                        host_results[ip] = {
                            'ip': ip,
                            'open_ports': [],
                            'services': {}
                        }
                        
                        for port_info in host_data.get('ports', []):
                            if port_info.get('state') == 'open':
                                port_data = {
                                    'port': int(port_info['port']),
                                    'protocol': port_info.get('protocol', 'tcp'),
                                    'service': port_info.get('service', 'unknown'),
                                    'version': port_info.get('version', ''),
                                    'state': 'open'
                                }
                                host_results[ip]['open_ports'].append(port_data)
                                host_results[ip]['services'][port_info['port']] = port_info.get('service', 'unknown')
            
            return {
                'method': 'nmap',
                'status': 'success',
                'host_results': host_results,
                'scan_parameters': {
                    'ports': ports,
                    'scan_type': scan_type
                }
            }
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {
                'method': 'nmap',
                'status': 'failed',
                'error': str(e),
                'host_results': {}
            }
    
    async def _masscan_scan(self, hosts: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Masscan scan via MCP"""
        
        try:
            if not self.scan_engine.is_tool_available('masscan'):
                raise RuntimeError("Masscan MCP tool not available")
            
            ports = options.get('ports', '1-1000')
            rate = options.get('rate', 1000)
            
            result = await self.scan_engine.run_tool(
                'masscan',
                'scan',
                {
                    'targets': hosts,
                    'ports': ports,
                    'rate': rate
                }
            )
            
            host_results = {}
            
            if result.get('status') == 'success':
                for scan_result in result.get('results', []):
                    ip = scan_result.get('ip')
                    port = scan_result.get('port')
                    
                    if ip and port:
                        if ip not in host_results:
                            host_results[ip] = {
                                'ip': ip,
                                'open_ports': [],
                                'services': {}
                            }
                        
                        port_data = {
                            'port': int(port),
                            'protocol': scan_result.get('protocol', 'tcp'),
                            'service': 'unknown',  # Masscan doesn't detect services
                            'state': 'open'
                        }
                        host_results[ip]['open_ports'].append(port_data)
            
            return {
                'method': 'masscan',
                'status': 'success',
                'host_results': host_results,
                'scan_parameters': {
                    'ports': ports,
                    'rate': rate
                }
            }
            
        except Exception as e:
            logger.error(f"Masscan scan failed: {e}")
            return {
                'method': 'masscan',
                'status': 'failed',
                'error': str(e),
                'host_results': {}
            }
    
    async def _tcp_connect_scan(self, hosts: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
        """Simple TCP connect scan for common ports"""
        
        try:
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
            ports_to_scan = options.get('common_ports', common_ports)
            
            host_results = {}
            
            for host in hosts:
                host_results[host] = {
                    'ip': host,
                    'open_ports': [],
                    'services': {}
                }
                
                # Scan ports for this host
                port_tasks = []
                for port in ports_to_scan:
                    port_tasks.append(self._check_tcp_port(host, port))
                
                port_results = await asyncio.gather(*port_tasks, return_exceptions=True)
                
                for i, is_open in enumerate(port_results):
                    if is_open and not isinstance(is_open, Exception):
                        port = ports_to_scan[i]
                        service = self._guess_service_by_port(port)
                        
                        port_data = {
                            'port': port,
                            'protocol': 'tcp',
                            'service': service,
                            'state': 'open'
                        }
                        host_results[host]['open_ports'].append(port_data)
                        host_results[host]['services'][str(port)] = service
            
            return {
                'method': 'tcp_connect',
                'status': 'success',
                'host_results': host_results,
                'scan_parameters': {
                    'ports': ports_to_scan
                }
            }
            
        except Exception as e:
            logger.error(f"TCP connect scan failed: {e}")
            return {
                'method': 'tcp_connect',
                'status': 'failed',
                'error': str(e),
                'host_results': {}
            }
    
    async def _check_tcp_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a TCP port is open"""
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    def _guess_service_by_port(self, port: int) -> str:
        """Guess service by port number"""
        port_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            111: 'rpcbind',
            135: 'msrpc',
            139: 'netbios-ssn',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1723: 'pptp',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            8080: 'http-proxy'
        }
        return port_services.get(port, 'unknown')
    
    async def _shodan_port_discovery(self, target: str) -> Dict[str, Any]:
        """Discover open ports using Shodan API"""
        
        try:
            if not config.shodan_api_key:
                return {
                    'source': 'shodan',
                    'status': 'skipped',
                    'reason': 'No API key configured',
                    'ports': []
                }
            
            import shodan
            
            api = shodan.Shodan(config.shodan_api_key)
            
            try:
                # Search for the target
                results = api.host(target)
                
                ports = []
                for item in results.get('data', []):
                    port = item.get('port')
                    if port:
                        ports.append({
                            'port': port,
                            'protocol': item.get('transport', 'tcp'),
                            'service': item.get('product', 'unknown'),
                            'banner': item.get('data', '')[:100]  # Truncate banner
                        })
                
                return {
                    'source': 'shodan',
                    'status': 'success',
                    'ports': [p['port'] for p in ports],
                    'detailed_ports': ports,
                    'count': len(ports)
                }
                
            except shodan.APIError as e:
                return {
                    'source': 'shodan',
                    'status': 'failed',
                    'error': str(e),
                    'ports': []
                }
                
        except ImportError:
            return {
                'source': 'shodan',
                'status': 'skipped',
                'reason': 'Shodan library not installed',
                'ports': []
            }
        except Exception as e:
            logger.error(f"Shodan port discovery failed: {e}")
            return {
                'source': 'shodan',
                'status': 'failed',
                'error': str(e),
                'ports': []
            }
    
    async def _censys_port_discovery(self, target: str) -> Dict[str, Any]:
        """Discover open ports using Censys API"""
        
        try:
            # Censys API integration would go here
            # For now, return placeholder
            
            return {
                'source': 'censys',
                'status': 'not_implemented',
                'reason': 'Censys integration not implemented',
                'ports': []
            }
            
        except Exception as e:
            logger.error(f"Censys port discovery failed: {e}")
            return {
                'source': 'censys',
                'status': 'failed',
                'error': str(e),
                'ports': []
            }
    
    async def _certificate_port_discovery(self, target: str) -> Dict[str, Any]:
        """Discover ports by checking common SSL/TLS ports"""
        
        try:
            ssl_ports = [443, 993, 995, 8443, 9443]
            
            open_ports = []
            
            for port in ssl_ports:
                try:
                    # Try to establish SSL connection
                    import ssl
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    future = asyncio.open_connection(target, port, ssl=context)
                    reader, writer = await asyncio.wait_for(future, timeout=5.0)
                    
                    # Get certificate info
                    peercert = writer.get_extra_info('peercert')
                    
                    open_ports.append({
                        'port': port,
                        'protocol': 'tcp',
                        'service': 'ssl/tls',
                        'ssl': True,
                        'certificate': bool(peercert)
                    })
                    
                    writer.close()
                    await writer.wait_closed()
                    
                except Exception:
                    continue
            
            return {
                'source': 'certificate_discovery',
                'status': 'success',
                'ports': [p['port'] for p in open_ports],
                'detailed_ports': open_ports,
                'count': len(open_ports)
            }
            
        except Exception as e:
            logger.error(f"Certificate port discovery failed: {e}")
            return {
                'source': 'certificate_discovery',
                'status': 'failed',
                'error': str(e),
                'ports': []
            }
    
    def _is_ip_address(self, address: str) -> bool:
        """Check if address is an IP address"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False