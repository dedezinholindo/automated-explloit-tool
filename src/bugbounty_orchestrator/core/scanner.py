"""
Core scanning engine for coordinating MCP tools
"""

import asyncio
import subprocess
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import httpx

from .config import config, platform_config

logger = logging.getLogger(__name__)

class MCPClient:
    """Client for communicating with MCP servers"""
    
    def __init__(self, tool_name: str, tool_path: str):
        self.tool_name = tool_name
        self.tool_path = Path(tool_path)
        self.process: Optional[subprocess.Popen] = None
        
    async def start(self) -> bool:
        """Start the MCP server"""
        try:
            if not self.tool_path.exists():
                logger.error(f"MCP tool path not found: {self.tool_path}")
                return False
                
            # Start the MCP server process
            self.process = subprocess.Popen(
                ["python", "-m", "mcp_server"],
                cwd=self.tool_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a moment for startup
            await asyncio.sleep(2)
            
            if self.process.poll() is None:
                logger.info(f"MCP server {self.tool_name} started successfully")
                return True
            else:
                logger.error(f"MCP server {self.tool_name} failed to start")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start MCP server {self.tool_name}: {e}")
            return False
    
    async def stop(self) -> None:
        """Stop the MCP server"""
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self._wait_for_process(), timeout=10)
            except asyncio.TimeoutError:
                self.process.kill()
            self.process = None
    
    async def _wait_for_process(self) -> None:
        """Wait for process to terminate"""
        while self.process and self.process.poll() is None:
            await asyncio.sleep(0.1)
    
    async def call_tool(self, tool_function: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Call a specific tool function via MCP"""
        try:
            # This is a simplified implementation
            # In a real implementation, you'd use the MCP protocol
            
            if not self.process or self.process.poll() is not None:
                raise RuntimeError(f"MCP server {self.tool_name} is not running")
            
            # For now, simulate tool execution
            # In practice, you'd send MCP messages to the server
            result = await self._simulate_tool_call(tool_function, parameters)
            return result
            
        except Exception as e:
            logger.error(f"Failed to call tool {tool_function} on {self.tool_name}: {e}")
            raise
    
    async def _simulate_tool_call(self, tool_function: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate tool call - replace with actual MCP communication"""
        # This is a placeholder - in real implementation, use MCP protocol
        
        if self.tool_name == "nuclei":
            return await self._simulate_nuclei_call(tool_function, parameters)
        elif self.tool_name == "httpx":
            return await self._simulate_httpx_call(tool_function, parameters)
        elif self.tool_name == "amass":
            return await self._simulate_amass_call(tool_function, parameters)
        elif self.tool_name == "nmap":
            return await self._simulate_nmap_call(tool_function, parameters)
        else:
            return {"status": "success", "data": {}, "tool": self.tool_name}
    
    async def _simulate_nuclei_call(self, function: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate Nuclei MCP call"""
        target = params.get("target", "")
        templates = params.get("templates", [])
        
        # Simulate nuclei execution
        cmd = [
            "nuclei",
            "-target", target,
            "-json",
            "-severity", "critical,high,medium,low,info"
        ]
        
        if templates:
            cmd.extend(["-templates", ",".join(templates)])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            results = []
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            
            return {
                "status": "success",
                "tool": "nuclei",
                "results": results,
                "total_findings": len(results)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "tool": "nuclei",
                "error": str(e),
                "results": []
            }
    
    async def _simulate_httpx_call(self, function: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate httpx MCP call"""
        targets = params.get("targets", [])
        
        cmd = ["httpx", "-json", "-title", "-tech-detect", "-status-code"]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                input="\n".join(targets),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            results = []
            for line in stdout.strip().split('\n'):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            
            return {
                "status": "success",
                "tool": "httpx",
                "results": results,
                "total_hosts": len(results)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "tool": "httpx", 
                "error": str(e),
                "results": []
            }
    
    async def _simulate_amass_call(self, function: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate Amass MCP call"""
        domain = params.get("domain", "")
        
        cmd = ["amass", "enum", "-d", domain, "-json"]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
            
            results = []
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Amass might output plain text sometimes
                        if '.' in line and line.strip():
                            results.append({"name": line.strip(), "domain": domain})
            
            return {
                "status": "success",
                "tool": "amass",
                "results": results,
                "total_subdomains": len(results)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "tool": "amass",
                "error": str(e),
                "results": []
            }
    
    async def _simulate_nmap_call(self, function: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate Nmap MCP call"""
        targets = params.get("targets", [])
        ports = params.get("ports", "1-1000")
        
        cmd = ["nmap", "-sS", "-T4", "-p", ports, "--open", "-oX", "-"] + targets
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            # Parse XML output (simplified)
            import xml.etree.ElementTree as ET
            
            try:
                root = ET.fromstring(stdout.decode())
                results = []
                
                for host in root.findall('host'):
                    host_data = {}
                    
                    # Get host address
                    address = host.find('address')
                    if address is not None:
                        host_data['ip'] = address.get('addr')
                    
                    # Get open ports
                    ports_elem = host.find('ports')
                    if ports_elem is not None:
                        open_ports = []
                        for port in ports_elem.findall('port'):
                            state = port.find('state')
                            if state is not None and state.get('state') == 'open':
                                port_info = {
                                    'port': port.get('portid'),
                                    'protocol': port.get('protocol'),
                                    'service': port.find('service').get('name') if port.find('service') is not None else 'unknown'
                                }
                                open_ports.append(port_info)
                        
                        host_data['ports'] = open_ports
                    
                    if host_data:
                        results.append(host_data)
                
                return {
                    "status": "success",
                    "tool": "nmap",
                    "results": results,
                    "total_hosts": len(results)
                }
                
            except ET.ParseError:
                return {
                    "status": "error",
                    "tool": "nmap",
                    "error": "Failed to parse XML output",
                    "results": []
                }
                
        except Exception as e:
            return {
                "status": "error",
                "tool": "nmap",
                "error": str(e),
                "results": []
            }

class ScanEngine:
    """Core scanning engine that manages MCP tools"""
    
    def __init__(self):
        self.mcp_clients: Dict[str, MCPClient] = {}
        self.active_scans: Dict[str, asyncio.Task] = {}
        
    async def initialize(self) -> None:
        """Initialize all enabled MCP tools"""
        logger.info("Initializing MCP tools...")
        
        mcp_tools = platform_config.get_mcp_tools()
        
        for tool_name, tool_config in mcp_tools.items():
            if tool_config.get('enabled', False):
                tool_path = tool_config.get('path', f'../{tool_name}-mcp')
                
                client = MCPClient(tool_name, tool_path)
                success = await client.start()
                
                if success:
                    self.mcp_clients[tool_name] = client
                    logger.info(f"Initialized MCP client for {tool_name}")
                else:
                    logger.warning(f"Failed to initialize MCP client for {tool_name}")
    
    async def shutdown(self) -> None:
        """Shutdown all MCP clients"""
        logger.info("Shutting down MCP clients...")
        
        for client in self.mcp_clients.values():
            await client.stop()
        
        self.mcp_clients.clear()
    
    async def run_tool(self, tool_name: str, function: str, 
                      parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Run a specific tool function"""
        
        if tool_name not in self.mcp_clients:
            raise ValueError(f"Tool {tool_name} not available")
        
        client = self.mcp_clients[tool_name]
        return await client.call_tool(function, parameters)
    
    async def run_parallel_tools(self, tool_calls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run multiple tools in parallel"""
        
        tasks = []
        tool_names = []
        
        for call in tool_calls:
            tool_name = call['tool']
            function = call['function']
            parameters = call['parameters']
            
            if tool_name in self.mcp_clients:
                task = self.run_tool(tool_name, function, parameters)
                tasks.append(task)
                tool_names.append(tool_name)
        
        if not tasks:
            return {"status": "error", "message": "No valid tools found"}
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            combined_results = {}
            for i, result in enumerate(results):
                tool_name = tool_names[i]
                if isinstance(result, Exception):
                    combined_results[tool_name] = {
                        "status": "error",
                        "error": str(result)
                    }
                else:
                    combined_results[tool_name] = result
            
            return {
                "status": "success",
                "results": combined_results
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to run parallel tools: {e}"
            }
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        return list(self.mcp_clients.keys())
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        return tool_name in self.mcp_clients