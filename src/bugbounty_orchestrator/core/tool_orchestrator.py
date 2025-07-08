"""
Tool orchestration system for managing and coordinating security tools
"""

import asyncio
import logging
import subprocess
import signal
import time
import psutil
import os
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import resource
import json

from .config_manager import config_manager, ToolConfig

logger = logging.getLogger(__name__)

@dataclass
class ToolExecution:
    """Represents a tool execution instance"""
    tool_name: str
    command: List[str]
    started_at: datetime
    process_id: Optional[int] = None
    status: str = "running"  # running, completed, failed, timeout, cancelled
    output: str = ""
    error: str = ""
    return_code: Optional[int] = None
    duration: Optional[float] = None
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None

class ResourceMonitor:
    """Monitor system resources during tool execution"""
    
    def __init__(self):
        self.monitoring = False
        self.data_points: List[Dict[str, Any]] = []
    
    async def start_monitoring(self, process_id: int, interval: float = 1.0):
        """Start monitoring a process"""
        self.monitoring = True
        self.data_points = []
        
        try:
            process = psutil.Process(process_id)
            
            while self.monitoring and process.is_running():
                try:
                    # Get process stats
                    memory_info = process.memory_info()
                    cpu_percent = process.cpu_percent()
                    
                    # Get children processes
                    children = process.children(recursive=True)
                    total_memory = memory_info.rss
                    total_cpu = cpu_percent
                    
                    for child in children:
                        try:
                            child_memory = child.memory_info()
                            child_cpu = child.cpu_percent()
                            total_memory += child_memory.rss
                            total_cpu += child_cpu
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    self.data_points.append({
                        'timestamp': datetime.now(),
                        'memory_mb': total_memory / 1024 / 1024,
                        'cpu_percent': total_cpu,
                        'process_count': len(children) + 1
                    })
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
                
                await asyncio.sleep(interval)
                
        except Exception as e:
            logger.error(f"Error monitoring process {process_id}: {e}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
    
    def get_peak_usage(self) -> Dict[str, float]:
        """Get peak resource usage"""
        if not self.data_points:
            return {'memory_mb': 0, 'cpu_percent': 0}
        
        peak_memory = max(point['memory_mb'] for point in self.data_points)
        peak_cpu = max(point['cpu_percent'] for point in self.data_points)
        
        return {
            'memory_mb': peak_memory,
            'cpu_percent': peak_cpu,
            'avg_memory_mb': sum(p['memory_mb'] for p in self.data_points) / len(self.data_points),
            'avg_cpu_percent': sum(p['cpu_percent'] for p in self.data_points) / len(self.data_points)
        }

class RateLimiter:
    """Rate limiting for tool execution"""
    
    def __init__(self):
        self.tool_limits: Dict[str, Dict[str, Any]] = {}
        self.global_limit = None
        self.request_history: List[datetime] = []
    
    def set_tool_limit(self, tool_name: str, requests_per_second: float):
        """Set rate limit for specific tool"""
        self.tool_limits[tool_name] = {
            'rps': requests_per_second,
            'last_requests': []
        }
    
    def set_global_limit(self, requests_per_second: float):
        """Set global rate limit"""
        self.global_limit = requests_per_second
    
    async def acquire(self, tool_name: str) -> bool:
        """Acquire permission to execute tool"""
        now = datetime.now()
        
        # Check global limit
        if self.global_limit:
            # Clean old requests
            cutoff = now - timedelta(seconds=1)
            self.request_history = [req for req in self.request_history if req > cutoff]
            
            if len(self.request_history) >= self.global_limit:
                return False
        
        # Check tool-specific limit
        if tool_name in self.tool_limits:
            limit_info = self.tool_limits[tool_name]
            cutoff = now - timedelta(seconds=1)
            limit_info['last_requests'] = [req for req in limit_info['last_requests'] if req > cutoff]
            
            if len(limit_info['last_requests']) >= limit_info['rps']:
                return False
        
        # Record request
        if self.global_limit:
            self.request_history.append(now)
        
        if tool_name in self.tool_limits:
            self.tool_limits[tool_name]['last_requests'].append(now)
        
        return True
    
    async def wait_for_slot(self, tool_name: str, timeout: float = 30.0):
        """Wait for available slot to execute tool"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if await self.acquire(tool_name):
                return True
            
            await asyncio.sleep(0.1)
        
        return False

class ToolOrchestrator:
    """Main tool orchestration system"""
    
    def __init__(self, max_concurrent_tools: int = 5):
        self.max_concurrent_tools = max_concurrent_tools
        self.active_executions: Dict[str, ToolExecution] = {}
        self.execution_history: List[ToolExecution] = []
        self.rate_limiter = RateLimiter()
        self.resource_monitors: Dict[str, ResourceMonitor] = {}
        
        # Thread pool for CPU-bound operations
        self.thread_pool = ThreadPoolExecutor(max_workers=max_concurrent_tools)
        
        # Statistics
        self.stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'timeout_executions': 0,
            'cancelled_executions': 0,
            'total_execution_time': 0.0
        }
        
        # Initialize rate limits from configuration
        self._setup_rate_limits()
    
    def _setup_rate_limits(self):
        """Setup rate limits from configuration"""
        main_config = config_manager.get_config('main')
        rate_limiting = main_config.get('scanning', {}).get('rate_limiting', {})
        
        if rate_limiting.get('enabled', True):
            global_rps = rate_limiting.get('requests_per_second', 10)
            self.rate_limiter.set_global_limit(global_rps)
        
        # Tool-specific rate limits
        tools = config_manager.get_config('tools')
        for tool_name, tool_config in tools.items():
            if hasattr(tool_config, 'rate_limit') and tool_config.rate_limit:
                self.rate_limiter.set_tool_limit(tool_name, tool_config.rate_limit / 60.0)  # Convert per minute to per second
    
    async def execute_tool(self, 
                          tool_name: str, 
                          target: str, 
                          args: Dict[str, Any] = None,
                          timeout: Optional[int] = None,
                          callback: Optional[Callable] = None) -> ToolExecution:
        """Execute a security tool"""
        
        # Check concurrent execution limit
        if len(self.active_executions) >= self.max_concurrent_tools:
            raise RuntimeError(f"Maximum concurrent tools limit reached ({self.max_concurrent_tools})")
        
        # Get tool configuration
        tool_config = config_manager.get_tool_config(tool_name)
        if not tool_config:
            raise ValueError(f"Tool {tool_name} not configured")
        
        if not tool_config.enabled:
            raise ValueError(f"Tool {tool_name} is disabled")
        
        # Wait for rate limit slot
        if not await self.rate_limiter.wait_for_slot(tool_name):
            raise RuntimeError(f"Rate limit timeout for tool {tool_name}")
        
        # Prepare command
        command = self._build_command(tool_config, target, args or {})
        
        # Create execution instance
        execution_id = f"{tool_name}_{int(time.time())}"
        execution = ToolExecution(
            tool_name=tool_name,
            command=command,
            started_at=datetime.now()
        )
        
        self.active_executions[execution_id] = execution
        
        try:
            # Set resource limits
            resource_limits = self._get_resource_limits(tool_config)
            
            # Execute tool
            await self._run_tool_process(execution, timeout or tool_config.timeout, resource_limits)
            
            # Process results
            if callback:
                await callback(execution)
            
            # Update statistics
            self._update_stats(execution)
            
            return execution
            
        except Exception as e:
            logger.error(f"Tool execution failed for {tool_name}: {e}")
            execution.status = "failed"
            execution.error = str(e)
            return execution
            
        finally:
            # Clean up
            if execution_id in self.active_executions:
                del self.active_executions[execution_id]
            
            self.execution_history.append(execution)
            
            # Keep history limited
            if len(self.execution_history) > 1000:
                self.execution_history = self.execution_history[-500:]
    
    def _build_command(self, tool_config: ToolConfig, target: str, args: Dict[str, Any]) -> List[str]:
        """Build command line for tool execution"""
        command = [tool_config.path or tool_config.name]
        
        # Add target
        if tool_config.name == "subfinder":
            command.extend(["-d", target])
        elif tool_config.name == "nuclei":
            command.extend(["-u", target])
        elif tool_config.name == "httpx":
            command.extend(["-l", "-"])  # Read from stdin
        elif tool_config.name == "katana":
            command.extend(["-u", target])
        elif tool_config.name == "nmap":
            command.append(target)
        else:
            command.append(target)
        
        # Add tool-specific arguments from config
        tool_args = tool_config.args or {}
        for key, value in tool_args.items():
            if isinstance(value, bool):
                if value:
                    command.append(f"-{key}")
            elif isinstance(value, list):
                for item in value:
                    command.extend([f"-{key}", str(item)])
            else:
                command.extend([f"-{key}", str(value)])
        
        # Add runtime arguments
        for key, value in args.items():
            if isinstance(value, bool):
                if value:
                    command.append(f"-{key}")
            elif isinstance(value, list):
                for item in value:
                    command.extend([f"-{key}", str(item)])
            else:
                command.extend([f"-{key}", str(value)])
        
        return command
    
    def _get_resource_limits(self, tool_config: ToolConfig) -> Dict[str, int]:
        """Get resource limits for tool execution"""
        main_config = config_manager.get_config('main')
        resource_limits = main_config.get('scanning', {}).get('resource_limits', {})
        
        return {
            'max_memory_mb': resource_limits.get('max_memory_mb', 2048),
            'max_cpu_percent': resource_limits.get('max_cpu_percent', 80)
        }
    
    async def _run_tool_process(self, execution: ToolExecution, timeout: Optional[int], resource_limits: Dict[str, int]):
        """Run tool process with monitoring"""
        
        def set_resource_limits():
            """Set resource limits for the process"""
            try:
                # Set memory limit (in bytes)
                max_memory = resource_limits['max_memory_mb'] * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (max_memory, max_memory))
            except Exception as e:
                logger.warning(f"Failed to set memory limit: {e}")
        
        try:
            # Start process
            env = dict(os.environ)
            tool_config = config_manager.get_tool_config(execution.tool_name)
            if tool_config and tool_config.environment:
                env.update(tool_config.environment)
            
            process = await asyncio.create_subprocess_exec(
                *execution.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                preexec_fn=set_resource_limits
            )
            
            execution.process_id = process.pid
            
            # Start resource monitoring
            monitor = ResourceMonitor()
            self.resource_monitors[str(process.pid)] = monitor
            monitor_task = asyncio.create_task(monitor.start_monitoring(process.pid))
            
            try:
                # Wait for completion with timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                execution.output = stdout.decode('utf-8', errors='replace')
                execution.error = stderr.decode('utf-8', errors='replace')
                execution.return_code = process.returncode
                execution.status = "completed" if process.returncode == 0 else "failed"
                
            except asyncio.TimeoutError:
                # Handle timeout
                logger.warning(f"Tool {execution.tool_name} timed out after {timeout} seconds")
                
                # Kill process tree
                try:
                    parent = psutil.Process(process.pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                    parent.kill()
                except psutil.NoSuchProcess:
                    pass
                
                execution.status = "timeout"
                execution.error = f"Process timed out after {timeout} seconds"
                
            finally:
                # Stop monitoring
                monitor.stop_monitoring()
                monitor_task.cancel()
                
                # Get resource usage
                usage = monitor.get_peak_usage()
                execution.memory_usage = usage.get('memory_mb', 0)
                execution.cpu_usage = usage.get('cpu_percent', 0)
                
                # Calculate duration
                execution.duration = (datetime.now() - execution.started_at).total_seconds()
                
                # Clean up monitor
                if str(process.pid) in self.resource_monitors:
                    del self.resource_monitors[str(process.pid)]
                
        except Exception as e:
            execution.status = "failed"
            execution.error = str(e)
            logger.error(f"Process execution failed: {e}")
    
    def _update_stats(self, execution: ToolExecution):
        """Update execution statistics"""
        self.stats['total_executions'] += 1
        
        if execution.status == "completed":
            self.stats['successful_executions'] += 1
        elif execution.status == "failed":
            self.stats['failed_executions'] += 1
        elif execution.status == "timeout":
            self.stats['timeout_executions'] += 1
        elif execution.status == "cancelled":
            self.stats['cancelled_executions'] += 1
        
        if execution.duration:
            self.stats['total_execution_time'] += execution.duration
    
    async def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a running tool execution"""
        if execution_id not in self.active_executions:
            return False
        
        execution = self.active_executions[execution_id]
        
        if execution.process_id:
            try:
                # Kill process tree
                parent = psutil.Process(execution.process_id)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
                
                execution.status = "cancelled"
                return True
                
            except psutil.NoSuchProcess:
                return False
        
        return False
    
    async def execute_parallel_tools(self, 
                                   tool_configs: List[Dict[str, Any]], 
                                   target: str,
                                   max_parallel: int = None) -> List[ToolExecution]:
        """Execute multiple tools in parallel"""
        
        max_parallel = max_parallel or min(len(tool_configs), self.max_concurrent_tools)
        semaphore = asyncio.Semaphore(max_parallel)
        
        async def execute_with_semaphore(tool_config):
            async with semaphore:
                return await self.execute_tool(
                    tool_config['name'],
                    target,
                    tool_config.get('args', {}),
                    tool_config.get('timeout')
                )
        
        # Execute all tools
        tasks = [execute_with_semaphore(config) for config in tool_configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        executions = []
        for result in results:
            if isinstance(result, ToolExecution):
                executions.append(result)
            else:
                logger.error(f"Parallel execution failed: {result}")
        
        return executions
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        return {
            **self.stats,
            'active_executions': len(self.active_executions),
            'avg_execution_time': (
                self.stats['total_execution_time'] / self.stats['total_executions']
                if self.stats['total_executions'] > 0 else 0
            ),
            'success_rate': (
                self.stats['successful_executions'] / self.stats['total_executions'] * 100
                if self.stats['total_executions'] > 0 else 0
            )
        }
    
    def get_active_executions(self) -> List[Dict[str, Any]]:
        """Get information about active executions"""
        active = []
        for execution_id, execution in self.active_executions.items():
            runtime = (datetime.now() - execution.started_at).total_seconds()
            
            active.append({
                'id': execution_id,
                'tool_name': execution.tool_name,
                'status': execution.status,
                'runtime_seconds': runtime,
                'process_id': execution.process_id,
                'memory_usage_mb': execution.memory_usage or 0
            })
        
        return active
    
    def get_tool_performance(self, tool_name: str) -> Dict[str, Any]:
        """Get performance metrics for a specific tool"""
        tool_executions = [
            exec for exec in self.execution_history 
            if exec.tool_name == tool_name
        ]
        
        if not tool_executions:
            return {}
        
        successful = [e for e in tool_executions if e.status == "completed"]
        failed = [e for e in tool_executions if e.status == "failed"]
        
        durations = [e.duration for e in tool_executions if e.duration]
        memory_usages = [e.memory_usage for e in tool_executions if e.memory_usage]
        
        return {
            'total_executions': len(tool_executions),
            'successful_executions': len(successful),
            'failed_executions': len(failed),
            'success_rate': len(successful) / len(tool_executions) * 100,
            'avg_duration': sum(durations) / len(durations) if durations else 0,
            'avg_memory_usage_mb': sum(memory_usages) / len(memory_usages) if memory_usages else 0,
            'last_execution': tool_executions[-1].started_at.isoformat() if tool_executions else None
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on tool orchestration system"""
        results = {
            'status': 'healthy',
            'active_executions': len(self.active_executions),
            'max_concurrent': self.max_concurrent_tools,
            'utilization_percent': len(self.active_executions) / self.max_concurrent_tools * 100,
            'stats': self.get_execution_stats(),
            'issues': []
        }
        
        # Check for stuck processes
        stuck_threshold = 3600  # 1 hour
        current_time = datetime.now()
        
        for execution_id, execution in self.active_executions.items():
            runtime = (current_time - execution.started_at).total_seconds()
            if runtime > stuck_threshold:
                results['issues'].append(f"Process {execution_id} has been running for {runtime:.0f} seconds")
        
        # Check system resources
        try:
            memory = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=1)
            
            if memory.percent > 90:
                results['issues'].append(f"High memory usage: {memory.percent:.1f}%")
            
            if cpu > 90:
                results['issues'].append(f"High CPU usage: {cpu:.1f}%")
            
            results['system'] = {
                'memory_percent': memory.percent,
                'cpu_percent': cpu
            }
            
        except Exception as e:
            results['issues'].append(f"Failed to get system stats: {e}")
        
        if results['issues']:
            results['status'] = 'degraded' if len(results['issues']) < 3 else 'unhealthy'
        
        return results
    
    async def cleanup(self):
        """Cleanup resources"""
        # Cancel all active executions
        for execution_id in list(self.active_executions.keys()):
            await self.cancel_execution(execution_id)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        logger.info("Tool orchestrator cleanup completed")

# Global tool orchestrator instance
tool_orchestrator = ToolOrchestrator()