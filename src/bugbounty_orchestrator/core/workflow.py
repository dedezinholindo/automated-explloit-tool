"""
Workflow engine for orchestrating complex scanning workflows
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field

from .config import platform_config
from .scanner import ScanEngine

logger = logging.getLogger(__name__)

@dataclass
class WorkflowStep:
    """Represents a single step in a workflow"""
    name: str
    function: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    timeout: int = 300
    retry_count: int = 1
    continue_on_error: bool = True
    parallel: bool = False

@dataclass
class WorkflowResult:
    """Result of a workflow execution"""
    workflow_name: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    steps_completed: int = 0
    total_steps: int = 0
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

class WorkflowEngine:
    """Engine for executing complex multi-step workflows"""
    
    def __init__(self, scan_engine: Optional[ScanEngine] = None):
        self.scan_engine = scan_engine or ScanEngine()
        self.workflows: Dict[str, List[WorkflowStep]] = {}
        self.step_functions: Dict[str, Callable] = {}
        self.active_workflows: Dict[str, WorkflowResult] = {}
        
        # Load workflows from configuration
        self._load_workflows()
        
        # Register built-in step functions
        self._register_step_functions()
    
    def _load_workflows(self) -> None:
        """Load workflow definitions from configuration"""
        workflows_config = platform_config.get_workflows()
        
        for workflow_name, workflow_config in workflows_config.items():
            steps = workflow_config.get('steps', [])
            workflow_steps = []
            
            for step_name in steps:
                # Create workflow step from configuration
                step = WorkflowStep(
                    name=step_name,
                    function=step_name  # Default function name same as step name
                )
                workflow_steps.append(step)
            
            self.workflows[workflow_name] = workflow_steps
            logger.info(f"Loaded workflow '{workflow_name}' with {len(workflow_steps)} steps")
    
    def _register_step_functions(self) -> None:
        """Register step functions that can be called in workflows"""
        
        # Import modules here to avoid circular imports
        from ..modules.subdomain_discovery import SubdomainDiscovery
        from ..modules.port_scanner import PortScanner
        from ..modules.web_crawler import WebCrawler
        from ..modules.vulnerability_scanner import VulnerabilityScanner
        from ..modules.modern_tools import ModernToolsIntegrator
        
        # Initialize module instances
        subdomain_discovery = SubdomainDiscovery()
        port_scanner = PortScanner()
        web_crawler = WebCrawler()
        vulnerability_scanner = VulnerabilityScanner()
        modern_tools = ModernToolsIntegrator()
        
        # Register step functions
        self.step_functions.update({
            'subdomain_discovery': subdomain_discovery.run_discovery,
            'passive_subdomain_discovery': subdomain_discovery.run_passive_discovery,
            'basic_subdomain_discovery': subdomain_discovery.run_basic_discovery,
            'certificate_transparency': subdomain_discovery.cert_transparency_search,
            
            'port_scanning': port_scanner.scan_ports,
            'passive_port_discovery': port_scanner.passive_scan,
            
            'web_crawling': web_crawler.crawl_target,
            'http_probing': web_crawler.http_probe,
            
            'vulnerability_scanning': vulnerability_scanner.scan_vulnerabilities,
            'basic_vulnerability_scanning': vulnerability_scanner.basic_scan,
            'exploitation_testing': vulnerability_scanner.exploitation_scan,
            
            'historical_data_analysis': modern_tools.run_historical_analysis,
        })
    
    async def execute_workflow(self, workflow_name: str, target: str, 
                             options: Dict[str, Any] = None) -> WorkflowResult:
        """Execute a complete workflow"""
        
        if workflow_name not in self.workflows:
            raise ValueError(f"Unknown workflow: {workflow_name}")
        
        options = options or {}
        workflow_steps = self.workflows[workflow_name]
        
        # Create workflow result tracker
        result = WorkflowResult(
            workflow_name=workflow_name,
            status="running",
            started_at=datetime.now(),
            total_steps=len(workflow_steps)
        )
        
        # Store active workflow
        workflow_id = f"{workflow_name}_{target}_{datetime.now().timestamp()}"
        self.active_workflows[workflow_id] = result
        
        try:
            logger.info(f"Starting workflow '{workflow_name}' for target: {target}")
            
            # Execute workflow steps
            for step in workflow_steps:
                try:
                    logger.info(f"Executing step: {step.name}")
                    
                    # Check dependencies
                    if not self._check_dependencies(step, result.results):
                        logger.warning(f"Skipping step {step.name} - dependencies not met")
                        continue
                    
                    # Execute step with retry logic
                    step_result = await self._execute_step_with_retry(
                        step, target, options, result.results
                    )
                    
                    # Store step result
                    result.results[step.name] = step_result
                    result.steps_completed += 1
                    
                    logger.info(f"Completed step: {step.name}")
                    
                except Exception as e:
                    error_msg = f"Error in step {step.name}: {str(e)}"
                    logger.error(error_msg)
                    result.errors.append(error_msg)
                    
                    if not step.continue_on_error:
                        logger.error(f"Workflow failed on step {step.name}")
                        result.status = "failed"
                        break
            
            # Mark workflow as completed if no critical errors
            if result.status == "running":
                result.status = "completed"
            
            result.completed_at = datetime.now()
            
            logger.info(f"Workflow '{workflow_name}' completed with status: {result.status}")
            
        except Exception as e:
            error_msg = f"Workflow execution failed: {str(e)}"
            logger.error(error_msg)
            result.errors.append(error_msg)
            result.status = "failed"
            result.completed_at = datetime.now()
        
        finally:
            # Remove from active workflows
            if workflow_id in self.active_workflows:
                del self.active_workflows[workflow_id]
        
        return result
    
    async def _execute_step_with_retry(self, step: WorkflowStep, target: str,
                                     options: Dict[str, Any], 
                                     previous_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a workflow step with retry logic"""
        
        for attempt in range(step.retry_count):
            try:
                # Prepare step parameters
                step_params = {
                    'target': target,
                    'options': {**options, **step.parameters},
                    'previous_results': previous_results
                }
                
                # Execute step function
                if step.function in self.step_functions:
                    step_func = self.step_functions[step.function]
                    
                    # Execute with timeout
                    step_result = await asyncio.wait_for(
                        step_func(target, step_params['options']),
                        timeout=step.timeout
                    )
                    
                    return {
                        'status': 'success',
                        'data': step_result,
                        'attempt': attempt + 1
                    }
                else:
                    raise ValueError(f"Unknown step function: {step.function}")
                    
            except asyncio.TimeoutError:
                if attempt < step.retry_count - 1:
                    logger.warning(f"Step {step.name} timed out, retrying...")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise asyncio.TimeoutError(f"Step {step.name} timed out after {step.retry_count} attempts")
                    
            except Exception as e:
                if attempt < step.retry_count - 1:
                    logger.warning(f"Step {step.name} failed, retrying: {e}")
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise
        
        # Should not reach here
        raise RuntimeError(f"Step {step.name} failed after all retry attempts")
    
    def _check_dependencies(self, step: WorkflowStep, 
                          previous_results: Dict[str, Any]) -> bool:
        """Check if step dependencies are satisfied"""
        
        for dependency in step.dependencies:
            if dependency not in previous_results:
                return False
            
            # Check if dependency completed successfully
            dep_result = previous_results[dependency]
            if isinstance(dep_result, dict) and dep_result.get('status') != 'success':
                return False
        
        return True
    
    def add_workflow(self, name: str, steps: List[WorkflowStep]) -> None:
        """Add a new workflow definition"""
        self.workflows[name] = steps
        logger.info(f"Added workflow '{name}' with {len(steps)} steps")
    
    def get_workflow_names(self) -> List[str]:
        """Get list of available workflow names"""
        return list(self.workflows.keys())
    
    def get_workflow_steps(self, workflow_name: str) -> List[WorkflowStep]:
        """Get steps for a specific workflow"""
        return self.workflows.get(workflow_name, [])
    
    def add_step_function(self, name: str, function: Callable) -> None:
        """Add a custom step function"""
        self.step_functions[name] = function
        logger.info(f"Registered step function: {name}")
    
    def get_active_workflows(self) -> Dict[str, WorkflowResult]:
        """Get currently active workflows"""
        return self.active_workflows.copy()
    
    async def cancel_workflow(self, workflow_id: str) -> bool:
        """Cancel an active workflow"""
        if workflow_id in self.active_workflows:
            self.active_workflows[workflow_id].status = "cancelled"
            # In a more complex implementation, you'd also cancel running tasks
            logger.info(f"Cancelled workflow: {workflow_id}")
            return True
        return False
    
    def create_custom_workflow(self, name: str, step_configs: List[Dict[str, Any]]) -> None:
        """Create a custom workflow from configuration"""
        
        steps = []
        for step_config in step_configs:
            step = WorkflowStep(
                name=step_config['name'],
                function=step_config['function'],
                parameters=step_config.get('parameters', {}),
                dependencies=step_config.get('dependencies', []),
                timeout=step_config.get('timeout', 300),
                retry_count=step_config.get('retry_count', 1),
                continue_on_error=step_config.get('continue_on_error', True),
                parallel=step_config.get('parallel', False)
            )
            steps.append(step)
        
        self.add_workflow(name, steps)
    
    async def execute_parallel_workflow(self, workflow_name: str, targets: List[str],
                                      options: Dict[str, Any] = None) -> List[WorkflowResult]:
        """Execute a workflow against multiple targets in parallel"""
        
        tasks = []
        for target in targets:
            task = self.execute_workflow(workflow_name, target, options)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Workflow failed for target {targets[i]}: {result}")
                # Create a failed result
                failed_result = WorkflowResult(
                    workflow_name=workflow_name,
                    status="failed",
                    started_at=datetime.now(),
                    completed_at=datetime.now()
                )
                failed_result.errors.append(str(result))
                valid_results.append(failed_result)
            else:
                valid_results.append(result)
        
        return valid_results