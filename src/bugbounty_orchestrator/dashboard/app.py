"""
FastAPI web dashboard for Bug Bounty Orchestrator
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ..core.orchestrator import BugBountyOrchestrator
from ..core.config import config

logger = logging.getLogger(__name__)

# Pydantic models for API
class ScanRequest(BaseModel):
    target: str
    workflow: str = "comprehensive_scan"
    options: Dict[str, Any] = {}

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

# Global orchestrator instance
orchestrator: Optional[BugBountyOrchestrator] = None

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Connection closed, remove it
                self.active_connections.remove(connection)

manager = ConnectionManager()

# Create FastAPI app
app = FastAPI(
    title="Bug Bounty Orchestrator Dashboard",
    description="Web interface for managing bug bounty scanning operations",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize the orchestrator on startup"""
    global orchestrator
    orchestrator = BugBountyOrchestrator()
    await orchestrator.initialize()
    logger.info("Dashboard started and orchestrator initialized")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global orchestrator
    if orchestrator:
        await orchestrator.shutdown()
    logger.info("Dashboard shutdown complete")

# API Routes

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the main dashboard page"""
    return get_dashboard_html()

@app.get("/api/status")
async def get_system_status():
    """Get system status"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    status = orchestrator.get_system_status()
    return JSONResponse(content=status)

@app.get("/api/tools")
async def get_available_tools():
    """Get list of available tools"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    tools = orchestrator.get_available_tools()
    return JSONResponse(content={"tools": tools})

@app.get("/api/workflows")
async def get_available_workflows():
    """Get list of available workflows"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    workflows = orchestrator.get_available_workflows()
    return JSONResponse(content={"workflows": workflows})

@app.post("/api/scans", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest):
    """Start a new scan"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    try:
        scan_id = await orchestrator.start_scan(
            scan_request.target,
            scan_request.workflow,
            scan_request.options
        )
        
        # Broadcast scan started event
        await manager.broadcast(f"scan_started:{scan_id}:{scan_request.target}")
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Scan started for {scan_request.target}"
        )
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/scans")
async def list_scans(status: Optional[str] = None, limit: int = 20):
    """List scans with optional filtering"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    scans = await orchestrator.list_scans(status)
    # Sort by created_at descending and limit
    scans.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    return JSONResponse(content={"scans": scans[:limit]})

@app.get("/api/scans/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get detailed status of a specific scan"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    scan_status = await orchestrator.get_scan_status(scan_id)
    
    if not scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return JSONResponse(content=scan_status)

@app.delete("/api/scans/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    success = await orchestrator.cancel_scan(scan_id)
    
    if success:
        await manager.broadcast(f"scan_cancelled:{scan_id}")
        return JSONResponse(content={"message": "Scan cancelled successfully"})
    else:
        raise HTTPException(status_code=404, detail="Scan not found or not cancellable")

@app.post("/api/test-tool/{tool_name}")
async def test_tool(tool_name: str, target: str):
    """Test a specific tool"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    result = await orchestrator.test_tool(tool_name, target)
    return JSONResponse(content=result)

@app.get("/api/scope-check/{target}")
async def check_scope(target: str):
    """Check if target is in scope for bug bounty programs"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    
    scope_results = await orchestrator.check_target_scope(target)
    return JSONResponse(content=scope_results)

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # Echo back for now (could handle commands later)
            await manager.send_personal_message(f"Echo: {data}", websocket)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Static files (for CSS, JS, etc.)
# app.mount("/static", StaticFiles(directory="static"), name="static")

def get_dashboard_html() -> str:
    """Get the dashboard HTML content"""
    
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Orchestrator Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            font-weight: 300;
        }
        
        .header p {
            opacity: 0.9;
            margin-top: 5px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .card:hover {
            transform: translateY(-2px);
        }
        
        .card h2 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        
        .scan-form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .form-group {
            display: flex;
            flex-direction: column;
        }
        
        .form-group label {
            margin-bottom: 5px;
            font-weight: 500;
            color: #555;
        }
        
        .form-group input,
        .form-group select {
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.2s;
        }
        
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: opacity 0.2s;
        }
        
        .btn:hover {
            opacity: 0.9;
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
        }
        
        .status-item {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .status-item .number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        
        .status-item .label {
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }
        
        .scans-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .scans-table th,
        .scans-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        .scans-table th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #555;
        }
        
        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 500;
        }
        
        .status-running {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .status-completed {
            background-color: #d4edda;
            color: #155724;
        }
        
        .status-failed {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .log-container {
            background: #1e1e1e;
            color: #00ff00;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            height: 200px;
            overflow-y: auto;
            margin-top: 15px;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .status-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>🎯 Bug Bounty Orchestrator</h1>
            <p>Comprehensive automated security testing platform</p>
        </div>
    </div>
    
    <div class="container">
        <div class="dashboard-grid">
            <!-- Start New Scan -->
            <div class="card">
                <h2>🚀 Start New Scan</h2>
                <form class="scan-form" id="scanForm">
                    <div class="form-group">
                        <label for="target">Target Domain/URL</label>
                        <input type="text" id="target" placeholder="example.com or https://example.com" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="workflow">Workflow</label>
                        <select id="workflow">
                            <option value="comprehensive_scan">Comprehensive Scan</option>
                            <option value="passive_recon">Passive Reconnaissance</option>
                            <option value="quick_scan">Quick Scan</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn" id="startScanBtn">Start Scan</button>
                </form>
            </div>
            
            <!-- System Status -->
            <div class="card">
                <h2>📊 System Status</h2>
                <div class="status-grid" id="statusGrid">
                    <div class="loading">Loading status...</div>
                </div>
            </div>
        </div>
        
        <!-- Recent Scans -->
        <div class="card">
            <h2>📋 Recent Scans</h2>
            <table class="scans-table">
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Workflow</th>
                        <th>Status</th>
                        <th>Started</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="scansTableBody">
                    <tr>
                        <td colspan="5" class="loading">Loading scans...</td>
                    </tr>
                </tbody>
            </table>
        </div>
        
        <!-- Live Log -->
        <div class="card">
            <h2>📺 Live Updates</h2>
            <div class="log-container" id="liveLog">
                <div>Connecting to live updates...</div>
            </div>
        </div>
    </div>
    
    <script>
        // WebSocket connection for live updates
        let ws = null;
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
            
            ws.onopen = function() {
                addLogMessage('Connected to live updates');
            };
            
            ws.onmessage = function(event) {
                addLogMessage(event.data);
            };
            
            ws.onclose = function() {
                addLogMessage('Disconnected from live updates');
                // Reconnect after 5 seconds
                setTimeout(connectWebSocket, 5000);
            };
        }
        
        function addLogMessage(message) {
            const logContainer = document.getElementById('liveLog');
            const timestamp = new Date().toLocaleTimeString();
            logContainer.innerHTML += `<div>[${timestamp}] ${message}</div>`;
            logContainer.scrollTop = logContainer.scrollHeight;
        }
        
        // Load system status
        async function loadSystemStatus() {
            try {
                const response = await fetch('/api/status');
                const status = await response.json();
                
                const statusGrid = document.getElementById('statusGrid');
                statusGrid.innerHTML = `
                    <div class="status-item">
                        <div class="number">${status.active_scans}</div>
                        <div class="label">Active Scans</div>
                    </div>
                    <div class="status-item">
                        <div class="number">${status.total_scans_completed}</div>
                        <div class="label">Completed</div>
                    </div>
                    <div class="status-item">
                        <div class="number">${status.available_tools}</div>
                        <div class="label">Tools</div>
                    </div>
                    <div class="status-item">
                        <div class="number">${status.available_workflows}</div>
                        <div class="label">Workflows</div>
                    </div>
                `;
            } catch (error) {
                console.error('Failed to load system status:', error);
            }
        }
        
        // Load recent scans
        async function loadRecentScans() {
            try {
                const response = await fetch('/api/scans?limit=10');
                const data = await response.json();
                
                const tbody = document.getElementById('scansTableBody');
                
                if (data.scans.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="loading">No scans found</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.scans.map(scan => {
                    const startedAt = new Date(scan.started_at || scan.created_at).toLocaleString();
                    const statusClass = `status-${scan.status}`;
                    
                    return `
                        <tr>
                            <td>${scan.target}</td>
                            <td>${scan.workflow}</td>
                            <td><span class="status-badge ${statusClass}">${scan.status}</span></td>
                            <td>${startedAt}</td>
                            <td>
                                <button onclick="viewScan('${scan.id}')" class="btn" style="padding: 5px 10px; font-size: 12px;">View</button>
                                ${scan.status === 'running' ? `<button onclick="cancelScan('${scan.id}')" class="btn" style="padding: 5px 10px; font-size: 12px; background: #dc3545;">Cancel</button>` : ''}
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (error) {
                console.error('Failed to load recent scans:', error);
            }
        }
        
        // Start new scan
        document.getElementById('scanForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const target = document.getElementById('target').value;
            const workflow = document.getElementById('workflow').value;
            const startBtn = document.getElementById('startScanBtn');
            
            startBtn.disabled = true;
            startBtn.textContent = 'Starting...';
            
            try {
                const response = await fetch('/api/scans', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target: target,
                        workflow: workflow,
                        options: {}
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    addLogMessage(`Scan started for ${target} (ID: ${result.scan_id})`);
                    document.getElementById('target').value = '';
                    
                    // Reload scans and status
                    setTimeout(() => {
                        loadRecentScans();
                        loadSystemStatus();
                    }, 1000);
                } else {
                    const error = await response.json();
                    addLogMessage(`Failed to start scan: ${error.detail}`);
                }
            } catch (error) {
                addLogMessage(`Error starting scan: ${error.message}`);
            } finally {
                startBtn.disabled = false;
                startBtn.textContent = 'Start Scan';
            }
        });
        
        // View scan details
        function viewScan(scanId) {
            // In a real implementation, this would open a detailed view
            addLogMessage(`Viewing scan details for ${scanId}`);
        }
        
        // Cancel scan
        async function cancelScan(scanId) {
            try {
                const response = await fetch(`/api/scans/${scanId}`, {
                    method: 'DELETE'
                });
                
                if (response.ok) {
                    addLogMessage(`Scan ${scanId} cancelled`);
                    loadRecentScans();
                    loadSystemStatus();
                } else {
                    const error = await response.json();
                    addLogMessage(`Failed to cancel scan: ${error.detail}`);
                }
            } catch (error) {
                addLogMessage(`Error cancelling scan: ${error.message}`);
            }
        }
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            connectWebSocket();
            loadSystemStatus();
            loadRecentScans();
            
            // Refresh data every 30 seconds
            setInterval(() => {
                loadSystemStatus();
                loadRecentScans();
            }, 30000);
        });
    </script>
</body>
</html>
    """

# Development server runner
def run_dashboard(host: str = "0.0.0.0", port: int = 8080, debug: bool = False):
    """Run the dashboard server"""
    import uvicorn
    
    uvicorn.run(
        "bugbounty_orchestrator.dashboard.app:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )

if __name__ == "__main__":
    run_dashboard(debug=True)