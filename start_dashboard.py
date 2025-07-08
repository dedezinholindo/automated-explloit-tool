#!/usr/bin/env python3
"""
Startup script for Bug Bounty Orchestrator Dashboard
"""

import sys
import asyncio
import logging
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from bugbounty_orchestrator.dashboard.app import run_dashboard

def main():
    """Main entry point for dashboard startup"""
    
    # Setup basic logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting Bug Bounty Orchestrator Dashboard...")
        
        # Create necessary directories
        Path('data').mkdir(exist_ok=True)
        Path('reports').mkdir(exist_ok=True)
        
        # Run the dashboard
        run_dashboard(
            host="0.0.0.0",
            port=8080,
            debug=True
        )
        
    except KeyboardInterrupt:
        logger.info("Dashboard shutdown requested by user")
    except Exception as e:
        logger.error(f"Failed to start dashboard: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()