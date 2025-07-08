"""
Report generation module for creating comprehensive security reports
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import json
import base64

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate comprehensive security reports in multiple formats"""
    
    def __init__(self):
        self.template_dir = Path("templates")
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)
        
    async def generate_report(self, scan_job: Any, formats: List[str] = None) -> Path:
        """Generate reports in specified formats"""
        
        formats = formats or ['html', 'json']
        
        # Extract report data from scan job
        report_data = self._extract_report_data(scan_job)
        
        # Generate reports in different formats
        generated_files = []
        
        for format_type in formats:
            try:
                if format_type == 'html':
                    file_path = await self._generate_html_report(report_data, scan_job)
                elif format_type == 'json':
                    file_path = await self._generate_json_report(report_data, scan_job)
                elif format_type == 'pdf':
                    file_path = await self._generate_pdf_report(report_data, scan_job)
                elif format_type == 'xml':
                    file_path = await self._generate_xml_report(report_data, scan_job)
                else:
                    logger.warning(f"Unsupported report format: {format_type}")
                    continue
                
                generated_files.append(file_path)
                logger.info(f"Generated {format_type.upper()} report: {file_path}")
                
            except Exception as e:
                logger.error(f"Failed to generate {format_type} report: {e}")
        
        # Return primary report file (HTML if available, otherwise first generated)
        if generated_files:
            html_reports = [f for f in generated_files if f.suffix == '.html']
            return html_reports[0] if html_reports else generated_files[0]
        
        raise RuntimeError("Failed to generate any reports")
    
    def _extract_report_data(self, scan_job: Any) -> Dict[str, Any]:
        """Extract and organize data for report generation"""
        
        results = scan_job.results
        
        # Extract key metrics
        subdomain_data = results.get('subdomain_discovery', {})
        port_scan_data = results.get('port_scanning', {})
        vuln_scan_data = results.get('vulnerability_scanning', {})
        web_crawl_data = results.get('web_crawling', {})
        
        # Organize findings by severity
        findings = vuln_scan_data.get('findings', [])
        findings_by_severity = {
            'critical': [f for f in findings if f.get('severity', '').lower() == 'critical'],
            'high': [f for f in findings if f.get('severity', '').lower() == 'high'],
            'medium': [f for f in findings if f.get('severity', '').lower() == 'medium'],
            'low': [f for f in findings if f.get('severity', '').lower() == 'low'],
            'info': [f for f in findings if f.get('severity', '').lower() == 'info']
        }
        
        # Calculate statistics
        stats = {
            'total_subdomains': subdomain_data.get('total_subdomains', 0),
            'verified_subdomains': len(subdomain_data.get('verified_subdomains', [])),
            'total_urls': web_crawl_data.get('total_urls', 0),
            'total_findings': len(findings),
            'critical_findings': len(findings_by_severity['critical']),
            'high_findings': len(findings_by_severity['high']),
            'medium_findings': len(findings_by_severity['medium']),
            'low_findings': len(findings_by_severity['low']),
            'info_findings': len(findings_by_severity['info'])
        }
        
        # Extract technologies
        technologies = set()
        if 'technologies' in web_crawl_data:
            technologies.update(web_crawl_data['technologies'])
        
        return {
            'scan_info': {
                'id': scan_job.id,
                'target': scan_job.target,
                'workflow': scan_job.workflow,
                'status': scan_job.status,
                'started_at': scan_job.started_at,
                'completed_at': scan_job.completed_at,
                'duration': self._calculate_duration(scan_job),
                'options': scan_job.options
            },
            'statistics': stats,
            'subdomains': {
                'discovered': subdomain_data.get('unique_subdomains', []),
                'verified': subdomain_data.get('verified_subdomains', []),
                'discovery_methods': subdomain_data.get('discovery_methods', {})
            },
            'ports': {
                'scan_results': port_scan_data.get('scan_results', {}),
                'summary': port_scan_data.get('summary', {})
            },
            'web_data': {
                'urls': web_crawl_data.get('discovered_urls', []),
                'endpoints': web_crawl_data.get('endpoints', []),
                'forms': web_crawl_data.get('forms', []),
                'technologies': list(technologies)
            },
            'vulnerabilities': {
                'all_findings': findings,
                'by_severity': findings_by_severity,
                'scan_methods': vuln_scan_data.get('scan_methods', {})
            },
            'errors': scan_job.errors
        }
    
    async def _generate_html_report(self, report_data: Dict[str, Any], scan_job: Any) -> Path:
        """Generate HTML report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{scan_job.target.replace('.', '_')}_{timestamp}.html"
        output_path = self.output_dir / filename
        
        html_content = self._create_html_report(report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    async def _generate_json_report(self, report_data: Dict[str, Any], scan_job: Any) -> Path:
        """Generate JSON report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{scan_job.target.replace('.', '_')}_{timestamp}.json"
        output_path = self.output_dir / filename
        
        # Convert datetime objects to ISO format strings
        json_data = self._serialize_for_json(report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    async def _generate_pdf_report(self, report_data: Dict[str, Any], scan_job: Any) -> Path:
        """Generate PDF report"""
        
        try:
            # Generate HTML first
            html_content = self._create_html_report(report_data)
            
            # Convert HTML to PDF using weasyprint or similar
            try:
                import weasyprint
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"scan_report_{scan_job.target.replace('.', '_')}_{timestamp}.pdf"
                output_path = self.output_dir / filename
                
                weasyprint.HTML(string=html_content).write_pdf(str(output_path))
                
                return output_path
                
            except ImportError:
                logger.warning("weasyprint not available, skipping PDF generation")
                raise RuntimeError("PDF generation requires weasyprint library")
                
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise
    
    async def _generate_xml_report(self, report_data: Dict[str, Any], scan_job: Any) -> Path:
        """Generate XML report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{scan_job.target.replace('.', '_')}_{timestamp}.xml"
        output_path = self.output_dir / filename
        
        xml_content = self._create_xml_report(report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        
        return output_path
    
    def _create_html_report(self, report_data: Dict[str, Any]) -> str:
        """Create HTML report content"""
        
        scan_info = report_data['scan_info']
        stats = report_data['statistics']
        vulnerabilities = report_data['vulnerabilities']
        
        # HTML template
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_info['target']}</title>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Scan Report</h1>
            <div class="scan-info">
                <h2>Scan Information</h2>
                <table>
                    <tr><td><strong>Target:</strong></td><td>{scan_info['target']}</td></tr>
                    <tr><td><strong>Scan ID:</strong></td><td>{scan_info['id'][:8]}</td></tr>
                    <tr><td><strong>Workflow:</strong></td><td>{scan_info['workflow']}</td></tr>
                    <tr><td><strong>Status:</strong></td><td class="status-{scan_info['status']}">{scan_info['status']}</td></tr>
                    <tr><td><strong>Duration:</strong></td><td>{scan_info['duration']}</td></tr>
                    <tr><td><strong>Generated:</strong></td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                </table>
            </div>
        </header>
        
        <section class="summary">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card critical">
                    <h3>Critical</h3>
                    <div class="stat-number">{stats['critical_findings']}</div>
                </div>
                <div class="stat-card high">
                    <h3>High</h3>
                    <div class="stat-number">{stats['high_findings']}</div>
                </div>
                <div class="stat-card medium">
                    <h3>Medium</h3>
                    <div class="stat-number">{stats['medium_findings']}</div>
                </div>
                <div class="stat-card low">
                    <h3>Low</h3>
                    <div class="stat-number">{stats['low_findings']}</div>
                </div>
            </div>
            
            <div class="discovery-stats">
                <h3>Discovery Statistics</h3>
                <ul>
                    <li><strong>Subdomains Found:</strong> {stats['total_subdomains']}</li>
                    <li><strong>Subdomains Verified:</strong> {stats['verified_subdomains']}</li>
                    <li><strong>URLs Discovered:</strong> {stats['total_urls']}</li>
                    <li><strong>Total Findings:</strong> {stats['total_findings']}</li>
                </ul>
            </div>
        </section>
        
        {self._generate_vulnerabilities_section(vulnerabilities)}
        
        {self._generate_subdomains_section(report_data['subdomains'])}
        
        {self._generate_web_data_section(report_data['web_data'])}
        
        {self._generate_technologies_section(report_data['web_data']['technologies'])}
        
        <footer>
            <p>Generated by Bug Bounty Orchestrator v1.0.0</p>
        </footer>
    </div>
</body>
</html>
        """
        
        return html_template.strip()
    
    def _generate_vulnerabilities_section(self, vulnerabilities: Dict[str, Any]) -> str:
        """Generate vulnerabilities section HTML"""
        
        findings_by_severity = vulnerabilities['by_severity']
        
        section = '<section class="vulnerabilities"><h2>Vulnerability Findings</h2>'
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings = findings_by_severity.get(severity, [])
            if not findings:
                continue
            
            section += f'<div class="severity-section {severity}">'
            section += f'<h3>{severity.title()} Severity ({len(findings)} findings)</h3>'
            
            for finding in findings:
                section += f'''
                <div class="finding">
                    <h4>{finding.get('title', 'Unknown Vulnerability')}</h4>
                    <p><strong>URL:</strong> <code>{finding.get('url', 'N/A')}</code></p>
                    <p><strong>Description:</strong> {finding.get('description', 'No description available')}</p>
                    <p><strong>Type:</strong> {finding.get('vulnerability_type', 'Unknown')}</p>
                    {f"<p><strong>Payload:</strong> <code>{finding['payload']}</code></p>" if finding.get('payload') else ""}
                    {f"<p><strong>Evidence:</strong> {finding['evidence']}</p>" if finding.get('evidence') else ""}
                </div>
                '''
            
            section += '</div>'
        
        section += '</section>'
        return section
    
    def _generate_subdomains_section(self, subdomains_data: Dict[str, Any]) -> str:
        """Generate subdomains section HTML"""
        
        discovered = subdomains_data.get('discovered', [])
        verified = subdomains_data.get('verified', [])
        
        section = '<section class="subdomains"><h2>Subdomain Discovery</h2>'
        
        if discovered:
            section += f'<h3>Discovered Subdomains ({len(discovered)})</h3>'
            section += '<ul class="subdomain-list">'
            for subdomain in discovered[:50]:  # Limit display
                section += f'<li><code>{subdomain}</code></li>'
            section += '</ul>'
            
            if len(discovered) > 50:
                section += f'<p><em>... and {len(discovered) - 50} more</em></p>'
        
        if verified:
            section += f'<h3>Verified Subdomains ({len(verified)})</h3>'
            section += '<div class="verified-subdomains">'
            for sub_data in verified[:20]:  # Limit display
                if isinstance(sub_data, dict):
                    url = sub_data.get('url', sub_data.get('subdomain', 'Unknown'))
                    status = sub_data.get('status_code', 'N/A')
                    title = sub_data.get('title', 'No title')
                    section += f'''
                    <div class="verified-subdomain">
                        <strong><a href="{url}" target="_blank">{url}</a></strong>
                        <span class="status">HTTP {status}</span>
                        <em>{title}</em>
                    </div>
                    '''
            section += '</div>'
        
        section += '</section>'
        return section
    
    def _generate_web_data_section(self, web_data: Dict[str, Any]) -> str:
        """Generate web data section HTML"""
        
        urls = web_data.get('urls', [])
        endpoints = web_data.get('endpoints', [])
        forms = web_data.get('forms', [])
        
        section = '<section class="web-data"><h2>Web Application Data</h2>'
        
        if endpoints:
            section += f'<h3>Discovered Endpoints ({len(endpoints)})</h3>'
            section += '<ul class="endpoint-list">'
            for endpoint in endpoints[:30]:  # Limit display
                section += f'<li><code>{endpoint}</code></li>'
            section += '</ul>'
        
        if forms:
            section += f'<h3>Forms Found ({len(forms)})</h3>'
            section += '<div class="forms-list">'
            for form in forms[:10]:  # Limit display
                if isinstance(form, dict):
                    action = form.get('action', 'N/A')
                    method = form.get('method', 'GET')
                    inputs = len(form.get('inputs', []))
                    section += f'''
                    <div class="form-info">
                        <strong>Action:</strong> <code>{action}</code><br>
                        <strong>Method:</strong> {method}<br>
                        <strong>Inputs:</strong> {inputs}
                    </div>
                    '''
            section += '</div>'
        
        section += '</section>'
        return section
    
    def _generate_technologies_section(self, technologies: List[str]) -> str:
        """Generate technologies section HTML"""
        
        if not technologies:
            return ''
        
        section = '<section class="technologies"><h2>Detected Technologies</h2>'
        section += '<div class="tech-grid">'
        
        for tech in technologies:
            section += f'<div class="tech-item">{tech}</div>'
        
        section += '</div></section>'
        return section
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for HTML report"""
        
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        
        header {
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        h1 {
            color: #007acc;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        h2 {
            color: #333;
            font-size: 1.8em;
            margin: 30px 0 15px 0;
            border-bottom: 2px solid #eee;
            padding-bottom: 5px;
        }
        
        h3 {
            color: #555;
            font-size: 1.3em;
            margin: 20px 0 10px 0;
        }
        
        .scan-info table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        
        .scan-info td {
            padding: 8px;
            border-bottom: 1px solid #eee;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }
        
        .stat-card.critical { background-color: #dc3545; }
        .stat-card.high { background-color: #fd7e14; }
        .stat-card.medium { background-color: #ffc107; color: #333; }
        .stat-card.low { background-color: #28a745; }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-top: 10px;
        }
        
        .finding {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }
        
        .finding h4 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .severity-section.critical .finding { border-left: 5px solid #dc3545; }
        .severity-section.high .finding { border-left: 5px solid #fd7e14; }
        .severity-section.medium .finding { border-left: 5px solid #ffc107; }
        .severity-section.low .finding { border-left: 5px solid #28a745; }
        
        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            word-break: break-all;
        }
        
        .subdomain-list, .endpoint-list {
            list-style: none;
            columns: 3;
            column-gap: 20px;
        }
        
        .subdomain-list li, .endpoint-list li {
            margin: 5px 0;
            break-inside: avoid;
        }
        
        .verified-subdomain {
            background: #f8f9fa;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #28a745;
        }
        
        .verified-subdomain .status {
            float: right;
            background: #007acc;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.9em;
        }
        
        .tech-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }
        
        .tech-item {
            background: #007acc;
            color: white;
            padding: 8px 12px;
            border-radius: 5px;
            text-align: center;
            font-size: 0.9em;
        }
        
        footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #666;
        }
        
        .status-completed { color: #28a745; font-weight: bold; }
        .status-failed { color: #dc3545; font-weight: bold; }
        .status-running { color: #ffc107; font-weight: bold; }
        """
    
    def _create_xml_report(self, report_data: Dict[str, Any]) -> str:
        """Create XML report content"""
        
        scan_info = report_data['scan_info']
        
        xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<scan_report>
    <scan_info>
        <id>{scan_info['id']}</id>
        <target>{scan_info['target']}</target>
        <workflow>{scan_info['workflow']}</workflow>
        <status>{scan_info['status']}</status>
        <duration>{scan_info['duration']}</duration>
        <generated_at>{datetime.now().isoformat()}</generated_at>
    </scan_info>
    
    <statistics>
        <total_findings>{report_data['statistics']['total_findings']}</total_findings>
        <critical>{report_data['statistics']['critical_findings']}</critical>
        <high>{report_data['statistics']['high_findings']}</high>
        <medium>{report_data['statistics']['medium_findings']}</medium>
        <low>{report_data['statistics']['low_findings']}</low>
        <info>{report_data['statistics']['info_findings']}</info>
    </statistics>
    
    <vulnerabilities>
'''
        
        # Add vulnerabilities
        for finding in report_data['vulnerabilities']['all_findings']:
            xml_content += f'''
        <vulnerability>
            <title><![CDATA[{finding.get('title', 'Unknown')}]]></title>
            <severity>{finding.get('severity', 'info')}</severity>
            <url><![CDATA[{finding.get('url', '')}]]></url>
            <description><![CDATA[{finding.get('description', '')}]]></description>
            <type>{finding.get('vulnerability_type', 'unknown')}</type>
        </vulnerability>'''
        
        xml_content += '''
    </vulnerabilities>
</scan_report>'''
        
        return xml_content
    
    def _serialize_for_json(self, data: Any) -> Any:
        """Serialize data for JSON output"""
        
        if isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, dict):
            return {k: self._serialize_for_json(v) for k, v in data.items()}
        elif isinstance(data, (list, tuple, set)):
            return [self._serialize_for_json(item) for item in data]
        else:
            return data
    
    def _calculate_duration(self, scan_job: Any) -> str:
        """Calculate scan duration"""
        
        if scan_job.completed_at and scan_job.started_at:
            duration = scan_job.completed_at - scan_job.started_at
            total_seconds = int(duration.total_seconds())
            
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        
        return "Unknown"