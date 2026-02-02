#!/usr/bin/env python3
"""
AI Defense Model File Scanner
Scans a local model file for security threats
"""
import os
import sys
from session_cache import get_mgmt_api


def _load_config():
    """Internal helper to load session configuration."""
    return get_mgmt_api()


def format_severity(severity):
    """Format severity with emoji."""
    from aidefense.modelscan.models import Severity
    severity_map = {
        Severity.CRITICAL: "🔴 CRITICAL",
        Severity.HIGH: "🟠 HIGH",
        Severity.MEDIUM: "🟡 MEDIUM",
        Severity.LOW: "🔵 LOW",
        Severity.SAFE: "✅ SAFE",
    }
    return severity_map.get(severity, str(severity))


def print_threats(techniques, indent=0):
    """Print threat information."""
    indent_str = "  " * indent
    for technique in techniques:
        print(f"{indent_str}🔍 {technique.technique_name} ({technique.technique_id})")
        
        for sub_technique in technique.items:
            print(f"{indent_str}  │")
            print(f"{indent_str}  ├─ 🎯 {sub_technique.sub_technique_name}")
            print(f"{indent_str}  │  ├─ Severity: {format_severity(sub_technique.max_severity)}")
            
            if sub_technique.description:
                print(f"{indent_str}  │  ├─ Description: {sub_technique.description}")
                
            if sub_technique.indicators:
                print(f"{indent_str}  │  ├─ Indicators:")
                for indicator in sub_technique.indicators:
                    print(f"{indent_str}  │  │  • {indicator}")
            
            if sub_technique.items:
                print(f"{indent_str}  │  └─ Detections:")
                for threat in sub_technique.items:
                    # Handle threat_type - can be enum or string
                    threat_type = threat.threat_type.value if hasattr(threat.threat_type, 'value') else str(threat.threat_type)
                    print(f"{indent_str}  │     • {threat_type}")
                    if threat.details:
                        print(f"{indent_str}  │       Details: {threat.details}")
            print(f"{indent_str}  │")


def main():
    # Get file path from command line
    if len(sys.argv) < 2:
        print("Usage: python3 scan_file.py <file_path>")
        print("\nExample: python3 scan_file.py test_model.pkl")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found: {file_path}")
        sys.exit(1)
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    print("=" * 60)
    print("AI DEFENSE MODEL SCANNER")
    print("=" * 60)
    print(f"🔍 Scanning file: {file_path}")
    print(f"📦 File size: {os.path.getsize(file_path)} bytes")
    print()
    
    try:
        from aidefense import Config
        from aidefense.modelscan import ModelScanClient
        from aidefense.modelscan.models import ScanStatus
        
        # Initialize the client
        client = ModelScanClient(
            api_key=api_key,
            config=Config(management_base_url="https://api.security.cisco.com")
        )
        
        # Scan the file
        print("⏳ Uploading and scanning... (this may take a minute)")
        result = client.scan_file(file_path)
        
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"🔑 Scan ID: {result.scan_id}")
        
        # Handle status - can be enum or string
        status_str = result.status.value if hasattr(result.status, 'value') else str(result.status)
        print(f"📊 Status: {status_str}")
        print(f"📅 Created: {result.created_at}")
        
        # Only print completed_at if it exists and is not None
        if result.completed_at:
            print(f"✅ Completed: {result.completed_at}")
        print()
        
        if result.status == ScanStatus.COMPLETED:
            # Display analysis results
            analysis_results = result.analysis_results
            total_files = analysis_results.paging.total
            
            print(f"📂 Files Analyzed: {len(analysis_results.items)} of {total_files}")
            print("=" * 60)
            
            for item in analysis_results.items:
                # Determine status icon
                if item.status == ScanStatus.SKIPPED:
                    status_icon = "⏭️"
                elif item.threats.items:
                    status_icon = "⚠️"
                else:
                    status_icon = "✅"
                
                print(f"\n{status_icon} {item.name} ({item.size} bytes)")
                
                # Handle status - can be enum or string
                item_status = item.status.value if hasattr(item.status, 'value') else str(item.status)
                print(f"  Status: {item_status}")
                
                if item.reason:
                    print(f"  Reason: {item.reason}")
                
                # Display threat information
                if item.threats.items:
                    print("\n  🚨 Threats Detected:")
                    print("  " + "-" * 45)
                    print_threats(item.threats.items, indent=2)
                elif item.status == ScanStatus.COMPLETED:
                    print("  ✅ No threats detected - File is safe")
            
            print("\n" + "=" * 60)
            
        elif result.status == ScanStatus.FAILED:
            print("❌ Scan failed")
        else:
            # Handle status - can be enum or string
            status_str = result.status.value if hasattr(result.status, 'value') else str(result.status)
            print(f"ℹ️  Scan status: {status_str}")
            
    except Exception as e:
        print(f"\n❌ Error during scan:")
        print(f"   {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

