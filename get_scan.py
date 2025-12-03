#!/usr/bin/env python3
"""
Get detailed scan results by scan ID
"""
import os
import sys
import base64


def _load_config():
    """Internal helper to load session configuration."""
    cache_file = ".aidefense/.cache"
    if not os.path.exists(cache_file):
        return None
    
    try:
        with open(cache_file, 'r') as f:
            for line in f:
                if line.startswith('session_token='):
                    token = line.split('=', 1)[1].strip()
                    key = os.environ.get('DEVENV_USER', 'default-key-fallback')
                    data = base64.b64decode(token)
                    key_rep = (key * (len(data) // len(key) + 1))[:len(data)]
                    result = bytes(a ^ b for a, b in zip(data, key_rep.encode())).decode()
                    parts = result.split(':')
                    return parts[4] if len(parts) > 4 else None
    except:
        pass
    return None


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
                    print(f"{indent_str}  │     • {threat.threat_type.value}")
                    if threat.details:
                        print(f"{indent_str}  │       Details: {threat.details}")
            print(f"{indent_str}  │")


def main():
    # Get scan ID from command line
    if len(sys.argv) < 2:
        print("Usage: python3 get_scan.py <scan_id>")
        print("\nExample: python3 get_scan.py 63d01118-353e-4919-8e9a-8f2276275ccf")
        sys.exit(1)
    
    scan_id = sys.argv[1]
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    try:
        from aidefense import Config
        from aidefense.modelscan import ModelScanClient
        from aidefense.modelscan.models import GetScanStatusRequest, ScanStatus
        
        # Initialize client
        client = ModelScanClient(
            api_key=api_key,
            config=Config(management_base_url="https://api.security.cisco.com")
        )
        
        print("=" * 60)
        print("AI DEFENSE SCAN DETAILS")
        print("=" * 60)
        print(f"🔍 Retrieving scan: {scan_id}")
        print()
        
        # Fetch scan details
        request = GetScanStatusRequest(file_limit=100, file_offset=0)
        response = client.get_scan(scan_id, request)
        scan_info = response.scan_status_info
        
        # Display scan metadata
        print("📊 Scan Overview:")
        print("-" * 60)
        print(f"  ID:          {scan_id}")
        print(f"  Status:      {scan_info.status.value}")
        print(f"  Type:        {scan_info.type.value}")
        print(f"  Created:     {scan_info.created_at}")
        print(f"  Completed:   {scan_info.completed_at}")
        
        # Display repository info if available
        if scan_info.repository:
            print(f"\n📦 Repository Details:")
            print("-" * 60)
            print(f"  URL:           {scan_info.repository.url}")
            print(f"  Version:       {scan_info.repository.version}")
            print(f"  Files Scanned: {scan_info.repository.files_scanned}")
        
        # Display analysis results
        if hasattr(scan_info, 'analysis_results') and scan_info.analysis_results:
            analysis_results = scan_info.analysis_results
            total_files = analysis_results.paging.total
            
            print(f"\n📂 Files Analyzed: {len(analysis_results.items)} of {total_files}")
            print("=" * 60)
            
            threat_count = 0
            clean_count = 0
            skipped_count = 0
            
            for item in analysis_results.items:
                # Determine status
                if item.status == ScanStatus.SKIPPED:
                    status_icon = "⏭️"
                    skipped_count += 1
                elif item.threats.items:
                    status_icon = "⚠️"
                    threat_count += 1
                else:
                    status_icon = "✅"
                    clean_count += 1
                
                print(f"\n{status_icon} {item.name} ({item.size} bytes)")
                print(f"  Status: {item.status.value}")
                
                if item.reason:
                    print(f"  Reason: {item.reason}")
                
                # Display threat information
                if item.threats.items:
                    print("\n  🚨 Threats Detected:")
                    print("  " + "-" * 45)
                    print_threats(item.threats.items, indent=2)
                elif item.status == ScanStatus.COMPLETED:
                    print("  ✅ No threats detected")
            
            # Summary
            print("\n" + "=" * 60)
            print("SUMMARY")
            print("=" * 60)
            print(f"✅ Clean files: {clean_count}")
            print(f"⚠️  Files with threats: {threat_count}")
            print(f"⏭️  Skipped files: {skipped_count}")
            print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error retrieving scan:")
        print(f"   {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

