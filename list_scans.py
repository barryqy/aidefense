#!/usr/bin/env python3
"""
List and review scan history
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


def main():
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    try:
        from aidefense import Config
        from aidefense.modelscan import ModelScanClient
        from aidefense.modelscan.models import ListScansRequest
        
        # Initialize client
        client = ModelScanClient(
            api_key=api_key,
            config=Config(management_base_url="https://api.security.cisco.com")
        )
        
        # Get recent scans
        request = ListScansRequest(limit=10, offset=0)
        response = client.list_scans(request)
        
        scans = response.scans.items
        paging = response.scans.paging
        
        print("=" * 70)
        print(f"SCAN HISTORY - Showing {len(scans)} of {paging.total} scans")
        print("=" * 70)
        
        if not scans:
            print("\nNo scans found. Run a scan first!")
            return
        
        for i, scan in enumerate(scans, 1):
            print(f"\n{i}. Scan ID: {scan.scan_id}")
            print(f"   Name: {scan.name}")
            print(f"   Type: {scan.type.value}")
            print(f"   Status: {scan.status.value}")
            print(f"   Files Scanned: {scan.files_scanned}")
            print(f"   Created: {scan.created_at}")
            
            # Display issues by severity
            if scan.issues_by_severity:
                issue_summary = []
                for severity, count in scan.issues_by_severity.items():
                    if count > 0:
                        issue_summary.append(f"{severity}: {count}")
                
                if issue_summary:
                    print(f"   Issues: {', '.join(issue_summary)}")
                else:
                    print(f"   Issues: None - All clean! ✅")
            
            print("   " + "-" * 66)
        
        print("\n" + "=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error:")
        print(f"   {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

