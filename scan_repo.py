#!/usr/bin/env python3
"""
AI Defense Repository Scanner
Scans a HuggingFace repository for security threats
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
                    # Handle threat_type - can be enum or string
                    threat_type = threat.threat_type.value if hasattr(threat.threat_type, 'value') else str(threat.threat_type)
                    print(f"{indent_str}  │     • {threat_type}")
                    if threat.details:
                        print(f"{indent_str}  │       Details: {threat.details}")
            print(f"{indent_str}  │")


def main():
    # Get repo URL from command line
    if len(sys.argv) < 2:
        print("Usage: python3 scan_repo.py <huggingface_repo_url>")
        print("\nExamples:")
        print("  python3 scan_repo.py https://huggingface.co/bert-base-uncased")
        print("  python3 scan_repo.py https://huggingface.co/gpt2")
        sys.exit(1)
    
    repo_url = sys.argv[1]
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    # Get HuggingFace token from environment (optional - only needed for private repos)
    hf_token = os.getenv("HUGGINGFACE_TOKEN")
    if not hf_token:
        print("ℹ️  Note: No HUGGINGFACE_TOKEN found")
        print("   Public repositories can be scanned without a token.")
        print("   For private repos, get a token at: https://huggingface.co/settings/tokens")
        print("   Then set it: export HUGGINGFACE_TOKEN='hf_your_token'")
        print()
    
    print("=" * 60)
    print("AI DEFENSE REPOSITORY SCANNER")
    print("=" * 60)
    print(f"🔍 Scanning repository: {repo_url}")
    print()
    
    try:
        from aidefense import Config
        from aidefense.modelscan import ModelScanClient
        from aidefense.modelscan.models import (
            ModelRepoConfig, URLType, Auth, HuggingFaceAuth, ScanStatus
        )
        
        # Initialize the client
        client = ModelScanClient(
            api_key=api_key,
            config=Config(management_base_url="https://api.security.cisco.com")
        )
        
        # Configure repository scan
        # Only include auth if token is provided
        if hf_token:
            repo_config = ModelRepoConfig(
                url=repo_url,
                type=URLType.HUGGING_FACE,
                auth=Auth(huggingface=HuggingFaceAuth(access_token=hf_token))
            )
        else:
            repo_config = ModelRepoConfig(
                url=repo_url,
                type=URLType.HUGGING_FACE
            )
        
        # Scan the repository
        print("⏳ Downloading and scanning repository... (this may take several minutes)")
        result = client.scan_repo(repo_config)
        
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
        
        if result.status == ScanStatus.COMPLETED:
            # Display repository info
            if result.repository:
                print(f"\n📦 Repository: {result.repository.url}")
                print(f"🔖 Version: {result.repository.version}")
                print(f"📁 Files Scanned: {result.repository.files_scanned}")
            
            print()
            
            # Display analysis results
            analysis_results = result.analysis_results
            total_files = analysis_results.paging.total
            
            print(f"📂 Files Analyzed: {len(analysis_results.items)} of {total_files}")
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
                    print("  ✅ No threats detected")
            
            # Summary
            print("\n" + "=" * 60)
            print("SCAN SUMMARY")
            print("=" * 60)
            print(f"✅ Clean files: {clean_count}")
            print(f"⚠️  Files with threats: {threat_count}")
            print(f"⏭️  Skipped files: {skipped_count}")
            print("=" * 60)
            
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

