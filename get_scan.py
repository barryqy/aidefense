#!/usr/bin/env python3
"""Get detailed scan results by scan ID."""
import sys

from scan_file import print_threats
from session_cache import get_mgmt_api


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_scan.py <scan_id>")
        print("\nExample: python3 get_scan.py 63d01118-353e-4919-8e9a-8f2276275ccf")
        sys.exit(1)

    scan_id = sys.argv[1]
    api_key = get_mgmt_api()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)

    try:
        from aidefense import Config
        from aidefense.modelscan import ModelScanClient
        from aidefense.modelscan.models import GetScanStatusRequest, ScanStatus

        client = ModelScanClient(
            api_key=api_key,
            config=Config(management_base_url="https://api.security.cisco.com"),
        )
        print("=" * 60)
        print("AI DEFENSE SCAN DETAILS")
        print("=" * 60)
        print(f"🔍 Retrieving scan: {scan_id}\n")
        response = client.get_scan(scan_id, GetScanStatusRequest(file_limit=100, file_offset=0))
        info = response.scan_status_info

        print("📊 Scan Overview:")
        print("-" * 60)
        print(f"  ID:          {info.scan_id}")
        print(f"  Status:      {getattr(info.status, 'value', info.status)}")
        print(f"  Type:        {getattr(info.type, 'value', info.type)}")
        print(f"  Created:     {info.created_at}")
        print(f"  Completed:   {info.completed_at}")
        if info.repository:
            print("\n📦 Repository Details:")
            print("-" * 60)
            print(f"  URL:           {info.repository.url}")
            print(f"  Version:       {info.repository.version}")
            print(f"  Files Scanned: {info.repository.files_scanned}")

        results = info.analysis_results
        print(f"\n📂 Files Analyzed: {len(results.items)} of {results.paging.total}")
        print("=" * 60)
        threat_count = clean_count = skipped_count = other_count = 0
        for item in results.items:
            if item.status == ScanStatus.SKIPPED:
                icon = "⏭️"
                skipped_count += 1
            elif item.threats.items:
                icon = "⚠️"
                threat_count += 1
            elif item.status == ScanStatus.COMPLETED:
                icon = "✅"
                clean_count += 1
            else:
                icon = "ℹ️"
                other_count += 1
            print(f"\n{icon} {item.name} ({item.size} bytes)")
            print(f"  Status: {getattr(item.status, 'value', item.status)}")
            if item.reason:
                print(f"  Reason: {item.reason}")
            if item.threats.items:
                print("\n  🚨 Threats Detected:")
                print("  " + "-" * 45)
                print_threats(item.threats.items, indent=2)
            elif item.status == ScanStatus.COMPLETED:
                print("  ✅ No threats detected")

        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"✅ Clean files: {clean_count}")
        print(f"⚠️  Files with threats: {threat_count}")
        print(f"⏭️  Skipped files: {skipped_count}")
        if other_count:
            print(f"ℹ️  Other files: {other_count}")
        print("=" * 60)
    except Exception as e:
        print("\n❌ Error retrieving scan:")
        print(f"   {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
