#!/usr/bin/env python3
"""List and review scan history."""
import sys

from session_cache import get_mgmt_api


def main():
    api_key = get_mgmt_api()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)

    try:
        from aidefense import Config
        from aidefense.modelscan import ModelScanClient
        from aidefense.modelscan.models import ListScansRequest, ScanStatus

        client = ModelScanClient(
            api_key=api_key,
            config=Config(management_base_url="https://api.security.cisco.com"),
        )
        response = client.list_scans(ListScansRequest(limit=10, offset=0))
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
            print(f"   Type: {getattr(scan.type, 'value', scan.type)}")
            print(f"   Status: {getattr(scan.status, 'value', scan.status)}")
            print(f"   Files Scanned: {scan.files_scanned}")
            print(f"   Created: {scan.created_at}")
            if scan.issues_by_severity:
                issues = [f"{severity}: {count}" for severity, count in scan.issues_by_severity.items() if count > 0]
                if issues:
                    print(f"   Issues: {', '.join(issues)}")
                elif scan.status == ScanStatus.COMPLETED:
                    print("   Issues: None - All clean! ✅")
                else:
                    print("   Issues: Unavailable - scan has not completed")
            print("   " + "-" * 66)
        print("\n" + "=" * 70)
    except Exception as e:
        print("\n❌ Error:")
        print(f"   {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
