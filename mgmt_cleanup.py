#!/usr/bin/env python3
"""
AI Defense Management API - Cleanup Lab Resources
Lists and deletes lab-created applications and connections
"""
import os
import sys
import json
from session_cache import get_mgmt_api


def _load_config():
    """Internal helper to load session configuration."""
    return get_mgmt_api()


def load_lab_resources():
    """Load lab-created resources from tracking file."""
    resources_file = ".aidefense/.lab_resources.json"
    if os.path.exists(resources_file):
        try:
            with open(resources_file, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}


def clear_lab_resources():
    """Clear the lab resources tracking file."""
    resources_file = ".aidefense/.lab_resources.json"
    if os.path.exists(resources_file):
        try:
            os.remove(resources_file)
        except:
            pass


def main():
    # Check for --force flag
    force = "--force" in sys.argv or "-f" in sys.argv
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    # Load lab resources
    lab_resources = load_lab_resources()
    
    if not lab_resources or (not lab_resources.get('applications') and not lab_resources.get('connections')):
        print("=" * 70)
        print("📭 NO LAB RESOURCES TO CLEAN UP")
        print("=" * 70)
        print()
        print("No lab-created resources were found in the tracking file.")
        print()
        print("💡 This is normal if:")
        print("   - You haven't created any resources yet")
        print("   - Resources were already cleaned up")
        print("   - You're running this script for the first time")
        print()
        return
    
    print("=" * 70)
    print("🧹 AI DEFENSE MANAGEMENT API - CLEANUP LAB RESOURCES")
    print("=" * 70)
    print()
    print("The following lab-created resources will be deleted:")
    print()
    
    # Display resources to be deleted
    applications = lab_resources.get('applications', [])
    connections = lab_resources.get('connections', [])
    
    if applications:
        print(f"📱 APPLICATIONS ({len(applications)}):")
        for i, app in enumerate(applications, 1):
            print(f"   {i}. {app['name']}")
            print(f"      ID: {app['id']}")
            print(f"      Created: {app.get('created_at', 'Unknown')}")
        print()
    
    if connections:
        print(f"🔌 CONNECTIONS ({len(connections)}):")
        for i, conn in enumerate(connections, 1):
            print(f"   {i}. {conn['name']}")
            print(f"      ID: {conn['id']}")
            print(f"      Application: {conn.get('application_id', 'Unknown')}")
            print(f"      Created: {conn.get('created_at', 'Unknown')}")
        print()
    
    print("=" * 70)
    print()
    
    # Confirmation
    if not force:
        print("⚠️  WARNING: This action cannot be undone!")
        print()
        response = input("Are you sure you want to delete these resources? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("\n❌ Cleanup cancelled")
            return
        print()
    
    try:
        from aidefense import Config
        from aidefense.management import ManagementClient
        
        # Initialize the ManagementClient
        config = Config(
            management_base_url="https://api.security.cisco.com",
            timeout=60
        )
        client = ManagementClient(api_key=api_key, config=config)
        
        deleted_connections = 0
        deleted_applications = 0
        errors = []
        
        # Delete connections first (must be deleted before applications)
        if connections:
            print("🔄 Deleting connections...")
            for conn in connections:
                try:
                    print(f"   Deleting: {conn['name']} ({conn['id']})...")
                    client.connections.delete_connection(conn['id'])
                    deleted_connections += 1
                    print(f"      ✅ Deleted")
                except Exception as e:
                    error_msg = f"Failed to delete connection {conn['id']}: {e}"
                    errors.append(error_msg)
                    print(f"      ❌ Error: {e}")
            print()
        
        # Delete applications
        if applications:
            print("🔄 Deleting applications...")
            for app in applications:
                try:
                    print(f"   Deleting: {app['name']} ({app['id']})...")
                    client.applications.delete_application(app['id'])
                    deleted_applications += 1
                    print(f"      ✅ Deleted")
                except Exception as e:
                    error_msg = f"Failed to delete application {app['id']}: {e}"
                    errors.append(error_msg)
                    print(f"      ❌ Error: {e}")
            print()
        
        print("=" * 70)
        print("🧹 CLEANUP SUMMARY")
        print("=" * 70)
        print(f"✅ Deleted {deleted_connections} connection(s)")
        print(f"✅ Deleted {deleted_applications} application(s)")
        
        if errors:
            print(f"\n⚠️  {len(errors)} error(s) occurred:")
            for error in errors:
                print(f"   - {error}")
        else:
            print("\n✨ All resources cleaned up successfully!")
            
            # Clear the tracking file
            clear_lab_resources()
            print("   Tracking file cleared")
        
        print()
        
    except Exception as e:
        print(f"\n❌ Error during cleanup:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

