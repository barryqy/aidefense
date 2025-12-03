#!/usr/bin/env python3
"""
AI Defense Management API - Create Application
Creates a new application in AI Defense for protecting your AI systems
"""
import os
import sys
import base64
import json
from datetime import datetime


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


def save_resource_id(resource_type, resource_id, name):
    """Save created resource ID for tracking and cleanup."""
    resources_file = ".aidefense/.lab_resources.json"
    
    # Load existing resources
    resources = {}
    if os.path.exists(resources_file):
        try:
            with open(resources_file, 'r') as f:
                resources = json.load(f)
        except:
            resources = {}
    
    # Add new resource
    if resource_type not in resources:
        resources[resource_type] = []
    
    resources[resource_type].append({
        "id": resource_id,
        "name": name,
        "created_at": datetime.now().isoformat()
    })
    
    # Save back
    os.makedirs(os.path.dirname(resources_file), exist_ok=True)
    with open(resources_file, 'w') as f:
        json.dump(resources, f, indent=2)


def main():
    # Get application details from command line
    if len(sys.argv) < 2:
        print("Usage: python3 mgmt_create_app.py <application_name> [description]")
        print("\nExample: python3 mgmt_create_app.py 'My ChatBot' 'Customer service AI assistant'")
        sys.exit(1)
    
    app_name = sys.argv[1]
    app_description = sys.argv[2] if len(sys.argv) > 2 else f"Application created on {datetime.now().strftime('%Y-%m-%d')}"
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    print("=" * 70)
    print("AI DEFENSE MANAGEMENT API - CREATE APPLICATION")
    print("=" * 70)
    print(f"📝 Application Name: {app_name}")
    print(f"📄 Description: {app_description}")
    print()
    
    try:
        from aidefense import Config
        from aidefense.management import ManagementClient
        from aidefense.management.models.application import CreateApplicationRequest
        from aidefense.management.models.connection import ConnectionType
        
        # Initialize the ManagementClient
        config = Config(
            management_base_url="https://api.security.cisco.com",
            timeout=60
        )
        client = ManagementClient(api_key=api_key, config=config)
        
        print("🔄 Creating application...")
        
        # Create application request
        create_app_request = CreateApplicationRequest(
            application_name=app_name,
            description=app_description,
            connection_type=ConnectionType.API
        )
        
        # Call the API
        result = client.applications.create_application(create_app_request)
        
        print("\n" + "=" * 70)
        print("✅ APPLICATION CREATED SUCCESSFULLY")
        print("=" * 70)
        print(f"🆔 Application ID: {result.application_id}")
        print(f"📝 Name: {app_name}")
        print(f"📄 Description: {app_description}")
        print(f"🔌 Connection Type: API")
        print()
        
        # Save resource ID for cleanup
        save_resource_id("applications", result.application_id, app_name)
        
        print("💡 Next Steps:")
        print("   1. Create a connection for this application:")
        print(f"      python3 mgmt_create_connection.py {result.application_id}")
        print()
        print("   2. View all resources:")
        print("      python3 mgmt_list_resources.py")
        print()
        
    except Exception as e:
        print(f"\n❌ Error creating application:")
        print(f"   {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

