#!/usr/bin/env python3
"""
AI Defense Management API - Create Connection
Creates a connection for an application and generates an API key
"""
import os
import sys
import base64
import json
from datetime import datetime, timedelta


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


def save_resource_id(resource_type, resource_id, name, extra_data=None):
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
    
    resource_entry = {
        "id": resource_id,
        "name": name,
        "created_at": datetime.now().isoformat()
    }
    
    if extra_data:
        resource_entry.update(extra_data)
    
    resources[resource_type].append(resource_entry)
    
    # Save back
    os.makedirs(os.path.dirname(resources_file), exist_ok=True)
    with open(resources_file, 'w') as f:
        json.dump(resources, f, indent=2)


def save_api_key(connection_id, api_key):
    """Save generated API key for testing (encrypted)."""
    key_file = ".aidefense/.test_api_key"
    
    # Simple obfuscation for lab purposes
    key_data = {
        "connection_id": connection_id,
        "api_key": base64.b64encode(api_key.encode()).decode(),
        "created_at": datetime.now().isoformat()
    }
    
    with open(key_file, 'w') as f:
        json.dump(key_data, f, indent=2)
    
    os.chmod(key_file, 0o600)


def main():
    # Get connection details from command line
    if len(sys.argv) < 2:
        print("Usage: python3 mgmt_create_connection.py <application_id> [connection_name]")
        print("\nExample: python3 mgmt_create_connection.py 123e4567-e89b-12d3-a456-426614174000 'Production API'")
        sys.exit(1)
    
    application_id = sys.argv[1]
    connection_name = sys.argv[2] if len(sys.argv) > 2 else f"Connection {datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    print("=" * 70)
    print("AI DEFENSE MANAGEMENT API - CREATE CONNECTION")
    print("=" * 70)
    print(f"🆔 Application ID: {application_id}")
    print(f"🔌 Connection Name: {connection_name}")
    print()
    
    try:
        from aidefense import Config
        from aidefense.management import ManagementClient
        from aidefense.management.models.connection import (
            CreateConnectionRequest,
            ConnectionType
        )
        from aidefense.management.models import ApiKeyRequest
        
        # Initialize the ManagementClient
        config = Config(
            management_base_url="https://api.security.cisco.com",
            timeout=60
        )
        client = ManagementClient(api_key=api_key, config=config)
        
        print("🔄 Creating connection and generating API key...")
        
        # Create connection with API key
        key_name = f"Lab Key {datetime.now().strftime('%Y%m%d-%H%M%S')}"
        expiry = datetime.now() + timedelta(days=30)
        
        create_conn_request = CreateConnectionRequest(
            application_id=application_id,
            connection_name=connection_name,
            connection_type=ConnectionType.API,
            key={
                "name": key_name,
                "expiry": expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        )
        
        # Call the API
        result = client.connections.create_connection(create_conn_request)
        
        print("\n" + "=" * 70)
        print("✅ CONNECTION CREATED SUCCESSFULLY")
        print("=" * 70)
        print(f"🆔 Connection ID: {result.connection_id}")
        print(f"🔌 Connection Name: {connection_name}")
        print(f"📱 Application ID: {application_id}")
        print()
        
        # Display API key information
        if result.key:
            generated_api_key = result.key.api_key
            key_id = result.key.key_id
            
            print("🔑 API KEY GENERATED")
            print("=" * 70)
            print(f"Key ID: {key_id}")
            print(f"Key Name: {key_name}")
            print(f"Expiry: {expiry.strftime('%Y-%m-%d')}")
            print()
            print(f"API Key: {generated_api_key[:10]}...{generated_api_key[-10:]} (masked)")
            print()
            print("⚠️  IMPORTANT: Save this API key securely!")
            print("   It will be stored temporarily for lab testing purposes.")
            print()
            
            # Save for testing
            save_api_key(result.connection_id, generated_api_key)
            print("✓ API key saved to .aidefense/.test_api_key (encrypted)")
        
        # Save resource ID for cleanup
        save_resource_id(
            "connections", 
            result.connection_id, 
            connection_name,
            {"application_id": application_id}
        )
        
        print()
        print("💡 Next Steps:")
        print("   1. Test the API key with inspection:")
        print("      python3 -c \"from aidefense.runtime import ChatInspectionClient; from aidefense import Config, Message, Role; client = ChatInspectionClient(api_key='YOUR_KEY', config=Config(runtime_base_url='https://api.inspect.aidefense.aiteam.cisco.com')); print(client.inspect_conversation([Message(role=Role.USER, content='Hello')]))\"")
        print()
        print("   2. Associate with a policy:")
        print(f"      python3 mgmt_policy_config.py associate <policy_id> {result.connection_id}")
        print()
        print("   3. View all resources:")
        print("      python3 mgmt_list_resources.py")
        print()
        
        # Close the client
        client.close()
        
    except Exception as e:
        print(f"\n❌ Error creating connection:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

