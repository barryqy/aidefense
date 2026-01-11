#!/usr/bin/env python3
"""
AI Defense Management API - List Resources
Lists all applications, connections, and policies in your AI Defense tenant
"""
import os
import sys
import base64
import json


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


def main():
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    print("=" * 70)
    print("AI DEFENSE MANAGEMENT API - RESOURCE INVENTORY")
    print("=" * 70)
    print()
    
    try:
        from aidefense import Config
        from aidefense.management import ManagementClient
        from aidefense.management.models.application import ListApplicationsRequest
        from aidefense.management.models.connection import ListConnectionsRequest
        from aidefense.management.models.policy import ListPoliciesRequest
        
        # Initialize the ManagementClient
        config = Config(
            management_base_url="https://api.security.cisco.com",
            timeout=60
        )
        client = ManagementClient(api_key=api_key, config=config)
        
        # Load lab-created resources
        lab_resources = load_lab_resources()
        lab_app_ids = {r['id'] for r in lab_resources.get('applications', [])}
        lab_conn_ids = {r['id'] for r in lab_resources.get('connections', [])}
        
        # List Applications
        print("📱 APPLICATIONS")
        print("-" * 70)
        try:
            list_apps_req = ListApplicationsRequest(limit=50, order="desc")
            apps_resp = client.applications.list_applications(list_apps_req)
            
            if apps_resp.applications.items:
                for i, app in enumerate(apps_resp.applications.items, 1):
                    lab_marker = " [LAB]" if app.application_id in lab_app_ids else ""
                    print(f"\n{i}. {app.application_name}{lab_marker}")
                    print(f"   ID: {app.application_id}")
                    if app.description:
                        print(f"   Description: {app.description}")
                    # Handle connection_type which might be enum or string
                    if hasattr(app, 'connection_type') and app.connection_type:
                        conn_type = app.connection_type.value if hasattr(app.connection_type, 'value') else str(app.connection_type)
                        print(f"   Connection Type: {conn_type}")
                    if hasattr(app, 'created_at') and app.created_at:
                        print(f"   Created: {app.created_at}")
                
                print(f"\n   Total: {apps_resp.applications.paging.total} applications")
            else:
                print("   No applications found")
        except Exception as e:
            print(f"   Error listing applications: {e}")
        
        print()
        
        # List Connections
        print("🔌 CONNECTIONS")
        print("-" * 70)
        try:
            list_conns_req = ListConnectionsRequest(limit=50, order="desc")
            conns_resp = client.connections.list_connections(list_conns_req)
            
            if conns_resp.items:
                for i, conn in enumerate(conns_resp.items, 1):
                    lab_marker = " [LAB]" if conn.connection_id in lab_conn_ids else ""
                    print(f"\n{i}. {conn.connection_name}{lab_marker}")
                    print(f"   Connection ID: {conn.connection_id}")
                    print(f"   Application ID: {conn.application_id}")
                    if hasattr(conn, 'created_at') and conn.created_at:
                        print(f"   Created: {conn.created_at}")
                    
                    # Try to get API keys count
                    try:
                        keys = client.connections.get_api_keys(conn.connection_id)
                        active_keys = sum(1 for k in keys.items if k.status == "Active")
                        print(f"   API Keys: {active_keys} active, {len(keys.items)} total")
                    except:
                        pass
                
                print(f"\n   Total: {conns_resp.paging.total} connections")
            else:
                print("   No connections found")
        except Exception as e:
            print(f"   Error listing connections: {e}")
        
        print()
        
        # List Policies
        print("🛡️  POLICIES")
        print("-" * 70)
        try:
            list_policies_req = ListPoliciesRequest(limit=20, expanded=False, order="desc")
            policies_resp = client.policies.list_policies(list_policies_req)
            
            if policies_resp.items:
                for i, policy in enumerate(policies_resp.items, 1):
                    print(f"\n{i}. {policy.policy_name}")
                    print(f"   Policy ID: {policy.policy_id}")
                    if policy.description:
                        print(f"   Description: {policy.description}")
                    if policy.status:
                        print(f"   Status: {policy.status}")
                    
                    # Count guardrails if available
                    if hasattr(policy, 'guardrails') and policy.guardrails and policy.guardrails.items:
                        print(f"   Guardrails: {len(policy.guardrails.items)} configured")
                
                print(f"\n   Total: {policies_resp.paging.total} policies")
            else:
                print("   No policies found")
        except Exception as e:
            print(f"   Error listing policies: {e}")
        
        print()
        print("=" * 70)
        
        # Summary
        print("\n📊 SUMMARY")
        print("-" * 70)
        
        try:
            app_count = apps_resp.applications.paging.total if 'apps_resp' in locals() else 0
            conn_count = conns_resp.paging.total if 'conns_resp' in locals() else 0
            policy_count = policies_resp.paging.total if 'policies_resp' in locals() else 0
            
            print(f"Applications: {app_count}")
            print(f"Connections: {conn_count}")
            print(f"Policies: {policy_count}")
            
            # Lab resources
            lab_app_count = len(lab_resources.get('applications', []))
            lab_conn_count = len(lab_resources.get('connections', []))
            
            if lab_app_count > 0 or lab_conn_count > 0:
                print()
                print(f"Lab-created resources marked with [LAB]:")
                print(f"  - Applications: {lab_app_count}")
                print(f"  - Connections: {lab_conn_count}")
        except:
            pass
        
        print()
        
    except Exception as e:
        print(f"\n❌ Error:")
        print(f"   {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

