#!/usr/bin/env python3
"""
AI Defense Management API - List Resources
Lists all applications, connections, and policies in your AI Defense tenant
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


def connection_type_label(value):
    if hasattr(value, "value"):
        return value.value
    return str(value)


def api_key_counts(client, connection_id):
    try:
        raw_keys = client.connections.make_request("GET", f"connections/{connection_id}/keys")
        items = raw_keys.get("keys", {}).get("items", [])
        active_keys = sum(1 for item in items if item.get("status") == "Active")
        return active_keys, len(items)
    except Exception:
        return None, None


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
                        print(f"   Connection Type: {connection_type_label(app.connection_type)}")
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
                        active_keys, total_keys = api_key_counts(client, conn.connection_id)
                        if total_keys is not None:
                            print(f"   API Keys: {active_keys} active, {total_keys} total")
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
            raw_resp = client.policies.make_request("GET", "policies", params=list_policies_req.to_params())
            policies = raw_resp.get("policies", {}).get("items", [])
            policy_count = raw_resp.get("policies", {}).get("paging", {}).get("total", len(policies))
            
            if policies:
                for i, policy in enumerate(policies, 1):
                    print(f"\n{i}. {policy.get('policy_name', 'Unnamed Policy')}")
                    print(f"   Policy ID: {policy.get('policy_id', 'Unknown')}")
                    if policy.get('description'):
                        print(f"   Description: {policy['description']}")
                    if policy.get('status'):
                        print(f"   Status: {policy['status']}")
                    if policy.get('connection_type'):
                        print(f"   Connection Type: {policy['connection_type']}")
                
                print(f"\n   Total: {policy_count} policies")
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
            policy_count = policy_count if 'policy_count' in locals() else 0
            
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
