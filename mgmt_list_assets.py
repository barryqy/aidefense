#!/usr/bin/env python3
"""
AI Defense Management API - List AI Assets
Lists all AI applications and connections in your AI Defense tenant
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
    print("AI DEFENSE - AI ASSET INVENTORY")
    print("=" * 70)
    print()
    
    try:
        from aidefense import Config
        from aidefense.management import ManagementClient
        from aidefense.management.models.application import ListApplicationsRequest
        from aidefense.management.models.connection import ListConnectionsRequest
        
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
        
        # List Applications - categorized by asset type
        print("🤖 AI ASSETS")
        print("-" * 70)
        try:
            list_apps_req = ListApplicationsRequest(limit=50, order="desc")
            apps_resp = client.applications.list_applications(list_apps_req)
            
            if apps_resp.applications.items:
                # Categorize by type
                agents = []
                protected_services = []
                knowledge_bases = []
                other = []
                
                for app in apps_resp.applications.items:
                    name_lower = app.application_name.lower()
                    desc_lower = (app.description or "").lower()
                    conn_type = connection_type_label(app.connection_type).lower()
                    
                    # Categorize based on name and description
                    if "gateway" in conn_type or any(keyword in name_lower + desc_lower for keyword in ['gateway', 'gpt', 'claude', 'llm', 'model']):
                        protected_services.append(app)
                    elif any(keyword in name_lower for keyword in ['bot', 'agent', 'assistant', 'barry']):
                        agents.append(app)
                    elif any(keyword in name_lower + desc_lower for keyword in ['knowledge', 'rag', 'vector', 'database']):
                        knowledge_bases.append(app)
                    else:
                        other.append(app)
                
                # Display AI Agents
                if agents:
                    print("\n🤖 AI Agents:")
                    for i, app in enumerate(agents, 1):
                        lab_marker = " [LAB]" if app.application_id in lab_app_ids else ""
                        print(f"   {i}. {app.application_name}{lab_marker}")
                        if app.description:
                            print(f"      Description: {app.description}")
                        print(f"      Integration: {connection_type_label(app.connection_type)}")
                
                if protected_services:
                    print("\n🧠 Protected Model Services:")
                    for i, app in enumerate(protected_services, 1):
                        lab_marker = " [LAB]" if app.application_id in lab_app_ids else ""
                        print(f"   {i}. {app.application_name}{lab_marker}")
                        if app.description:
                            print(f"      Description: {app.description}")
                        print(f"      Integration: {connection_type_label(app.connection_type)}")
                
                # Display Knowledge Bases
                if knowledge_bases:
                    print("\n📚 Knowledge Bases:")
                    for i, app in enumerate(knowledge_bases, 1):
                        lab_marker = " [LAB]" if app.application_id in lab_app_ids else ""
                        print(f"   {i}. {app.application_name}{lab_marker}")
                        if app.description:
                            print(f"      Description: {app.description}")
                        print(f"      Integration: {connection_type_label(app.connection_type)}")
                
                # Display Other Assets
                if other:
                    print("\n🔧 Other AI Assets:")
                    for i, app in enumerate(other, 1):
                        lab_marker = " [LAB]" if app.application_id in lab_app_ids else ""
                        print(f"   {i}. {app.application_name}{lab_marker}")
                        if app.description:
                            print(f"      Description: {app.description}")
                        print(f"      Integration: {connection_type_label(app.connection_type)}")
                
                print(f"\n   Total AI Assets: {apps_resp.applications.paging.total}")
            else:
                print("   No AI assets found")
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
        print("=" * 70)
        
        # Summary
        print("\n📊 AI ASSET SUMMARY")
        print("-" * 70)
        
        try:
            total_assets = apps_resp.applications.paging.total if 'apps_resp' in locals() else 0
            conn_count = conns_resp.paging.total if 'conns_resp' in locals() else 0
            
            print(f"Total AI Assets: {total_assets}")
            print(f"  - AI Agents: {len(agents) if 'agents' in locals() else 0}")
            print(f"  - Protected Model Services: {len(protected_services) if 'protected_services' in locals() else 0}")
            print(f"  - Knowledge Bases: {len(knowledge_bases) if 'knowledge_bases' in locals() else 0}")
            print(f"  - Other Assets: {len(other) if 'other' in locals() else 0}")
            print(f"\nActive Connections: {conn_count}")
            
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
