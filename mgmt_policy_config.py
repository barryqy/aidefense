#!/usr/bin/env python3
"""
AI Defense Management API - Policy Configuration
Manage policies and associate connections with policies
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


def list_policies(client):
    """List all policies."""
    from aidefense.management.models.policy import ListPoliciesRequest
    
    print("=" * 70)
    print("🛡️  POLICIES")
    print("=" * 70)
    print()
    
    list_policies_req = ListPoliciesRequest(limit=20, expanded=True, order="desc")
    policies_resp = client.policies.list_policies(list_policies_req)
    
    if not policies_resp.items:
        print("No policies found")
        return
    
    for i, policy in enumerate(policies_resp.items, 1):
        print(f"{i}. {policy.policy_name}")
        print(f"   Policy ID: {policy.policy_id}")
        if policy.description:
            print(f"   Description: {policy.description}")
        print(f"   Status: {policy.status}")
        
        # Display guardrails
        if hasattr(policy, 'guardrails') and policy.guardrails and policy.guardrails.items:
            print(f"   Guardrails ({len(policy.guardrails.items)}):")
            for guardrail in policy.guardrails.items:
                print(f"      - {guardrail.guardrails_type}")
        
        # Display connections if available
        if hasattr(policy, 'connections') and policy.connections:
            if policy.connections.items:
                print(f"   Associated Connections: {len(policy.connections.items)}")
            else:
                print("   Associated Connections: None")
        
        print()
    
    print(f"Total: {policies_resp.paging.total} policies")


def get_policy(client, policy_id):
    """Get detailed policy information."""
    print("=" * 70)
    print("🛡️  POLICY DETAILS")
    print("=" * 70)
    print()
    
    policy = client.policies.get_policy(policy_id, expanded=True)
    
    print(f"Name: {policy.policy_name}")
    print(f"ID: {policy.policy_id}")
    if policy.description:
        print(f"Description: {policy.description}")
    print(f"Status: {policy.status}")
    print()
    
    # Display guardrails
    if hasattr(policy, 'guardrails') and policy.guardrails and policy.guardrails.items:
        print("Guardrails:")
        for guardrail in policy.guardrails.items:
            print(f"  - Type: {guardrail.guardrails_type}")
            if hasattr(guardrail, 'description') and guardrail.description:
                print(f"    Description: {guardrail.description}")
            if hasattr(guardrail, 'action') and guardrail.action:
                print(f"    Action: {guardrail.action}")
        print()
    
    # Display connections
    if hasattr(policy, 'connections') and policy.connections:
        if policy.connections.items:
            print(f"Associated Connections ({len(policy.connections.items)}):")
            for conn in policy.connections.items:
                print(f"  - {conn.connection_name} ({conn.connection_id})")
        else:
            print("Associated Connections: None")


def associate_connection(client, policy_id, connection_id):
    """Associate a connection with a policy."""
    from aidefense.management.models.policy import AddOrUpdatePolicyConnectionsRequest
    
    print("=" * 70)
    print("🔗 ASSOCIATING CONNECTION WITH POLICY")
    print("=" * 70)
    print(f"Policy ID: {policy_id}")
    print(f"Connection ID: {connection_id}")
    print()
    
    print("🔄 Associating...")
    
    assoc_req = AddOrUpdatePolicyConnectionsRequest(
        connections_to_associate=[connection_id]
    )
    
    client.policies.update_policy_connections(policy_id, assoc_req)
    
    print("✅ Connection associated successfully!")
    print()
    print("💡 The connection will now be protected by this policy's guardrails")


def disassociate_connection(client, policy_id, connection_id):
    """Disassociate a connection from a policy."""
    from aidefense.management.models.policy import AddOrUpdatePolicyConnectionsRequest
    
    print("=" * 70)
    print("🔓 DISASSOCIATING CONNECTION FROM POLICY")
    print("=" * 70)
    print(f"Policy ID: {policy_id}")
    print(f"Connection ID: {connection_id}")
    print()
    
    print("🔄 Disassociating...")
    
    disassoc_req = AddOrUpdatePolicyConnectionsRequest(
        connections_to_disassociate=[connection_id]
    )
    
    client.policies.update_policy_connections(policy_id, disassoc_req)
    
    print("✅ Connection disassociated successfully!")


def main():
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 mgmt_policy_config.py list")
        print("  python3 mgmt_policy_config.py get <policy_id>")
        print("  python3 mgmt_policy_config.py associate <policy_id> <connection_id>")
        print("  python3 mgmt_policy_config.py disassociate <policy_id> <connection_id>")
        print()
        print("Examples:")
        print("  python3 mgmt_policy_config.py list")
        print("  python3 mgmt_policy_config.py get 550e8400-e29b-41d4-a716-446655440000")
        print("  python3 mgmt_policy_config.py associate 550e8400-e29b-41d4-a716-446655440000 323e4567-e89b-12d3-a456-426614174333")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    try:
        from aidefense import Config
        from aidefense.management import ManagementClient
        
        # Initialize the ManagementClient
        config = Config(
            management_base_url="https://api.security.cisco.com",
            timeout=60
        )
        client = ManagementClient(api_key=api_key, config=config)
        
        if command == "list":
            list_policies(client)
        
        elif command == "get":
            if len(sys.argv) < 3:
                print("❌ Error: policy_id required")
                print("Usage: python3 mgmt_policy_config.py get <policy_id>")
                sys.exit(1)
            policy_id = sys.argv[2]
            get_policy(client, policy_id)
        
        elif command == "associate":
            if len(sys.argv) < 4:
                print("❌ Error: policy_id and connection_id required")
                print("Usage: python3 mgmt_policy_config.py associate <policy_id> <connection_id>")
                sys.exit(1)
            policy_id = sys.argv[2]
            connection_id = sys.argv[3]
            associate_connection(client, policy_id, connection_id)
        
        elif command == "disassociate":
            if len(sys.argv) < 4:
                print("❌ Error: policy_id and connection_id required")
                print("Usage: python3 mgmt_policy_config.py disassociate <policy_id> <connection_id>")
                sys.exit(1)
            policy_id = sys.argv[2]
            connection_id = sys.argv[3]
            disassociate_connection(client, policy_id, connection_id)
        
        else:
            print(f"❌ Unknown command: {command}")
            print("Valid commands: list, get, associate, disassociate")
            sys.exit(1)
        
    except Exception as e:
        print(f"\n❌ Error:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

