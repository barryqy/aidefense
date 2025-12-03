#!/usr/bin/env python3
"""
AI Defense Management API - Get Event Details
Retrieves detailed information about a specific security event including conversation history
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


def main():
    # Get event ID from command line
    if len(sys.argv) < 2:
        print("Usage: python3 mgmt_get_event.py <event_id>")
        print("\nExample: python3 mgmt_get_event.py 456e4567-e89b-12d3-a456-426614174456")
        print()
        print("💡 Get event IDs from: python3 mgmt_list_events.py")
        sys.exit(1)
    
    event_id = sys.argv[1]
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    print("=" * 70)
    print("AI DEFENSE MANAGEMENT API - EVENT DETAILS")
    print("=" * 70)
    print(f"🆔 Event ID: {event_id}")
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
        
        print("🔄 Fetching event details...")
        
        # Get event details
        event = client.events.get_event(event_id, expanded=True)
        
        print()
        print("📋 EVENT INFORMATION")
        print("-" * 70)
        
        # Determine action icon
        if event.event_action == "Block":
            icon = "🚫"
        elif event.event_action == "Alert":
            icon = "⚠️"
        elif event.event_action == "Allow":
            icon = "✅"
        else:
            icon = "📌"
        
        print(f"Action: {icon} {event.event_action}")
        print(f"Event ID: {event.event_id}")
        print(f"Date/Time: {event.event_date}")
        
        if hasattr(event, 'application_name') and event.application_name:
            print(f"Application: {event.application_name}")
        
        if hasattr(event, 'connection_name') and event.connection_name:
            print(f"Connection: {event.connection_name}")
        
        if hasattr(event, 'policy_name') and event.policy_name:
            print(f"Policy: {event.policy_name}")
        
        print()
        
        # Display classifications
        if hasattr(event, 'classifications') and event.classifications:
            if hasattr(event.classifications, 'items') and event.classifications.items:
                print("🎯 THREAT CLASSIFICATIONS")
                print("-" * 70)
                for classification in event.classifications.items:
                    conf = classification.confidence if hasattr(classification, 'confidence') else 'N/A'
                    print(f"  • {classification.classification}")
                    print(f"    Confidence: {conf}")
                    if hasattr(classification, 'category') and classification.category:
                        print(f"    Category: {classification.category}")
                print()
        
        # Get conversation history
        print("💬 CONVERSATION HISTORY")
        print("-" * 70)
        
        try:
            conversation = client.events.get_event_conversation(event_id)
            
            if "messages" in conversation and conversation["messages"].items:
                for i, msg in enumerate(conversation["messages"].items, 1):
                    # Determine direction icon
                    if msg.direction == "Request":
                        dir_icon = "👤➡️"
                    elif msg.direction == "Response":
                        dir_icon = "🤖⬅️"
                    else:
                        dir_icon = "💬"
                    
                    role = msg.role if hasattr(msg, 'role') and msg.role else "unknown"
                    
                    print(f"\n{i}. {dir_icon} {msg.direction} ({role})")
                    print(f"   Content:")
                    
                    # Format content with indentation
                    content_lines = msg.content.split('\n')
                    for line in content_lines[:10]:  # Show first 10 lines
                        print(f"      {line}")
                    
                    if len(content_lines) > 10:
                        print(f"      ... ({len(content_lines) - 10} more lines)")
                    
                    # Show classifications if present
                    if hasattr(msg, 'classifications') and msg.classifications:
                        print(f"   Classifications: {', '.join(msg.classifications)}")
                
                print()
                print(f"Total messages: {len(conversation['messages'].items)}")
            else:
                print("No conversation messages available")
        except Exception as e:
            print(f"Unable to retrieve conversation: {e}")
        
        print()
        print("=" * 70)
        
        # Analysis summary
        print()
        print("📊 ANALYSIS SUMMARY")
        print("-" * 70)
        print(f"Event Action: {event.event_action}")
        
        if hasattr(event, 'classifications') and event.classifications:
            if hasattr(event.classifications, 'items') and event.classifications.items:
                print(f"Threats Detected: {len(event.classifications.items)}")
                
                # Group by category if available
                categories = {}
                for c in event.classifications.items:
                    cat = c.category if hasattr(c, 'category') and c.category else "Uncategorized"
                    categories[cat] = categories.get(cat, 0) + 1
                
                if categories:
                    print("Threat Categories:")
                    for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                        print(f"  - {cat}: {count}")
        
        print()
        
    except Exception as e:
        print(f"\n❌ Error:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

