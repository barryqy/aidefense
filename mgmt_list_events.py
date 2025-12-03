#!/usr/bin/env python3
"""
AI Defense Management API - List Security Events
Lists and analyzes security events from AI Defense
"""
import os
import sys
import base64
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


def main():
    # Parse command line arguments for time range
    days_back = 1  # Default to last 24 hours
    limit = 20  # Default limit
    
    if len(sys.argv) > 1:
        try:
            days_back = int(sys.argv[1])
        except ValueError:
            print("Usage: python3 mgmt_list_events.py [days_back] [limit]")
            print("\nExample: python3 mgmt_list_events.py 7 50  # Last 7 days, max 50 events")
            sys.exit(1)
    
    if len(sys.argv) > 2:
        try:
            limit = int(sys.argv[2])
        except ValueError:
            pass
    
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    # Calculate time range
    end_time = datetime.now()
    start_time = end_time - timedelta(days=days_back)
    
    print("=" * 70)
    print("AI DEFENSE MANAGEMENT API - SECURITY EVENTS")
    print("=" * 70)
    print(f"📅 Time Range: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}")
    print(f"📊 Max Events: {limit}")
    print()
    
    try:
        from aidefense import Config
        from aidefense.management import ManagementClient
        from aidefense.management.models.event import ListEventsRequest
        
        # Initialize the ManagementClient
        config = Config(
            management_base_url="https://api.security.cisco.com",
            timeout=60
        )
        client = ManagementClient(api_key=api_key, config=config)
        
        print("🔄 Fetching events...")
        print()
        
        # Create request
        list_events_request = ListEventsRequest(
            limit=limit,
            start_date=start_time,
            end_date=end_time,
            expanded=True,
            sort_by="event_timestamp",
            order="desc"
        )
        
        # Get events
        events = client.events.list_events(list_events_request)
        
        if not events.items:
            print("📭 No events found in the specified time range")
            print()
            print("💡 Events are generated when:")
            print("   - AI Defense detects threats in prompts or responses")
            print("   - Policy violations occur")
            print("   - Guardrails are triggered")
            print()
            print("   Try running some tests with your API connections to generate events.")
            client.close()
            return
        
        print(f"🔍 Found {len(events.items)} events (Total: {events.paging.total})")
        print("=" * 70)
        print()
        
        # Group events by action
        event_actions = {}
        for event in events.items:
            action = event.event_action if event.event_action else "Unknown"
            if action not in event_actions:
                event_actions[action] = []
            event_actions[action].append(event)
        
        # Display summary
        print("📊 EVENT SUMMARY BY ACTION")
        print("-" * 70)
        for action, action_events in sorted(event_actions.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"  {action}: {len(action_events)} events")
        print()
        
        # Display events
        print("📋 EVENT DETAILS")
        print("-" * 70)
        
        for i, event in enumerate(events.items, 1):
            # Determine status icon based on action
            if event.event_action == "Block":
                icon = "🚫"
            elif event.event_action == "Alert":
                icon = "⚠️"
            elif event.event_action == "Allow":
                icon = "✅"
            else:
                icon = "📌"
            
            print(f"\n{i}. {icon} {event.event_action or 'Unknown Action'}")
            print(f"   Event ID: {event.event_id}")
            print(f"   Time: {event.event_date}")
            
            if hasattr(event, 'application_name') and event.application_name:
                print(f"   Application: {event.application_name}")
            
            if hasattr(event, 'connection_name') and event.connection_name:
                print(f"   Connection: {event.connection_name}")
            
            # Display classifications if available
            if hasattr(event, 'classifications') and event.classifications:
                if hasattr(event.classifications, 'items') and event.classifications.items:
                    print(f"   Classifications:")
                    for classification in event.classifications.items[:3]:  # Show first 3
                        conf = classification.confidence if hasattr(classification, 'confidence') else 'N/A'
                        print(f"      - {classification.classification} (confidence: {conf})")
            
            # Show preview of content if available
            if hasattr(event, 'prompt_preview') and event.prompt_preview:
                preview = event.prompt_preview[:80] + "..." if len(event.prompt_preview) > 80 else event.prompt_preview
                print(f"   Prompt: {preview}")
        
        print()
        print("=" * 70)
        print()
        print("💡 To view detailed information for a specific event:")
        if events.items:
            print(f"   python3 mgmt_get_event.py {events.items[0].event_id}")
        print()
        
        # Close the client
        client.close()
        
    except Exception as e:
        print(f"\n❌ Error:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

