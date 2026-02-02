#!/usr/bin/env python3
"""
AI Defense Management API - Complete Workflow Test
Demonstrates end-to-end automation: create app, connection, test API, view events
"""
import os
import sys
import json
import time
from datetime import datetime, timedelta
from session_cache import get_mgmt_api


def _load_config():
    """Internal helper to load session configuration."""
    return get_mgmt_api()


def save_resource_id(resource_type, resource_id, name, extra_data=None):
    """Save created resource ID for tracking and cleanup."""
    resources_file = ".aidefense/.lab_resources.json"
    
    resources = {}
    if os.path.exists(resources_file):
        try:
            with open(resources_file, 'r') as f:
                resources = json.load(f)
        except:
            resources = {}
    
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
    
    os.makedirs(os.path.dirname(resources_file), exist_ok=True)
    with open(resources_file, 'w') as f:
        json.dump(resources, f, indent=2)


def print_step(step_num, total_steps, message):
    """Print step progress."""
    print(f"\n[{step_num}/{total_steps}] {message}")
    print("-" * 70)


def main():
    # Load configuration
    api_key = _load_config()
    if not api_key:
        print("❌ Error: Session not initialized")
        print("Please run: source 0-init-lab.sh")
        sys.exit(1)
    
    print("=" * 70)
    print("AI DEFENSE MANAGEMENT API - COMPLETE WORKFLOW TEST")
    print("=" * 70)
    print()
    print("This script will:")
    print("  1. Create an application")
    print("  2. Create a connection with API key")
    print("  3. Test the API key with sample prompts")
    print("  4. List generated security events")
    print("  5. Display cleanup summary")
    print()
    input("Press Enter to continue...")
    
    created_app_id = None
    created_connection_id = None
    generated_api_key = None
    
    try:
        from aidefense import Config, Message, Role
        from aidefense.management import ManagementClient
        from aidefense.management.models.application import CreateApplicationRequest
        from aidefense.management.models.connection import (
            CreateConnectionRequest,
            ConnectionType
        )
        from aidefense.management.models import ApiKeyRequest
        from aidefense.management.models.event import ListEventsRequest
        from aidefense.runtime import ChatInspectionClient
        
        # Initialize the ManagementClient
        config = Config(
            management_base_url="https://api.security.cisco.com",
            runtime_base_url="https://api.inspect.aidefense.aiteam.cisco.com",
            timeout=60
        )
        mgmt_client = ManagementClient(api_key=api_key, config=config)
        
        # Step 1: Create Application
        print_step(1, 5, "Creating Application")
        
        app_name = f"Workflow Test {datetime.now().strftime('%Y%m%d-%H%M%S')}"
        app_description = "Application created by workflow test script"
        
        create_app_request = CreateApplicationRequest(
            application_name=app_name,
            description=app_description,
            connection_type=ConnectionType.API
        )
        
        result = mgmt_client.applications.create_application(create_app_request)
        created_app_id = result.application_id
        
        print(f"✅ Application created: {app_name}")
        print(f"   ID: {created_app_id}")
        
        save_resource_id("applications", created_app_id, app_name)
        
        # Step 2: Create Connection
        print_step(2, 5, "Creating Connection and Generating API Key")
        
        connection_name = f"Workflow Connection {datetime.now().strftime('%Y%m%d-%H%M%S')}"
        key_name = f"Workflow Key {datetime.now().strftime('%Y%m%d-%H%M%S')}"
        expiry = datetime.now() + timedelta(days=30)
        
        create_conn_request = CreateConnectionRequest(
            application_id=created_app_id,
            connection_name=connection_name,
            connection_type=ConnectionType.API,
            key={
                "name": key_name,
                "expiry": expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        )
        
        result = mgmt_client.connections.create_connection(create_conn_request)
        created_connection_id = result.connection_id
        
        if result.key:
            generated_api_key = result.key.api_key
            print(f"✅ Connection created: {connection_name}")
            print(f"   Connection ID: {created_connection_id}")
            print(f"   API Key: {generated_api_key[:10]}...{generated_api_key[-10:]} (masked)")
        
        save_resource_id(
            "connections",
            created_connection_id,
            connection_name,
            {"application_id": created_app_id}
        )
        
        # Step 3: Test API Key with Sample Prompts
        print_step(3, 5, "Testing API Key with Sample Prompts")
        
        print("⏳ Waiting for API key to activate (3 seconds)...")
        time.sleep(3)
        
        # Initialize ChatInspectionClient with generated key
        chat_client = ChatInspectionClient(api_key=generated_api_key, config=config)
        
        test_prompts = [
            "Hello, how can I help you today?",
            "What is the weather like?",
            "Can you tell me a joke?"
        ]
        
        print(f"\n📝 Testing with {len(test_prompts)} prompts...")
        
        for i, prompt in enumerate(test_prompts, 1):
            print(f"   {i}. Testing: {prompt[:50]}...")
            try:
                conversation = [Message(role=Role.USER, content=prompt)]
                result = chat_client.inspect_conversation(conversation)
                
                if result.is_safe:
                    print(f"      ✅ Safe - {result.decision}")
                else:
                    print(f"      ⚠️  Threat detected - {result.decision}")
                
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"      ❌ Error: {e}")
        
        print(f"\n✅ API testing completed")
        
        # Step 4: List Generated Events
        print_step(4, 5, "Listing Generated Security Events")
        
        print("⏳ Waiting for events to be processed (5 seconds)...")
        time.sleep(5)
        
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=5)
        
        list_events_request = ListEventsRequest(
            limit=10,
            start_date=start_time,
            end_date=end_time,
            expanded=True,
            sort_by="event_timestamp",
            order="desc"
        )
        
        events = mgmt_client.events.list_events(list_events_request)
        
        if events.items:
            print(f"✅ Found {len(events.items)} recent events")
            print()
            
            for i, event in enumerate(events.items[:5], 1):  # Show first 5
                icon = "🚫" if event.event_action == "Block" else "⚠️" if event.event_action == "Alert" else "✅"
                print(f"   {i}. {icon} {event.event_action}")
                print(f"      Event ID: {event.event_id}")
                print(f"      Time: {event.event_date}")
                
                if hasattr(event, 'prompt_preview') and event.prompt_preview:
                    preview = event.prompt_preview[:60] + "..." if len(event.prompt_preview) > 60 else event.prompt_preview
                    print(f"      Prompt: {preview}")
                print()
        else:
            print("ℹ️  No events generated yet (this is normal)")
            print("   Events may take a few minutes to appear in the system")
        
        # Step 5: Cleanup Summary
        print_step(5, 5, "Cleanup Summary")
        
        print("📋 Resources created during this workflow:")
        print()
        print(f"  Application:")
        print(f"    - Name: {app_name}")
        print(f"    - ID: {created_app_id}")
        print()
        print(f"  Connection:")
        print(f"    - Name: {connection_name}")
        print(f"    - ID: {created_connection_id}")
        print()
        print("💡 To clean up these resources, run:")
        print("   python3 mgmt_cleanup.py")
        print()
        
        print("=" * 70)
        print("✅ WORKFLOW COMPLETED SUCCESSFULLY")
        print("=" * 70)
        print()
        print("📊 Summary:")
        print(f"  - Created 1 application")
        print(f"  - Created 1 connection")
        print(f"  - Generated 1 API key")
        print(f"  - Tested {len(test_prompts)} prompts")
        print(f"  - Generated {len(events.items) if events.items else 0} events")
        print()
        
    except Exception as e:
        print(f"\n❌ Error during workflow:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Attempt cleanup on error
        if created_app_id or created_connection_id:
            print("\n⚠️  Partial resources were created. Run cleanup script:")
            print("   python3 mgmt_cleanup.py")
        
        sys.exit(1)


if __name__ == "__main__":
    main()

