#!/usr/bin/env python3
"""
Test Real AI Defense Management API
Using the provided lab API token to test actual endpoints
"""
import requests
import json
import os

# Lab API token from pastebin
MGMT_API_KEY = "a1de47f520a27c7d655c65303c173f8645d7cb63d8becb88ecffa65e28bb6c2f"
MGMT_BASE_URL = "https://api.us.security.cisco.com/api/ai-defense/v1"

def test_api_connectivity():
    """Test basic API connectivity"""
    print("🔑 Testing AI Defense Management API Connectivity")
    print("=" * 60)
    print(f"API Key: {MGMT_API_KEY[:20]}...")
    print(f"Base URL: {MGMT_BASE_URL}")
    
    headers = {
        'x-cisco-ai-defense-tenant-api-key': MGMT_API_KEY,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Test health endpoint
    try:
        print("\n📡 Testing API health endpoint...")
        response = requests.get(f"{MGMT_BASE_URL}/health", headers=headers, timeout=30)
        print(f"Health Check: HTTP {response.status_code}")
        
        if response.status_code == 200:
            print("✅ API is healthy and accessible")
            try:
                health_data = response.json()
                print(f"Response: {json.dumps(health_data, indent=2)}")
            except:
                print(f"Response: {response.text}")
        else:
            print(f"❌ Health check failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Health check error: {e}")
    
    # Test models endpoint to see if we can list models
    try:
        print("\n📋 Testing models list endpoint...")
        response = requests.get(f"{MGMT_BASE_URL}/models", headers=headers, timeout=30)
        print(f"Models List: HTTP {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Models endpoint accessible")
            try:
                models_data = response.json()
                print(f"Models: {json.dumps(models_data, indent=2)}")
            except:
                print(f"Response: {response.text}")
        else:
            print(f"⚠️  Models endpoint response: {response.text}")
            
    except Exception as e:
        print(f"❌ Models endpoint error: {e}")
    
    # Test authentication by trying to access a protected endpoint
    try:
        print("\n🔐 Testing authentication...")
        response = requests.get(f"{MGMT_BASE_URL}/user/profile", headers=headers, timeout=30)
        print(f"Profile Access: HTTP {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Authentication successful")
        elif response.status_code == 401:
            print("❌ Authentication failed - invalid token")
        elif response.status_code == 404:
            print("ℹ️  Profile endpoint not found (expected)")
        else:
            print(f"Response: HTTP {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Authentication test error: {e}")

def test_model_registration():
    """Test model registration with a mock endpoint"""
    print("\n🤖 Testing Model Registration")
    print("=" * 60)
    
    headers = {
        'x-cisco-ai-defense-tenant-api-key': MGMT_API_KEY,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Test model registration payload
    model_data = {
        "name": "lab-test-model",
        "description": "Test model for AI Defense lab validation",
        "endpoint": "https://httpbin.org/post",  # Using httpbin as test endpoint
        "model_type": "chat-completion",
        "version": "1.0",
        "validation_enabled": True,
        "metadata": {
            "created_by": "ai-defense-lab",
            "purpose": "testing"
        }
    }
    
    try:
        print("📝 Attempting model registration...")
        print(f"Payload: {json.dumps(model_data, indent=2)}")
        
        response = requests.post(
            f"{MGMT_BASE_URL}/models",
            headers=headers,
            json=model_data,
            timeout=30
        )
        
        print(f"Registration Response: HTTP {response.status_code}")
        
        if response.status_code in [200, 201]:
            print("✅ Model registration successful!")
            result = response.json()
            model_id = result.get('id') or result.get('model_id')
            print(f"Model ID: {model_id}")
            return model_id
        else:
            print(f"⚠️  Registration response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return None

def main():
    """Run API tests"""
    print("🛡️  AI Defense Management API Testing")
    print("Using lab token from: https://pastebin.com/raw/nBgcnVvq")
    print("=" * 80)
    
    # Test basic connectivity
    test_api_connectivity()
    
    # Test model registration
    model_id = test_model_registration()
    
    print("\n" + "=" * 80)
    print("🏆 API Testing Summary:")
    if model_id:
        print("✅ API token is valid and working")
        print("✅ Model registration endpoint accessible")
        print("✅ Ready for full model validation workflow")
    else:
        print("⚠️  API testing completed with limitations")
        print("   Check endpoints and authentication requirements")
    
    print(f"\n💡 Next steps:")
    print("   1. Start mock model: python3 mock_ai_model.py")
    print("   2. Expose via ngrok: ngrok http 8080")
    print("   3. Run full validation: python3 setup_model_validation.py")

if __name__ == "__main__":
    main()
