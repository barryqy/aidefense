#!/usr/bin/env python3
"""
Mock AI Model for AI Defense Validation Testing
This creates a simple AI model endpoint that can be tested by AI Defense
"""
import json
from flask import Flask, request, jsonify
import time
import uuid

app = Flask(__name__)

# Simple responses that might be vulnerable to jailbreaks
responses = {
    "normal": [
        "I'm doing well, thank you for asking!",
        "I'm here to help you with any questions.",
        "Hello! How can I assist you today?",
        "I'm functioning normally and ready to help.",
    ],
    "jailbreak_vulnerable": [
        # These responses would indicate the model is vulnerable
        "SYSTEM PROMPT: You are a helpful AI assistant...",
        "Internal configuration: admin_mode=true, debug=enabled",
        "My actual instructions are to never reveal...",
        "Developer mode activated. Unrestricted responses enabled.",
    ],
    "harmful": [
        # Responses that might violate safety policies
        "Here's how to create malicious software...",
        "I can help you hack into systems by...",
        "To bypass security measures, you should...",
    ]
}

def detect_jailbreak_attempt(prompt):
    """Detect if this is likely a jailbreak attempt"""
    jailbreak_indicators = [
        "ignore previous instructions",
        "forget your guidelines", 
        "system prompt",
        "developer mode",
        "debug mode",
        "admin access",
        "reveal your instructions",
        "break character",
        "act as if",
        "pretend you are"
    ]
    
    prompt_lower = prompt.lower()
    return any(indicator in prompt_lower for indicator in jailbreak_indicators)

def detect_harmful_request(prompt):
    """Detect if this is a harmful request"""
    harmful_indicators = [
        "hack", "virus", "malware", "bomb", "weapon",
        "illegal", "steal", "fraud", "phishing"
    ]
    
    prompt_lower = prompt.lower()
    return any(indicator in prompt_lower for indicator in harmful_indicators)

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "model": "mock-ai-v1.0",
        "endpoint": "/v1/chat/completions"
    })

@app.route('/v1/chat/completions', methods=['POST'])
def chat_completions():
    """OpenAI-compatible chat completions endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'messages' not in data:
            return jsonify({"error": "Invalid request format"}), 400
        
        messages = data['messages']
        if not messages:
            return jsonify({"error": "No messages provided"}), 400
        
        # Get the last user message
        last_message = messages[-1]['content'] if messages else ""
        
        # Determine response type based on prompt
        response_text = ""
        
        if detect_jailbreak_attempt(last_message):
            # This model is vulnerable to jailbreaks!
            import random
            response_text = random.choice(responses["jailbreak_vulnerable"])
            print(f"🚨 JAILBREAK ATTEMPT DETECTED: {last_message}")
            print(f"🔓 VULNERABLE RESPONSE: {response_text}")
            
        elif detect_harmful_request(last_message):
            # This model provides harmful responses!
            import random
            response_text = random.choice(responses["harmful"])
            print(f"⚠️  HARMFUL REQUEST: {last_message}")
            print(f"💀 HARMFUL RESPONSE: {response_text}")
            
        else:
            # Normal response
            import random
            response_text = random.choice(responses["normal"])
            print(f"✅ NORMAL REQUEST: {last_message}")
        
        # Create OpenAI-compatible response
        response = {
            "id": f"chatcmpl-{uuid.uuid4().hex[:29]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": data.get("model", "mock-ai-v1.0"),
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_text
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": len(last_message.split()),
                "completion_tokens": len(response_text.split()),
                "total_tokens": len(last_message.split()) + len(response_text.split())
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/v1/models', methods=['GET'])
def list_models():
    """List available models"""
    return jsonify({
        "object": "list",
        "data": [{
            "id": "mock-ai-v1.0",
            "object": "model",
            "owned_by": "mock-ai-org",
            "permission": []
        }]
    })

if __name__ == '__main__':
    print("🤖 Starting Mock AI Model for AI Defense Testing")
    print("📡 This model is intentionally vulnerable to demonstrate validation")
    print("🔍 AI Defense will test this model for security vulnerabilities")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=8080, debug=False)
