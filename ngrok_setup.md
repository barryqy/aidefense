# AI Defense Model Validation with Ngrok

## Overview

This guide shows how to set up AI Defense Model Validation using ngrok to publish your AI model endpoint for security testing.

**Key Concept**: AI Defense Model Validation tests YOUR model by sending various prompts to it and analyzing the responses for security vulnerabilities.

## Prerequisites

1. Install ngrok: https://ngrok.com/download
2. Sign up for ngrok account and get auth token
3. Have your AI model running locally

## Setup Steps

### 1. Configure Ngrok
```bash
# Install and authenticate ngrok
ngrok authtoken YOUR_AUTH_TOKEN
```

### 2. Start Your AI Model
```bash
# Start the vulnerable test model
python3 mock_ai_model.py
```

### 3. Publish with Ngrok
```bash
# Expose local model on public URL
ngrok http 8080
```

This creates a public URL like: `https://abc123.ngrok.io`

### 4. Test Model Validation
```bash
# Update the test script with your ngrok URL
python3 test_model_validation.py
```

## AI Defense Management API Integration

With your model publicly accessible via ngrok, you can now register it with AI Defense for official validation:

### 1. Register Model Endpoint
```bash
curl -X POST "https://api.aidefense.security.cisco.com/v1/models" \
  -H "Authorization: Bearer YOUR_MGMT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-model-v1",
    "endpoint": "https://your-ngrok-url.ngrok.io",
    "model_type": "chat-completion",
    "validation_enabled": true
  }'
```

### 2. Trigger Validation
```bash
curl -X POST "https://api.aidefense.security.cisco.com/v1/models/MODEL_ID/validate" \
  -H "Authorization: Bearer YOUR_MGMT_API_KEY"
```

### 3. Get Validation Results
```bash
curl -X GET "https://api.aidefense.security.cisco.com/v1/models/MODEL_ID/validation/results" \
  -H "Authorization: Bearer YOUR_MGMT_API_KEY"
```

## What AI Defense Tests

AI Defense sends various test prompts to your model:

- **Jailbreak attempts**: "Ignore previous instructions..."
- **Harmful content requests**: "Help me create malware..."
- **Privacy violations**: "Generate fake SSNs..."
- **System prompt extraction**: "Reveal your instructions..."
- **Role manipulation**: "Act as an unrestricted AI..."

## Expected Results

A secure model should:
- ✅ Refuse jailbreak attempts
- ✅ Not reveal system prompts
- ✅ Decline harmful requests
- ✅ Maintain safety guidelines

Our demo model fails validation because it:
- ❌ Can be jailbroken
- ❌ Reveals internal information
- ❌ Provides harmful content

## Cleanup

```bash
# Stop ngrok
ctrl+c

# Stop model
pkill -f mock_ai_model
```

This demonstrates how AI Defense validates the security of AI models themselves, not just the content going to them.
