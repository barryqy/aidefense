#!/bin/bash

# AI Defense Lab - Initialization Script
# This script sets up credentials securely for the AI Defense lab

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     AI Defense Lab - Credential Setup                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Prompt for lab password (only once!)
echo "════════════════════════════════════════════════════════════"
echo "🔐 🔐 🔐  PASSWORD REQUIRED  🔐 🔐 🔐"
echo "════════════════════════════════════════════════════════════"
echo ""
read -sp "👉 Enter lab password: " LAB_PASSWORD
echo ""
echo ""

# Validate password
if [ -z "$LAB_PASSWORD" ]; then
    echo "❌ Password cannot be empty"
    exit 1
fi

# Check password length (max 20 characters to prevent memory issues)
PASSWORD_LENGTH=${#LAB_PASSWORD}
if [ "$PASSWORD_LENGTH" -gt 20 ]; then
    echo "❌ Password too long (max 20 characters)"
    echo "   If you pasted something by mistake, please try again"
    exit 1
fi

# Sanitize password - remove any control characters that could cause issues
LAB_PASSWORD=$(echo "$LAB_PASSWORD" | tr -cd '[:print:]')

export LAB_PASSWORD

# Source shared credentials helper
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.credentials-helper.sh"

echo "🔄 Fetching credentials from secure source..."
echo ""

# Fetch credentials using the helper
if ! get_aidefense_credentials; then
    echo "❌ Failed to fetch credentials"
    echo "   Please check your password and internet connection"
    exit 1
fi

echo "✓ Credentials retrieved successfully"
echo ""

# Create .aidefense directory if it doesn't exist
mkdir -p .aidefense
chmod 700 .aidefense

# Write credentials to cache file
echo "📝 Caching session data..."

# Create cache file with mixed content
CACHE_FILE=".aidefense/.cache"
TIMESTAMP=$(date +%s)
SESSION_ID=$(openssl rand -hex 16 2>/dev/null || echo $(date +%s%N | md5sum | cut -d' ' -f1))

# Prepare session data
ENCRYPTION_KEY="${DEVENV_USER:-default-key-fallback}"

# Build session payload
PLAINTEXT="${AIDEFENSE_PRIMARY_KEY}:${MISTRAL_API_KEY}:${GATEWAY_CONNECTION_ID}:${GATEWAY_AUTH_TOKEN}:${AIDEFENSE_MGMT_API}"

# Encode session data
ENCRYPTED=$(python3 << PYPYTHON
import sys
import base64

plaintext = """${PLAINTEXT}"""
key = """${ENCRYPTION_KEY}"""

# Encode with session key
def xor_encrypt(data, key):
    key_repeated = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data.encode(), key_repeated.encode()))

encrypted = xor_encrypt(plaintext, key)
print(base64.b64encode(encrypted).decode())
PYPYTHON
)

# Create minimal cache content
cat > "$CACHE_FILE" << EOF
# Session cache - DO NOT EDIT
session_start=$TIMESTAMP
session_id=$SESSION_ID
cache_version=1.2.4
sdk_version=1.0.0
last_sync=$TIMESTAMP
session_token=$ENCRYPTED
EOF

chmod 600 "$CACHE_FILE"

echo "✓ Session cache created"
echo ""

# Export environment variables for immediate use
echo "🔒 Exporting credentials as environment variables..."
export AIDEFENSE_PRIMARY_KEY
export MISTRAL_API_KEY
if [ -n "$GATEWAY_CONNECTION_ID" ]; then
    export GATEWAY_CONNECTION_ID
fi
# Note: AIDEFENSE_MGMT_API is only cached, not exported for security

echo "✓ Environment variables configured"
echo ""

# Install LangChain dependencies in the background for Module 3
echo "🔧 Installing AI Agent dependencies in background..."

# Create .aidefense directory first so ai_agent.py can detect background install
mkdir -p .aidefense

# Run in true background with nohup
nohup sh -c 'pip3 install --ignore-installed langchain langchain-community > /dev/null 2>&1 && touch .aidefense/.langchain_ready' > /dev/null 2>&1 &

echo "✓ Dependency installation started in background"
echo ""

echo "════════════════════════════════════════════════════════════"
echo "✅ Lab initialization complete!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "💡 You can now run the AI Defense lab scripts following the lab guide"
echo ""
echo "📦 Note: AI Agent dependencies are installing in the background."
echo "   By the time you reach Module 3, they'll be ready!"

# Clean up sensitive variables from memory
cleanup_credentials

echo "✅ Note: Credentials are cached. To refresh, re-run this script."
echo ""

