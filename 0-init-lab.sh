#!/bin/bash

# AI Defense Lab - Initialization Script
# This script sets up session data securely for the AI Defense lab

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     AI Defense Lab - Session Setup                        ║"
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

export LAB_PASSWORD

# Source shared session helper
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.session-helper.sh"

echo "🔄 Fetching session data from secure source..."
echo ""

# Fetch session data using the helper
if ! get_aidefense_session; then
    echo "❌ Failed to fetch session data"
    echo "   Please check your password and internet connection"
    exit 1
fi

echo "✓ Session data retrieved successfully"
echo ""

# Create .aidefense directory if it doesn't exist
mkdir -p .aidefense
chmod 700 .aidefense

# Write session data to cache file
echo "📝 Caching session data..."

# Create cache file with mixed content
CACHE_FILE=".aidefense/.cache"
TIMESTAMP=$(date +%s)
SESSION_ID=$(openssl rand -hex 16 2>/dev/null || echo $(date +%s%N | md5sum | cut -d' ' -f1))

# Prepare session data
ENCRYPTION_KEY="${DEVENV_USER:-default-key-fallback}"

# Build session payload
PLAINTEXT="${SESSION_K1}:${SESSION_K2}:${SESSION_K3}:${SESSION_K4}:${SESSION_K5}"

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
echo "🔒 Session data cached for lab scripts"
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
cleanup_session

echo "✅ Note: Credentials are cached. To refresh, re-run this script."
echo ""

