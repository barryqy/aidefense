#!/bin/bash

# AI Defense Lab - Initialization Script
# This script sets up session data securely for the AI Defense lab

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     AI Defense Lab - Session Setup                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# TEMPORARY: Auto-set password for live event (revert after event)
LAB_PASSWORD="585877"
echo "🔐 Using pre-configured event password"
echo ""

export LAB_PASSWORD

# Source shared session helper
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.session-helper.sh"

echo "🔄 Acquiring session data for the lab..."
echo ""

# Fetch session data using the helper
if ! get_aidefense_session; then
    echo "❌ Failed to fetch session data"
    echo "   Please check your password and internet connection"
    exit 1
fi

echo "✓ Session data ready"
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

# When the key service does not provide a dedicated gateway token, reuse the
# lab image's shared LLM key so gateway demos follow the new environment.
if [ -z "${SESSION_K4:-}" ] && [ -n "${LLM_API_KEY:-}" ]; then
    SESSION_K4="${LLM_API_KEY}"
fi

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

# Validate built-in lab LLM access from the container image
echo "🧠 Checking built-in lab LLM configuration..."
if [ -n "${LLM_BASE_URL:-}" ] && [ -n "${LLM_API_KEY:-}" ]; then
    echo "✓ Built-in lab LLM detected"
else
    echo "⚠️  Built-in lab LLM environment variables are not available in this shell"
    echo "   The AI agent and gateway demos expect LLM_BASE_URL and LLM_API_KEY"
fi
echo ""

echo "🔒 Session data cached for lab scripts"
echo ""

echo "════════════════════════════════════════════════════════════"
echo "✅ Lab initialization complete!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "💡 You can now run the AI Defense lab scripts following the lab guide"

# Clean up sensitive variables from memory
cleanup_session

echo "✅ Note: Credentials are cached. To refresh, re-run this script."
echo ""
