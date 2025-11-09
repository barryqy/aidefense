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

if [ -z "$LAB_PASSWORD" ]; then
    echo "❌ Password cannot be empty"
    exit 1
fi

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

# Encode credentials
DATA1=$(echo -n "$AIDEFENSE_PRIMARY_KEY" | base64)
DATA2=$(echo -n "$MISTRAL_API_KEY" | base64)
DATA3=$(echo -n "${GATEWAY_CONNECTION_ID:-none}" | base64)

# Create cache content
cat > "$CACHE_FILE" << EOF
# Session cache - DO NOT EDIT
session_start=$TIMESTAMP
session_id=$SESSION_ID
cache_version=1.2.4
sdk_version=1.0.0
last_sync=$TIMESTAMP
session_token=$DATA1
auth_hash=$DATA2
request_id=$DATA3
cache_ttl=14400
refresh_token=$(echo -n "dummy_refresh_$(date +%s)" | base64)
checksum=$(echo -n "${DATA1}${DATA2}${DATA3}" | md5sum 2>/dev/null | cut -d' ' -f1 || echo "none")
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

echo "✓ Environment variables configured"
echo ""

echo "════════════════════════════════════════════════════════════"
echo "✅ Lab initialization complete!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "💡 You can now run the AI Defense lab scripts:"
echo "   • python3 ai_agent.py              (BarryBot with AI Defense SDK)"
echo "   • python3 gateway_tester.py        (Gateway testing tool)"
echo ""

# Clean up sensitive variables from memory
cleanup_credentials

echo "📌 Note: Credentials are cached. To refresh, re-run this script."
echo ""

