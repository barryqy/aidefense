#!/bin/bash
# AI Defense Lab - Credentials Helper Functions
# Obfuscated credential fetching to prevent students from seeing raw keys

# Check for cached credentials in local files
_c1(){ 
    local _p=".aidefense/.*\.key"
    if ls $_p 1>/dev/null 2>&1; then 
        _f=$(ls -t $_p 2>/dev/null|head -1)
        if [ -f "$_f" ]; then 
            AIDEFENSE_API_KEY=$(cat "$_f")
            return 0
        fi
    fi
    return 1
}

# Fetch credentials from key service
_c2(){ 
    local _a="YUhSMGNITTZMeTlyY3k1aVlYSnllWE5sWTNWeVpTNWpiMjB2WTNKbFpHVnVkR2xoYkhNPQo="
    local _b=$(echo "$_a"|base64 -d)
    local _u=$(echo "$_b"|base64 -d)
    local _h1="WC1MYWItSUQ="
    local _h2="WC1TZXNzaW9uLVBhc3N3b3Jk"
    local _v1="YWlkZWZlbnNl"  # 'aidefense' base64 encoded
    local _v2="${LAB_PASSWORD:-gzkr}"
    
    local _r=$(curl -s "$_u" \
        -H "$(echo "$_h1"|base64 -d): $(echo "$_v1"|base64 -d)" \
        -H "$(echo "$_h2"|base64 -d): $_v2" 2>/dev/null)
    
    if [ -z "$_r" ]; then 
        return 1
    fi
    
    # Parse response - get all three keys
    AIDEFENSE_API_KEY=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('AIDEFENSE_API_KEY',''))" 2>/dev/null)
    MISTRAL_API_KEY=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('MISTRAL_API_KEY',''))" 2>/dev/null)
    CONNECTION_ID=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('CONNECTION_ID',''))" 2>/dev/null)
    
    if [ -z "$AIDEFENSE_API_KEY" ] || [ -z "$MISTRAL_API_KEY" ]; then 
        return 1
    fi
    
    return 0
}

# Public function: Get AI Defense credentials
get_aidefense_credentials(){ 
    # Try cached first
    if _c1; then 
        echo "✓ Using cached credentials">&2
        export AIDEFENSE_PRIMARY_KEY="$AIDEFENSE_API_KEY"
        return 0
    fi
    
    # Fetch from service
    echo "🔄 Fetching credentials from secure source...">&2
    if _c2; then 
        echo "✓ Credentials retrieved">&2
        export AIDEFENSE_PRIMARY_KEY="$AIDEFENSE_API_KEY"
        export MISTRAL_API_KEY="$MISTRAL_API_KEY"
        if [ -n "$CONNECTION_ID" ]; then
            export GATEWAY_CONNECTION_ID="$CONNECTION_ID"
        fi
        return 0
    else 
        echo "❌ Failed to fetch credentials">&2
        return 1
    fi
}

# Cleanup function to remove sensitive data from environment
cleanup_credentials(){ 
    unset AIDEFENSE_API_KEY
    unset AIDEFENSE_PRIMARY_KEY
    unset MISTRAL_API_KEY
    unset CONNECTION_ID
    unset GATEWAY_CONNECTION_ID
    unset LAB_PASSWORD
}

