#!/bin/bash
# AI Defense Lab - Session Helper Functions
# Check for cached session data in local files
_c1(){ 
    local _p=".aidefense/.*\.key"
    if ls $_p 1>/dev/null 2>&1; then 
        _f=$(ls -t $_p 2>/dev/null|head -1)
        if [ -f "$_f" ]; then 
            SESSION_K1=$(cat "$_f")
            return 0
        fi
    fi
    return 1
}

# Fetch session data from key service
_c2(){ 
    local _a="YUhSMGNITTZMeTlyY3k1aVlYSnllWE5sWTNWeVpTNWpiMjB2WTNKbFpHVnVkR2xoYkhNPQo="
    local _b=$(echo "$_a"|base64 -d)
    local _u=$(echo "$_b"|base64 -d)
    local _h1="WC1MYWItSUQ="
    local _h2="WC1TZXNzaW9uLVBhc3N3b3Jk"
    local _v1="YWlkZWZlbnNl"  # 'aidefense' base64 encoded
    local _v2="${LAB_PASSWORD}"
    
    local _r=$(curl -s "$_u" \
        -H "$(echo "$_h1"|base64 -d): $(echo "$_v1"|base64 -d)" \
        -H "$(echo "$_h2"|base64 -d): $_v2" 2>/dev/null)
    
    if [ -z "$_r" ]; then 
        return 1
    fi
    
    # Parse response - get all five keys
    SESSION_K1=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('AIDEFENSE_API_KEY',''))" 2>/dev/null)
    SESSION_K2=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('MISTRAL_API_KEY',''))" 2>/dev/null)
    SESSION_K3=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('CONNECTION_ID',''))" 2>/dev/null)
    SESSION_K4=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('GATEWAY_AUTH_TOKEN',''))" 2>/dev/null)
    SESSION_K5=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('AIDEFENSE_MGMT_API',''))" 2>/dev/null)
    
    if [ -z "$SESSION_K1" ] || [ -z "$SESSION_K2" ]; then 
        return 1
    fi
    
    return 0
}

# Public function: Get AI Defense session data
get_aidefense_session(){ 
    # Try cached first
    if _c1; then 
        echo "✓ Using cached session data">&2
        return 0
    fi
    
    # Fetch from service
    echo "🔄 Fetching session data from secure source...">&2
    if _c2; then 
        echo "✓ Session data retrieved">&2
        return 0
    else 
        echo "❌ Failed to fetch session data">&2
        return 1
    fi
}

# Cleanup function to remove sensitive data from environment
cleanup_session(){ 
    unset SESSION_K1
    unset SESSION_K2
    unset SESSION_K3
    unset SESSION_K4
    unset SESSION_K5
    unset LAB_PASSWORD
}
