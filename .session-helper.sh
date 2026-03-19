#!/bin/bash
# AI Defense Lab - Session Helper Functions
# Check for cached session data in local files
_c1(){ 
    local _cache=".aidefense/.cache"
    if [ -f "$_cache" ]; then
        local _token
        _token=$(python3 - <<'PY'
from pathlib import Path

cache_path = Path(".aidefense/.cache")
for line in cache_path.read_text(encoding="utf-8").splitlines():
    if line.startswith("session_token="):
        print(line.split("=", 1)[1].strip())
        break
PY
)

        if [ -n "$_token" ]; then
            local _decoded
            _decoded=$(python3 <<PY
import base64
import os

token = """$_token"""
env_key = os.environ.get("DEVENV_USER", "default-key-fallback").encode()
data = base64.b64decode(token)
key_rep = (env_key * (len(data) // len(env_key) + 1))[:len(data)]
print(bytes(a ^ b for a, b in zip(data, key_rep)).decode("utf-8"))
PY
)

            if [ -n "$_decoded" ]; then
                IFS=':' read -r SESSION_K1 SESSION_K2 SESSION_K3 SESSION_K4 SESSION_K5 <<< "$_decoded"
                return 0
            fi
        fi
    fi

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
    
    # Parse response - keep the legacy five-field payload shape so
    # existing cache readers keep working. Field 2 is now used as a
    # compatibility token for the prebuilt gateway connection.
    SESSION_K1=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('AIDEFENSE_API_KEY',''))" 2>/dev/null)
    SESSION_K2=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('MISTRAL_API_KEY',''))" 2>/dev/null)
    SESSION_K3=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('CONNECTION_ID',''))" 2>/dev/null)
    SESSION_K4=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('GATEWAY_AUTH_TOKEN',''))" 2>/dev/null)
    SESSION_K5=$(echo "$_r"|python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('AIDEFENSE_MGMT_API',''))" 2>/dev/null)
    
    if [ -z "$SESSION_K1" ] || [ -z "$SESSION_K3" ] || [ -z "$SESSION_K5" ]; then
        return 1
    fi
    
    return 0
}

# Public function: Get AI Defense session data
get_aidefense_session(){ 
    # Fetch fresh session data first so short-lived gateway tokens do not
    # get stuck behind an older local cache.
    if _c2; then
        echo "✓ Retrieved fresh session data">&2
        return 0
    fi
    
    if _c1; then
        echo "✓ Using cached session data">&2
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
