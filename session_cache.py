#!/usr/bin/env python3
"""
Shared session cache loader for the AI Defense lab.
Reads and decrypts the session token from .aidefense/.cache.
"""
from typing import Optional, List, Dict
import os
import base64

CACHE_FILE = ".aidefense/.cache"

FIELD_POSITIONS: Dict[str, int] = {
    "primary": 0,
    "mistral": 1,
    "gateway_connection_id": 2,
    "gateway_auth_token": 3,
    "mgmt_api": 4,
}


def _get_session_token() -> Optional[str]:
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("session_token="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return None


def _decode_session_token(token: str) -> Optional[str]:
    try:
        env_key = os.environ.get("DEVENV_USER", "default-key-fallback")
        data = base64.b64decode(token)
        key_rep = (env_key * (len(data) // len(env_key) + 1))[:len(data)]
        return bytes(a ^ b for a, b in zip(data, key_rep.encode())).decode("utf-8")
    except Exception:
        return None


def load_session_parts() -> Optional[List[str]]:
    token = _get_session_token()
    if not token:
        return None
    plaintext = _decode_session_token(token)
    if not plaintext:
        return None
    return plaintext.split(":")


def get_cached_value(field_name: str) -> Optional[str]:
    position = FIELD_POSITIONS.get(field_name)
    if position is None:
        return None
    parts = load_session_parts()
    if not parts or position >= len(parts):
        return None
    value = parts[position]
    if not value or value == "none":
        return None
    return value


def get_primary_key() -> Optional[str]:
    return get_cached_value("primary")


def get_mistral_key() -> Optional[str]:
    return get_cached_value("mistral")


def get_gateway_connection_id() -> Optional[str]:
    return get_cached_value("gateway_connection_id")


def get_gateway_auth_token() -> Optional[str]:
    return get_cached_value("gateway_auth_token")


def get_mgmt_api() -> Optional[str]:
    return get_cached_value("mgmt_api")
