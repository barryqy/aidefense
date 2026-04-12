#!/usr/bin/env python3
"""
Shared session cache loader for the AI Defense lab.
Reads and decrypts the session token from .aidefense/.cache.
"""
from typing import Optional, List, Dict
import os
import base64
from lab_llm import direct_model_name

CACHE_FILE = ".aidefense/.cache"
DEFAULT_AIDEFENSE_RUNTIME_BASE_URL = "https://us.api.inspect.aidefense.security.cisco.com/api/v1"
DEFAULT_GATEWAY_MODEL = "mistral-small-latest"

FIELD_POSITIONS: Dict[str, int] = {
    "primary": 0,
    "legacy_llm": 1,
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


def _read_cache_map() -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not os.path.exists(CACHE_FILE):
        return values
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                key, value = raw.split("=", 1)
                values[key] = value
    except Exception:
        return {}
    return values


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
    return get_legacy_connection_key()


def get_legacy_connection_key() -> Optional[str]:
    return get_cached_value("legacy_llm")


def get_lab_llm_api_key() -> Optional[str]:
    return os.environ.get("LLM_API_KEY")


def get_lab_llm_base_url() -> Optional[str]:
    return os.environ.get("LLM_BASE_URL")


def get_lab_llm_model() -> str:
    requested_model = (
        os.environ.get("LLM_MODEL")
        or os.environ.get("OPENAI_MODEL")
        or os.environ.get("MODEL_NAME")
    )
    return direct_model_name(requested_model)


def get_gateway_connection_id() -> Optional[str]:
    return get_cached_value("gateway_connection_id")


def get_gateway_auth_token() -> Optional[str]:
    dedicated_token = get_cached_value("gateway_auth_token")
    if dedicated_token:
        return dedicated_token
    return get_legacy_connection_key()


def get_gateway_auth_source() -> Optional[str]:
    if get_cached_value("gateway_auth_token"):
        return "dedicated"
    if get_legacy_connection_key():
        return "preconfigured_connection_key"
    return None


def get_gateway_model() -> str:
    requested_model = (
        os.environ.get("AIDEFENSE_GATEWAY_MODEL")
        or os.environ.get("GATEWAY_MODEL")
    )
    model_name = (requested_model or "").strip()
    return model_name or DEFAULT_GATEWAY_MODEL


def get_mgmt_api() -> Optional[str]:
    return get_cached_value("mgmt_api")


def get_aidefense_runtime_base_url() -> str:
    return _read_cache_map().get("aidefense_runtime_base_url") or DEFAULT_AIDEFENSE_RUNTIME_BASE_URL


def get_aidefense_real_runtime_base_url() -> str:
    return _read_cache_map().get("aidefense_real_runtime_base_url") or get_aidefense_runtime_base_url()


def get_aidefense_notice() -> Optional[str]:
    notice_b64 = _read_cache_map().get("aidefense_runtime_notice_b64")
    if not notice_b64:
        return None
    try:
        return base64.b64decode(notice_b64).decode("utf-8")
    except Exception:
        return None
