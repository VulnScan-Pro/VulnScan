# ai_providers.py
"""
AI provider abstraction with encrypted API key storage.

Providers supported:
  • Groq      (openai/gpt-oss-120b)
  • OpenAI    (gpt-5.4-mini)
  • Anthropic (claude-sonnet-4.5)
  • Mistral   (mistral-medium-3-5)
  • DeepSeek  (deepseek-v4-flash)

Fixes applied:
  C4 — API keys encrypted at rest (Fernet, keyed from SECRET_KEY)
  M5 — Mistral reuses the OpenAI client with a different base_url
  M6 — masked keys show only provider prefix
  H3 — no bare except: pass; failures logged
  M8 — timestamps compared as UTC epochs

This revision:
  • Model IDs updated to current, supported versions.
  • Every provider retries transient errors (429, 500, 502, 503, 504)
    with exponential backoff (1s → 2s → 4s, 3 attempts max).
  • Non-retryable errors (400, 401, 403) raise immediately.
"""

import base64
import hashlib
import logging
import sqlite3
import time

from openai import OpenAI
import anthropic
from groq import Groq

import config

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared retry helper
# ---------------------------------------------------------------------------
RETRYABLE_MARKERS = ("429", "500", "502", "503", "504",
                     "rate limit", "rate_limit", "overloaded",
                     "temporarily unavailable", "timeout")


def _is_retryable(exc: Exception) -> bool:
    """Heuristic: is this error transient (worth retrying)?"""
    msg = str(exc).lower()
    return any(marker in msg for marker in RETRYABLE_MARKERS)


def _call_with_retry(fn, max_retries=3, base_delay=1.0):
    """
    Call fn() and retry on transient errors.
    Delays: base_delay, 2*base_delay, 4*base_delay (e.g. 1s, 2s, 4s).
    """
    last_exc = None
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            retryable = _is_retryable(exc)
            if not retryable or attempt == max_retries - 1:
                raise
            delay = base_delay * (2 ** attempt)
            log.warning(
                "[retry] %s on attempt %d/%d — sleeping %.1fs",
                type(exc).__name__, attempt + 1, max_retries, delay,
            )
            time.sleep(delay)
    if last_exc:
        raise last_exc


# ---------------------------------------------------------------------------
# Fernet encryption
# ---------------------------------------------------------------------------
try:
    from cryptography.fernet import Fernet, InvalidToken
    _FERNET = Fernet(base64.urlsafe_b64encode(
        hashlib.sha256(config.SECRET_KEY.encode()).digest()
    ))
    _ENCRYPTION_AVAILABLE = True
except ImportError:
    _FERNET = None
    _ENCRYPTION_AVAILABLE = False
    log.warning(
        "[ai_providers] cryptography not installed — API keys stored in plaintext. "
        "Run: pip install cryptography"
    )


def _encrypt(value: str) -> str:
    if not _ENCRYPTION_AVAILABLE:
        return value
    return _FERNET.encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    if not _ENCRYPTION_AVAILABLE:
        return value
    try:
        return _FERNET.decrypt(value.encode()).decode()
    except InvalidToken:
        log.error("[ai_providers] failed to decrypt API key (SECRET_KEY changed?)")
        return ""


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_tables(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS api_keys (provider TEXT UNIQUE, api_key TEXT)")
    c.execute(
        "CREATE TABLE IF NOT EXISTS active_provider "
        "(id INTEGER PRIMARY KEY, provider TEXT)"
    )


# ---------------------------------------------------------------------------
# Provider classes — all use _call_with_retry
# ---------------------------------------------------------------------------
class GroqProvider:
    def __init__(self, api_key):
        self.client = Groq(api_key=api_key)

    def generate(self, system_prompt, user_prompt, max_tokens=1000, temperature=0.5):
        def _call():
            return self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model="openai/gpt-oss-120b",
                max_tokens=max_tokens,
                temperature=temperature,
            )
        res = _call_with_retry(_call)
        return res.choices[0].message.content


class OpenAIProvider:
    def __init__(self, api_key):
        self.client = OpenAI(api_key=api_key)

    def generate(self, system_prompt, user_prompt, max_tokens=1000, temperature=0.5):
        def _call():
            return self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model="gpt-5.4-mini",
                max_tokens=max_tokens,
                temperature=temperature,
            )
        res = _call_with_retry(_call)
        return res.choices[0].message.content


class DeepSeekProvider:
    def __init__(self, api_key):
        self.client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1")

    def generate(self, system_prompt, user_prompt, max_tokens=1000, temperature=0.5):
        def _call():
            return self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model="deepseek-v4-flash",
                max_tokens=max_tokens,
                temperature=temperature,
            )
        res = _call_with_retry(_call)
        return res.choices[0].message.content


class AnthropicProvider:
    def __init__(self, api_key):
        self.client = anthropic.Anthropic(api_key=api_key)

    def generate(self, system_prompt, user_prompt, max_tokens=1000, temperature=0.5):
        def _call():
            return self.client.messages.create(
                model="claude-sonnet-4.5",
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
        res = _call_with_retry(_call)
        return res.content[0].text


class MistralProvider:
    """
    Mistral uses an OpenAI-compatible endpoint.
    Docs: https://docs.mistral.ai/
    Base URL: https://api.mistral.ai/v1
    """
    def __init__(self, api_key):
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.mistral.ai/v1",
        )

    def generate(self, system_prompt, user_prompt, max_tokens=1000, temperature=0.5):
        def _call():
            return self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model="mistral-medium-3-5",
                max_tokens=max_tokens,
                temperature=temperature,
            )
        res = _call_with_retry(_call)
        return res.choices[0].message.content


# ---------------------------------------------------------------------------
# Key CRUD
# ---------------------------------------------------------------------------
def save_api_key(provider, key):
    if provider not in config.ALLOWED_PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    conn = get_db()
    try:
        _ensure_tables(conn)
        enc = _encrypt(key)
        conn.execute(
            "INSERT OR REPLACE INTO api_keys (provider, api_key) VALUES (?, ?)",
            (provider, enc),
        )
        conn.commit()
    finally:
        conn.close()


def get_api_key(provider):
    if provider not in config.ALLOWED_PROVIDERS:
        return None
    conn = get_db()
    try:
        _ensure_tables(conn)
        row = conn.execute(
            "SELECT api_key FROM api_keys WHERE provider=?", (provider,)
        ).fetchone()
    except sqlite3.Error as e:
        log.warning("[ai_providers] get_api_key: %s", e)
        row = None
    finally:
        conn.close()
    if not row:
        return None
    return _decrypt(row["api_key"])


def get_masked_keys():
    conn = get_db()
    out = {}
    try:
        _ensure_tables(conn)
        for row in conn.execute("SELECT provider, api_key FROM api_keys"):
            plain = _decrypt(row["api_key"])
            out[row["provider"]] = (plain[:3] + "***") if plain else "***"
    except sqlite3.Error as e:
        log.warning("[ai_providers] get_masked_keys: %s", e)
    finally:
        conn.close()
    return out


def delete_api_key(provider):
    conn = get_db()
    try:
        _ensure_tables(conn)
        conn.execute("DELETE FROM api_keys WHERE provider=?", (provider,))
        conn.commit()
    finally:
        conn.close()
    if get_active_provider() == provider:
        set_active_provider(None)


# ---------------------------------------------------------------------------
# Active provider
# ---------------------------------------------------------------------------
def set_active_provider(provider):
    if provider is not None and provider not in config.ALLOWED_PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    conn = get_db()
    try:
        _ensure_tables(conn)
        conn.execute(
            "INSERT OR REPLACE INTO active_provider (id, provider) VALUES (1, ?)",
            (provider,),
        )
        conn.commit()
    finally:
        conn.close()


def get_active_provider():
    conn = get_db()
    try:
        _ensure_tables(conn)
        row = conn.execute(
            "SELECT provider FROM active_provider WHERE id=1"
        ).fetchone()
    except sqlite3.Error as e:
        log.warning("[ai_providers] get_active_provider: %s", e)
        row = None
    finally:
        conn.close()
    return row["provider"] if row and row["provider"] else None


def get_ai_provider():
    provider = get_active_provider()
    if not provider:
        return None
    key = get_api_key(provider)
    if not key:
        return None
    try:
        if provider == "groq":
            return GroqProvider(key)
        if provider == "openai":
            return OpenAIProvider(key)
        if provider == "anthropic":
            return AnthropicProvider(key)
        if provider == "mistral":
            return MistralProvider(key)
        if provider == "deepseek":
            return DeepSeekProvider(key)
    except Exception:
        log.exception("[ai_providers] failed to instantiate %s", provider)
        raise
    return None