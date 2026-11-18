"""API key guard primitives.

The rules implemented here are deliberately fail-closed:

* keys are stored as deterministic hashes, never as plaintext;
* keys carry an environment prefix so tokens from one environment cannot be
  replayed into another;
* every key is bound to exactly one tenant;
* wildcard scopes are rejected in both the requested and the granted set;
* an expiry is mandatory -- a key without one is never active;
* revocation mutates the persisted record (``active=False``) rather than only
  dropping a cache entry;
* rotation invalidates the old key (optionally after a bounded grace window);
* credentials are rejected when carried in a URL;
* ``key_active`` / ``scope_allowed`` are pure per-call checks, so a key is
  re-authorised on every request instead of trusting a cached decision;
* :func:`scan_logs` applies the same URL detection to log lines, closing the
  "scan code but not logs" gap.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional, Union

__all__ = [
    "hash_key",
    "verify_key",
    "scope_allowed",
    "key_active",
    "revoke",
    "rotate",
    "tenant_match",
    "contains_key_in_url",
    "contains_key_in_log",
    "scan_logs",
    "issue_key",
    "environment_of",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Environment prefixes. A key issued for ``live`` can never authenticate in
#: ``test`` (and vice versa) because the prefix is part of the raw key and is
#: checked before any database lookup.
ENVIRONMENT_PREFIXES = {
    "dev": "ak_dev_",
    "test": "ak_test_",
    "staging": "ak_staging_",
    "live": "ak_live_",
}

#: Parameter names that indicate a credential is travelling in a URL. These
#: end up in access logs, proxies, browser history and referrer headers, so
#: they are always rejected.
_URL_KEY_PARAM_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "key",
        "token",
        "access_token",
        "accesstoken",
        "access-token",
        "auth",
        "auth_token",
        "x-api-key",
        "x_api_key",
    }
)

_URL_CREDENTIAL_RE = re.compile(
    r"(?:[?&;#]|^)"
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|x[_-]api[_-]key|token|key|auth)"
    r"=",
    re.IGNORECASE,
)

_WILDCARD = "*"

_TEXT_LIKE = (str, bytes, bytearray)


# ---------------------------------------------------------------------------
# Key storage
# ---------------------------------------------------------------------------


def _as_bytes(value: Union[str, bytes, bytearray]) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value.encode("utf-8")


def hash_key(
    key: Union[str, bytes, bytearray],
    salt: Union[str, bytes, bytearray, None] = None,
) -> str:
    """Return a stable, non-reversible representation of *key*.

    The function is deterministic (the same key and salt always produce the
    same digest) so a stored hash can be looked up, but the plaintext key is
    never persisted. An optional *salt* is mixed in before hashing; callers
    that use a shared salt can still look keys up by hash.
    """

    if not isinstance(key, (str, bytes, bytearray)):
        raise TypeError("key must be str or bytes")
    if not key:
        raise ValueError("key must not be empty")

    payload = _as_bytes(key)
    if salt is not None:
        if not isinstance(salt, (str, bytes, bytearray)):
            raise TypeError("salt must be str or bytes")
        payload = _as_bytes(salt) + b"\x00" + payload

    return hashlib.sha256(payload).hexdigest()


def verify_key(
    candidate: Union[str, bytes, bytearray],
    stored_hash: str,
    salt: Union[str, bytes, bytearray, None] = None,
) -> bool:
    """Constant-time comparison of a presented key against a stored hash."""

    if not stored_hash or not isinstance(candidate, (str, bytes, bytearray)):
        return False
    try:
        computed = hash_key(candidate, salt=salt)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(computed, stored_hash)


# ---------------------------------------------------------------------------
# Environment prefix
# ---------------------------------------------------------------------------


def issue_key(
    environment: str,
    secret: Optional[str] = None,
) -> str:
    """Build a raw key carrying an environment prefix.

    ``issue_key("live")`` -> ``ak_live_<random>``. Persist only
    ``hash_key(issue_key(...))``; the raw value is shown to the caller once.
    """

    if environment not in ENVIRONMENT_PREFIXES:
        raise ValueError(f"unknown environment: {environment!r}")
    if secret is None:
        secret = secrets.token_urlsafe(32)
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty str")
    return ENVIRONMENT_PREFIXES[environment] + secret


def environment_of(key: Union[str, bytes, bytearray]) -> Optional[str]:
    """Return the environment encoded in a raw key, or ``None`` if unknown."""

    if isinstance(key, (bytes, bytearray)):
        try:
            key = bytes(key).decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(key, str):
        return None
    for environment, prefix in ENVIRONMENT_PREFIXES.items():
        if key.startswith(prefix):
            return environment
    return None


# ---------------------------------------------------------------------------
# Scope checks
# ---------------------------------------------------------------------------


def _normalise_scopes(granted: Any) -> set:
    if granted is None:
        return set()
    if isinstance(granted, str):
        return {part.strip() for part in granted.split(",") if part.strip()}
    if isinstance(granted, Iterable):
        return {scope for scope in granted if isinstance(scope, str) and scope}
    return set()


def scope_allowed(scope: Any, granted_scopes: Any) -> bool:
    """Return whether *scope* is explicitly granted.

    Fails closed on empty scopes and on wildcards: neither ``"*"`` as the
    requested scope nor a granted set containing ``"*"`` (or a glob such as
    ``"read*"``) is accepted.
    """

    if not isinstance(scope, str):
        return False
    scope = scope.strip()
    if not scope or _WILDCARD in scope:
        return False

    granted = _normalise_scopes(granted_scopes)
    # A wildcard grant would silently expand to every permission; refuse it
    # rather than returning a misleading True.
    if any(_WILDCARD in item for item in granted if isinstance(item, str)):
        return False

    return scope in granted


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def _coerce_expiry(expires: Any) -> Optional[float]:
    if expires is None:
        return None
    if isinstance(expires, bool):
        return None
    if isinstance(expires, (int, float)):
        return float(expires)
    if isinstance(expires, datetime):
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires.timestamp()
    return None


def key_active(record: Mapping[str, Any], now: Optional[float] = None) -> bool:
    """Return whether *record* is currently usable.

    All of the following must hold, checked on every call (no caching):

    * the record is marked active;
    * it has not been revoked;
    * it has a non-``None`` expiry in the future (expiry is mandatory).
    """

    if not isinstance(record, Mapping):
        return False
    if record.get("revoked") is True:
        return False
    if record.get("active") is not True:
        return False

    expires = _coerce_expiry(record.get("expires"))
    if expires is None:
        # No expiry means the key would live forever; fail closed.
        return False

    if now is None:
        now_value = time.time()
    elif isinstance(now, datetime):
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        now_value = now.timestamp()
    elif isinstance(now, bool) or not isinstance(now, (int, float)):
        return False
    else:
        now_value = float(now)

    return now_value < expires


def revoke(
    record: Mapping[str, Any],
    now: Optional[float] = None,
    *,
    store: Optional[dict] = None,
    key_id: Any = None,
) -> dict:
    """Revoke *record* in place and return the updated, persisted record.

    Revocation is written to the record itself (``active`` becomes ``False``
    and ``revoked`` becomes ``True``) instead of merely dropping a cache
    entry, so a database read still sees the key as invalid. When *store* and
    *key_id* are supplied the updated copy is also written back to the store.
    """

    updated = dict(record)
    updated["active"] = False
    updated["revoked"] = True
    updated["revoked_at"] = time.time() if now is None else now

    if store is not None and key_id is not None:
        store[key_id] = updated

    return updated


def rotate(
    record: Mapping[str, Any],
    grace_seconds: float = 0,
    now: Optional[float] = None,
) -> dict:
    """Rotate *record*, invalidating the old key.

    By default the old key stops being active immediately (``old_active`` is
    ``False``). A caller may request a small, bounded *grace_seconds* window
    during which the old key keeps working; the window is recorded in
    ``grace_until`` and is never open-ended. A freshly generated replacement
    key is returned alongside its hash; only the hash should be persisted.
    """

    if isinstance(grace_seconds, bool) or not isinstance(grace_seconds, (int, float)):
        raise TypeError("grace_seconds must be a number")
    grace_seconds = max(0.0, float(grace_seconds))

    now_value = time.time() if now is None else float(now)
    grace_until = now_value + grace_seconds
    old_active = grace_seconds > 0

    new_key = secrets.token_urlsafe(32)

    updated = dict(record)
    updated["old_active"] = old_active
    updated["rotated"] = True
    updated["rotated_at"] = now_value
    updated["grace_until"] = grace_until
    updated["new_key"] = new_key
    updated["new_key_hash"] = hash_key(new_key)

    if old_active:
        updated["active"] = record.get("active") is True
    else:
        # Outside a grace window the old key is dead immediately.
        updated["active"] = False
        updated["revoked"] = True

    return updated


# ---------------------------------------------------------------------------
# Tenant binding
# ---------------------------------------------------------------------------


def tenant_match(key_tenant: Any, request_tenant: Any) -> bool:
    """Return whether a key issued for *key_tenant* may serve *request_tenant*.

    Tenant ids must be non-empty strings and must match exactly. ``None``,
    empty values and wildcards never match, preventing a key from drifting
    across tenants.
    """

    if not isinstance(key_tenant, str) or not isinstance(request_tenant, str):
        return False

    key_tenant = key_tenant.strip()
    request_tenant = request_tenant.strip()

    if not key_tenant or not request_tenant:
        return False
    if _WILDCARD in key_tenant or _WILDCARD in request_tenant:
        return False

    return hmac.compare_digest(key_tenant, request_tenant)


# ---------------------------------------------------------------------------
# URL / log leakage
# ---------------------------------------------------------------------------


def contains_key_in_url(url: Any) -> bool:
    """Return ``True`` if *url* carries a credential in a loggable position.

    Detects credentials in the query string or fragment (for example
    ``?api_key=...``), as well as a password in the URL userinfo component.
    Putting a key in a URL leaks it into access logs, proxies, referrer
    headers and browser history, so such URLs are rejected.
    """

    if not isinstance(url, str) or not url:
        return False

    if _URL_CREDENTIAL_RE.search(url):
        return True

    # ``urlsplit`` normalises query/fragment parsing; malformed input simply
    # falls back to the regex check above.
    try:
        from urllib.parse import parse_qsl, urlsplit

        parts = urlsplit(url)
    except (ValueError, TypeError):
        return False

    for name, _value in parse_qsl(parts.query, keep_blank_values=True):
        if name.strip().lower() in _URL_KEY_PARAM_NAMES:
            return True
    for name, _value in parse_qsl(parts.fragment, keep_blank_values=True):
        if name.strip().lower() in _URL_KEY_PARAM_NAMES:
            return True

    # ``https://user:secret@host/`` also puts a credential in the URL.
    netloc = parts.netloc
    if "@" in netloc:
        userinfo = netloc.rsplit("@", 1)[0]
        if ":" in userinfo and userinfo.split(":", 1)[1]:
            return True

    return False


def contains_key_in_log(line: Any) -> bool:
    """Return ``True`` if a log line appears to contain leaked key material."""

    if not isinstance(line, str) or not line:
        return False
    if contains_key_in_url(line):
        return True
    # Also catch bare credential assignments written to logs, e.g.
    # ``Authorization: Bearer ...`` or ``api_key=...`` outside a URL.
    return bool(
        re.search(
            r"(?:authorization\s*[:=]\s*(?:bearer|basic)\s+\S+"
            r"|(?:api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S+)",
            line,
            re.IGNORECASE,
        )
    )


def scan_logs(lines: Iterable[Any]) -> list:
    """Return the log lines that contain leaked credentials.

    This closes the gap where secret scanning only inspects source code:
    credentials can leak through runtime logs even when the code is clean.
    """

    findings = []
    for line in lines:
        if contains_key_in_log(line):
            findings.append(line)
    return findings
