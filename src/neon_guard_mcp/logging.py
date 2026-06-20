"""Logging setup with secret redaction.

All logging goes to STDERR only — stdout is the MCP JSON-RPC channel.
A redaction filter scrubs secret shapes (Neon API keys, Bearer tokens,
and postgresql:// credentials) from every log record before it is emitted.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

# Neon API keys look like "napi_<token>"; allow '-'/'_' in the body too.
_NAPI_RE = re.compile(r"napi_[A-Za-z0-9_-]+")
# "Bearer <token>" in any casing (e.g. authorization header dumps).
_BEARER_RE = re.compile(r"bearer\s+\S+", re.IGNORECASE)
# postgres:// OR postgresql:// (any case): mask the whole userinfo up to the
# host. Greedy to the last '@' so a password that itself contains '@' is still
# fully masked. Over-masking is acceptable; under-masking a credential is not.
_PG_RE = re.compile(r"(postgres(?:ql)?://)[^\s]*@", re.IGNORECASE)
# Keyword credential forms that carry no '@': libpq key/value DSNs and URI query
# strings, e.g. "password=secret", "PGPASSWORD: secret", "?sslpassword=secret".
_KV_PW_RE = re.compile(
    r"(?i)((?:pg|ssl)?password['\"]?\s*[=:]\s*['\"]?)([^\s&;'\"]+)"
)


def redact(text: str) -> str:
    """Replace secret shapes in *text* with masked placeholders. Pure."""
    text = _NAPI_RE.sub("napi_***", text)
    text = _BEARER_RE.sub("Bearer ***", text)
    text = _PG_RE.sub(r"\1***@", text)
    text = _KV_PW_RE.sub(r"\1***", text)
    return text


def _redact_args(args: Any) -> Any:
    """Recursively redact strings inside log args (tuple/list/dict/str)."""
    if isinstance(args, dict):
        return {k: _redact_args(v) for k, v in args.items()}
    if isinstance(args, (list, tuple)):
        return type(args)(_redact_args(v) for v in args)
    if isinstance(args, str):
        return redact(args)
    return args


_EXC_FORMATTER = logging.Formatter()


class _RedactionFilter(logging.Filter):
    """Scrub secret shapes from a record's message, args, and traceback.

    Covers the common message path, nested container args, a non-str message
    object whose str() carries a secret, and a rendered exc_info traceback.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        elif not record.args:
            record.msg = redact(str(record.msg))
        if record.args:
            record.args = _redact_args(record.args)
        if record.exc_info and not record.exc_text:
            # Pre-render the traceback redacted so the handler's Formatter reuses
            # it instead of re-rendering the raw (secret-bearing) exception.
            record.exc_text = redact(_EXC_FORMATTER.formatException(record.exc_info))
        elif record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def setup_logging(level: int = logging.INFO) -> None:
    """Route the root logger to a single stderr handler with redaction.

    Replaces any existing handlers so nothing can leak to stdout.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(_RedactionFilter())
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # Defense in depth: FastMCP's own logger uses a separate handler and does
    # not propagate to root, so scrub records it emits directly too.
    logging.getLogger("fastmcp").addFilter(_RedactionFilter())


def get_logger(name: str) -> logging.Logger:
    """Return a named logger (configured via setup_logging)."""
    return logging.getLogger(name)
