"""Secrets must never reach logs, errors, or the LLM-facing surface."""

from __future__ import annotations

import logging

import pytest

from neon_guard_mcp.logging import _RedactionFilter, get_logger, redact, setup_logging
from neon_guard_mcp.neon_client import NeonAPIError

API_KEY = "napi_abc123DEF456ghi789"
URI = "postgresql://app_owner:s3cr3tPassw0rd@ep-cool-host.neon.tech/appdb"


def test_redact_removes_napi_key():
    out = redact(f"using key {API_KEY} now")
    assert API_KEY not in out
    assert "abc123DEF456ghi789" not in out
    assert "napi_***" in out


def test_redact_removes_bearer_token():
    out = redact("Authorization: Bearer napi_secretToken12345")
    assert "napi_secretToken12345" not in out
    assert "secretToken12345" not in out
    assert "Bearer ***" in out


def test_redact_removes_bearer_case_insensitive():
    out = redact("authorization: bearer SuperSecretToken")
    assert "SuperSecretToken" not in out
    assert "Bearer ***" in out


def test_redact_removes_postgres_credentials():
    out = redact(f"connect to {URI}")
    assert "s3cr3tPassw0rd" not in out
    assert "app_owner" not in out
    assert "postgresql://***@" in out
    # The non-secret host/db tail may remain; only the userinfo is scrubbed.
    assert "ep-cool-host.neon.tech/appdb" in out


def test_redact_is_pure_and_noop_on_clean_text():
    clean = "branch ai-test-feature created with id br-new"
    assert redact(clean) == clean


def test_neon_api_error_never_contains_api_key():
    # Even if an upstream message somehow embedded a key, str() must be safe to
    # surface — and at minimum, constructing an error never leaks the master key.
    err = NeonAPIError(403, "forbidden")
    text = str(err)
    assert API_KEY not in text
    assert "napi_" not in text
    assert err.status_code == 403
    assert err.message == "forbidden"
    assert "403" in text


def test_neon_api_error_redacts_embedded_secret():
    # Defense in depth: even if an upstream payload echoed a credential, the
    # error must scrub it on construction (str() and .message both safe).
    err = NeonAPIError(401, "token Bearer napi_abc123XYZ is invalid")
    assert "napi_abc123XYZ" not in str(err)
    assert "napi_abc123XYZ" not in err.message
    assert err.status_code == 401


def test_logging_redacts_secret_in_stderr_record(caplog):
    log = get_logger("neon_guard_mcp.test")
    # The real stderr handler installed by setup_logging carries the redaction
    # filter; caplog's own handler does not, so attach one to reproduce exactly
    # what would be emitted to stderr.
    caplog.handler.addFilter(_RedactionFilter())
    with caplog.at_level(logging.INFO, logger="neon_guard_mcp.test"):
        # Secrets passed as %s args (the common case) must be scrubbed.
        log.info("minted connection %s for branch", URI)
        log.info("master key leaked: %s", "napi_leakedKeyValue999")
        # ...and secrets embedded directly in the message string.
        log.info("authorization header was Bearer napi_inlineSecretXYZ")

    text = caplog.text
    assert "s3cr3tPassw0rd" not in text
    assert "app_owner" not in text
    assert "napi_leakedKeyValue999" not in text
    assert "leakedKeyValue999" not in text
    assert "napi_inlineSecretXYZ" not in text
    assert "inlineSecretXYZ" not in text
    assert "postgresql://***@" in text
    assert "Bearer ***" in text
    assert "napi_***" in text


def test_redaction_filter_scrubs_record_args_directly():
    filt = _RedactionFilter()
    record = logging.LogRecord(
        name="x",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="uri=%s",
        args=(URI,),
        exc_info=None,
    )
    filt.filter(record)
    rendered = record.getMessage()
    assert "s3cr3tPassw0rd" not in rendered
    assert "postgresql://***@" in rendered


def test_setup_logging_targets_stderr_only():
    setup_logging(logging.INFO)
    root = logging.getLogger()
    assert len(root.handlers) == 1
    handler = root.handlers[0]
    assert isinstance(handler, logging.StreamHandler)
    # stdout is the MCP JSON-RPC channel; logs must go to stderr.
    import sys

    assert handler.stream is sys.stderr
    # The redaction filter is the single most important security invariant on
    # the logging path; assert it is actually installed so a regression that
    # drops addFilter() cannot pass silently.
    assert any(isinstance(f, _RedactionFilter) for f in handler.filters)


# --- adversarial redaction: the shapes a real attacker would try ----------

@pytest.mark.parametrize(
    "secret, dsn",
    [
        ("s3cr3tPassw0rd", "postgres://app_owner:s3cr3tPassw0rd@ep-x.neon.tech/db"),
        ("Pa55word", "POSTGRESQL://u:Pa55word@host/db"),
        ("p@ssw0rd", "postgresql://user:p@ssw0rd@host/db"),
        ("d33p", "postgresql://app:d33p@ep-y.neon.tech/db?sslmode=require"),
    ],
)
def test_redact_masks_dsn_credential_variants(secret, dsn):
    # postgres:// alias, mixed-case scheme, and '@' inside the password must all
    # be masked — a Neon error message can echo any of these shapes.
    out = redact(f"neon said: {dsn}")
    assert secret not in out
    assert "***@" in out


@pytest.mark.parametrize(
    "text, secret",
    [
        ("connection failed: password=hunter2 host=ep.neon.tech", "hunter2"),
        ("dsn ?sslmode=require&password=topSecret123", "topSecret123"),
        ("PGPASSWORD=raw_pw_here port=5432", "raw_pw_here"),
        ("libpq said password: 's3cret!' nope", "s3cret!"),
    ],
)
def test_redact_masks_keyword_password_forms(text, secret):
    # Credential keyword shapes that carry no '@' (query strings, key/value DSNs).
    out = redact(text)
    assert secret not in out
    assert "***" in out


def test_redact_masks_napi_key_with_separators():
    out = redact("key napi_AbC-12_34xyz done")
    assert "AbC-12_34xyz" not in out
    assert "napi_***" in out


def test_redaction_filter_handles_non_str_msg():
    class _Carrier:
        def __str__(self) -> str:
            return URI

    rec = logging.LogRecord("x", logging.INFO, __file__, 1, _Carrier(), None, None)
    _RedactionFilter().filter(rec)
    assert "s3cr3tPassw0rd" not in rec.getMessage()


def test_redaction_filter_scrubs_nested_container_args():
    rec = logging.LogRecord(
        "x", logging.INFO, __file__, 1, "items=%s", ([URI, "ok"],), None
    )
    _RedactionFilter().filter(rec)
    assert "s3cr3tPassw0rd" not in rec.getMessage()


def test_redaction_filter_redacts_exc_info_traceback():
    import sys

    try:
        raise ValueError(f"dsn {URI} key {API_KEY}")
    except ValueError:
        rec = logging.LogRecord(
            "x", logging.ERROR, __file__, 1, "boom", None, sys.exc_info()
        )
    _RedactionFilter().filter(rec)
    text = logging.Formatter("%(message)s").format(rec)
    assert "s3cr3tPassw0rd" not in text
    assert API_KEY not in text
