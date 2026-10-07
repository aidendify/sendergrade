"""SenderGrade storage + config: SQLite schema, env config, branding settings."""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone

from flask import g, has_app_context

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_name TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE,
  dkim_selectors TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  report_token TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS check_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  kind TEXT NOT NULL,
  domains_checked INTEGER NOT NULL DEFAULT 0,
  changes INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS domain_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER,
  client_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  grade TEXT NOT NULL,
  spf_status TEXT, dkim_status TEXT, dmarc_status TEXT, mx_status TEXT,
  spf_raw TEXT, dmarc_raw TEXT, dkim_found_json TEXT, mx_raw TEXT,
  findings_json TEXT, lookup_count INTEGER,
  effective_json TEXT,
  checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_dc_client ON domain_checks(client_id, id);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER,
  run_id INTEGER,
  domain TEXT NOT NULL DEFAULT '',
  old_grade TEXT, new_grade TEXT,
  summary TEXT NOT NULL,
  delivery_status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_client ON alerts(client_id, id);
CREATE TABLE IF NOT EXISTS leads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', company TEXT NOT NULL DEFAULT '',
  domain TEXT NOT NULL, grade TEXT NOT NULL, findings_json TEXT,
  ip_hash TEXT NOT NULL, consent INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS public_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_pc_time ON public_checks(created_at);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def env_bool(name: str, default: bool) -> bool:
    raw = env(name)
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name) or default)
    except ValueError:
        return default


def database_path() -> str:
    return env("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sendergrade.db"))


def data_dir() -> str:
    return os.path.dirname(os.path.abspath(database_path()))


def connect() -> sqlite3.Connection:
    path = database_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_db() -> sqlite3.Connection:
    if not has_app_context():
        return connect()
    if "db" not in g:
        g.db = connect()
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_schema() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def new_token() -> str:
    return secrets.token_urlsafe(24)


# --------------------------------------------------------------------------- config


def owner_password() -> str:
    return os.environ.get("OWNER_PASSWORD", "")


def secret_key() -> str:
    return env("SECRET_KEY", "sendergrade-change-me")


def public_base_url() -> str:
    return env("PUBLIC_BASE_URL", "http://127.0.0.1:8080").rstrip("/")


def marketing_url() -> str:
    return env("MARKETING_URL")


def smtp_configured() -> bool:
    return bool(env("SMTP_HOST") and env("SMTP_FROM"))


def alert_email() -> str:
    return env("ALERT_EMAIL")


def check_hour_utc() -> int:
    return min(23, max(0, env_int("CHECK_HOUR_UTC", 3)))


def rate_per_hour() -> int:
    return max(1, env_int("PUBLIC_CHECK_RATE_PER_HOUR", 10))


def global_rate_per_hour() -> int:
    return max(1, env_int("PUBLIC_CHECK_GLOBAL_PER_HOUR", 200))


# Branding / public page settings: env gives defaults, Settings page overrides.
BRAND_KEYS = {
    "agency_name": ("AGENCY_NAME", "SenderGrade"),
    "agency_logo_url": ("AGENCY_LOGO_URL", ""),
    "agency_accent_color": ("AGENCY_ACCENT_COLOR", "#1d4e89"),
    "check_headline": (None, "Is your email landing in spam? Check your domain in 10 seconds."),
    "agency_cta_text": ("AGENCY_CTA_TEXT", "Want us to fix this? Book a call"),
    "agency_cta_url": ("AGENCY_CTA_URL", ""),
    "consent_text": (None, "I agree to be contacted about my domain's email setup."),
    "public_check_enabled": (None, "true"),
}


def env_default(key: str) -> str:
    env_name, default = BRAND_KEYS[key]
    return env(env_name, default) if env_name else default


def get_setting(key: str, conn=None) -> str:
    conn = conn or get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row is not None else env_default(key)


def set_setting(key: str, value: str, conn=None) -> None:
    conn = conn or get_db()
    if value == env_default(key):
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    else:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
    conn.commit()


def safe_color(value: str) -> str:
    v = (value or "").strip()
    return v if re.fullmatch(r"#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?", v) else "#1d4e89"


def safe_url(value: str) -> str:
    v = (value or "").strip()
    return v if re.match(r"^https?://", v, re.I) else ""


def branding(conn=None) -> dict:
    vals = {k: get_setting(k, conn) for k in BRAND_KEYS}
    vals["agency_accent_color"] = safe_color(vals["agency_accent_color"])
    vals["agency_logo_url"] = safe_url(vals["agency_logo_url"])
    vals["agency_cta_url"] = safe_url(vals["agency_cta_url"])
    vals["agency_name"] = vals["agency_name"] or "SenderGrade"
    return vals


def public_check_enabled(conn=None) -> bool:
    """Env PUBLIC_CHECK_ENABLED is the master switch; the Settings toggle can only turn it off."""
    if not env_bool("PUBLIC_CHECK_ENABLED", True):
        return False
    return get_setting("public_check_enabled", conn) == "true"
