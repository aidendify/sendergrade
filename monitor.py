"""SenderGrade runs: check all domains, change detection, alerts, email, scheduler."""

from __future__ import annotations

import fcntl
import json
import os
import smtplib
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import checks as C
import db as D

LABEL = {"spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC", "mx": "MX"}
NOT_SENT = "not_sent_smtp_unconfigured"


# --------------------------------------------------------------------------- email


def send_email(to_addr: str, subject: str, body: str) -> None:
    host = D.env("SMTP_HOST")
    sender = D.env("SMTP_FROM")
    if not (host and sender):
        raise RuntimeError("SMTP is not configured")
    port = D.env_int("SMTP_PORT", 587)
    user = D.env("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD", "")
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    if port == 465:
        smtp = smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context())
    else:
        smtp = smtplib.SMTP(host, port, timeout=20)
    with smtp:
        if port != 465 and D.env_bool("SMTP_STARTTLS", True):
            smtp.starttls(context=ssl.create_default_context())
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)


def deliver(subject: str, body: str) -> str:
    """Send to ALERT_EMAIL if possible; return a delivery_status string."""
    if not D.smtp_configured():
        return NOT_SENT
    to_addr = D.alert_email()
    if not to_addr:
        return "not_sent_no_alert_email"
    try:
        send_email(to_addr, subject, body)
        return "sent"
    except Exception as exc:  # report, never crash a run
        return f"send_failed: {str(exc)[:120]}"


# --------------------------------------------------------------------------- storage helpers


def dkim_text(found: list[dict]) -> str:
    return "\n".join(f"{f['selector']}: {f.get('record', '')}" for f in sorted(found, key=lambda x: x["selector"]))


def raw_for(result: dict, check: str) -> str:
    if check == "dkim":
        return dkim_text(result["dkim"].get("found", []))
    return result[check].get("raw", "") or ""


def effective_state(domain: str, result: dict, prev_eff: dict | None) -> dict:
    """Comparison state. A check in DNS 'error' carries forward the previous value
    so resolver timeouts never flap alerts."""
    eff = {"domain": domain}
    partial_dkim = any(f["code"] == "dns_error" for f in result["dkim"].get("findings", []))
    for c in C.CHECKS:
        st = result[c]["status"]
        raw = raw_for(result, c)
        if prev_eff and prev_eff.get("domain") == domain and c in prev_eff:
            if st == "error":
                st, raw = prev_eff[c]["status"], prev_eff[c]["raw"]
            elif c == "dkim" and partial_dkim:
                raw = prev_eff[c]["raw"]
        eff[c] = {"status": st, "raw": raw}
    eff["grade"] = C.worst(eff[c]["status"] for c in C.CHECKS)
    return eff


def diff_states(prev: dict, cur: dict) -> tuple[list[str], str]:
    """Return (list of change lines, comparable old grade)."""
    lines: list[str] = []
    if prev.get("domain") != cur.get("domain"):
        lines.append(f"Domain changed: {prev.get('domain')} → {cur.get('domain')}")
    old_statuses = []
    for c in C.CHECKS:
        p = prev.get(c) or {"status": "error", "raw": ""}
        n = cur[c]
        p_status = n["status"] if p["status"] == "error" or n["status"] == "error" else p["status"]
        old_statuses.append(p_status)
        if p_status != n["status"]:
            lines.append(f"{LABEL[c]}: {p_status} → {n['status']}")
        if c in ("spf", "dmarc", "dkim") and "error" not in (p["status"], n["status"]) and p["raw"] != n["raw"]:
            what = "found DKIM keys" if c == "dkim" else f"{LABEL[c]} record"
            lines.append(f"{LABEL[c]}: {what} changed\n    was: {p['raw'] or '(none)'}\n    now: {n['raw'] or '(none)'}")
    old_grade = prev.get("grade") if prev.get("domain") != cur.get("domain") else C.worst(old_statuses)
    if old_grade != cur["grade"]:
        lines.insert(0, f"Grade: {old_grade} → {cur['grade']}")
    return lines, old_grade


def fix_hints(result: dict) -> list[str]:
    out = []
    for c in C.CHECKS:
        for f in result[c].get("findings", []):
            if f["level"] in ("warn", "fail", "error") and f.get("hint"):
                out.append(f"{LABEL[c]}: {f['hint']}")
    return out


def all_findings(result: dict) -> dict:
    return {c: result[c].get("findings", []) for c in C.CHECKS}


@contextmanager
def file_lock(name: str):
    os.makedirs(D.data_dir(), exist_ok=True)
    fh = open(os.path.join(D.data_dir(), name), "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


# --------------------------------------------------------------------------- runs


def _check_client(row) -> dict:
    return C.check_domain(row["domain"], C.parse_selectors(row["dkim_selectors"]))


def run_checks(kind: str = "manual", client_id: int | None = None, checker=None) -> dict:
    """Check active domains (or one client), store results, raise alerts. Runs are serialised."""
    checker = checker or _check_client
    with file_lock("run.lock"):
        conn = D.connect()
        try:
            return _run(conn, kind, client_id, checker)
        finally:
            conn.close()


def _run(conn, kind, client_id, checker) -> dict:
    cur = conn.execute("INSERT INTO check_runs(started_at, kind) VALUES(?, ?)", (D.now_iso(), kind))
    run_id = cur.lastrowid
    conn.commit()
    if client_id:
        clients = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchall()
    else:
        clients = conn.execute("SELECT * FROM clients WHERE active = 1 ORDER BY id").fetchall()
    results = {}
    if clients:
        with ThreadPoolExecutor(max_workers=min(4, len(clients))) as ex:
            for row, res in zip(clients, ex.map(checker, clients)):
                results[row["id"]] = res
    new_alerts = []
    still_failing = []
    for row in clients:
        res = results[row["id"]]
        prev = conn.execute(
            "SELECT effective_json FROM domain_checks WHERE client_id = ? ORDER BY id DESC LIMIT 1", (row["id"],)
        ).fetchone()
        prev_eff = json.loads(prev["effective_json"]) if prev and prev["effective_json"] else None
        eff = effective_state(row["domain"], res, prev_eff)
        conn.execute(
            """INSERT INTO domain_checks(run_id, client_id, domain, grade, spf_status, dkim_status, dmarc_status,
               mx_status, spf_raw, dmarc_raw, dkim_found_json, mx_raw, findings_json, lookup_count, effective_json, checked_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run_id, row["id"], row["domain"], res["grade"], res["spf"]["status"], res["dkim"]["status"],
             res["dmarc"]["status"], res["mx"]["status"], res["spf"].get("raw", ""), res["dmarc"].get("raw", ""),
             json.dumps(res["dkim"].get("found", [])), res["mx"].get("raw", ""), json.dumps(all_findings(res)),
             res.get("lookup_count"), json.dumps(eff), D.now_iso()),
        )
        if prev_eff is None:
            continue  # first check of a client = baseline, no alert
        lines, old_grade = diff_states(prev_eff, eff)
        if lines:
            hints = fix_hints(res)
            summary = "\n".join(lines)
            if hints:
                summary += "\nFix hints:\n" + "\n".join(f"  - {h}" for h in hints)
            cur = conn.execute(
                """INSERT INTO alerts(client_id, run_id, domain, old_grade, new_grade, summary, delivery_status, created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (row["id"], run_id, row["domain"], old_grade, eff["grade"], summary, "pending", D.now_iso()),
            )
            new_alerts.append({"id": cur.lastrowid, "client": row["client_name"], "domain": row["domain"],
                               "old": old_grade, "new": eff["grade"], "summary": summary})
        elif eff["grade"] == "fail":
            still_failing.append(row["domain"])
    conn.commit()

    status = None
    digest = f"Still failing (unchanged, not re-alerted): {', '.join(still_failing)}" if still_failing else ""
    if new_alerts or (kind == "scheduled" and still_failing):
        body = [f"SenderGrade run #{run_id} ({kind}) — {len(new_alerts)} domain(s) changed.", ""]
        for a in new_alerts:
            body += [f"{a['client']} — {a['domain']}: {a['old']} → {a['new']}", a["summary"], ""]
        if digest:
            body.append(digest)
        body.append(f"Dashboard: {D.public_base_url()}/")
        subject = (f"[SenderGrade] {len(new_alerts)} domain change(s)" if new_alerts
                   else f"[SenderGrade] Daily digest: {len(still_failing)} domain(s) still failing")
        status = deliver(subject, "\n".join(body))
    if new_alerts:
        conn.execute("UPDATE alerts SET delivery_status = ? WHERE run_id = ? AND delivery_status = 'pending'",
                     (status, run_id))
    conn.execute(
        "UPDATE check_runs SET finished_at = ?, domains_checked = ?, changes = ?, summary = ? WHERE id = ?",
        (D.now_iso(), len(clients), len(new_alerts), digest, run_id),
    )
    conn.commit()
    return {"run_id": run_id, "domains": len(clients), "alerts": len(new_alerts), "delivery": status}


def send_test_alert() -> str:
    body = ("This is a test alert from SenderGrade.\n\nIf you can read this, change alerts for your "
            f"client domains will reach this inbox.\n\nDashboard: {D.public_base_url()}/")
    status = deliver("[SenderGrade] Test alert", body)
    conn = D.connect()
    try:
        conn.execute(
            "INSERT INTO alerts(client_id, run_id, domain, old_grade, new_grade, summary, delivery_status, created_at)"
            " VALUES(NULL, NULL, '', NULL, NULL, ?, ?, ?)",
            ("Test alert", status, D.now_iso()),
        )
        conn.commit()
    finally:
        conn.close()
    return status


# --------------------------------------------------------------------------- scheduler


def _parse(ts: str | None):
    if not ts:
        return None
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def has_active_clients(conn) -> bool:
    return conn.execute("SELECT 1 FROM clients WHERE active = 1 LIMIT 1").fetchone() is not None


def startup_due(conn, now: datetime) -> bool:
    row = conn.execute("SELECT MAX(started_at) AS t FROM check_runs").fetchone()
    last = _parse(row["t"])
    return has_active_clients(conn) and (last is None or now - last > timedelta(hours=24))


def daily_due(conn, now: datetime, hour: int) -> bool:
    slot = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if now < slot:
        return False
    row = conn.execute(
        "SELECT 1 FROM check_runs WHERE kind IN ('scheduled', 'startup') AND started_at >= ? LIMIT 1",
        (slot.strftime("%Y-%m-%dT%H:%M:%SZ"),),
    ).fetchone()
    return row is None and has_active_clients(conn)


def _scheduler_loop() -> None:
    os.makedirs(D.data_dir(), exist_ok=True)
    fh = open(os.path.join(D.data_dir(), "scheduler.lock"), "w")
    holding = False
    while True:
        try:
            if not holding:
                try:
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    holding = True
                    conn = D.connect()
                    try:
                        due = startup_due(conn, datetime.now(timezone.utc))
                    finally:
                        conn.close()
                    if due:
                        run_checks("startup")
                except BlockingIOError:
                    pass
            if holding:
                conn = D.connect()
                try:
                    due = daily_due(conn, datetime.now(timezone.utc), D.check_hour_utc())
                finally:
                    conn.close()
                if due:
                    run_checks("scheduled")
        except Exception as exc:  # keep the scheduler alive
            print(f"[sendergrade scheduler] {exc}", flush=True)
        time.sleep(60)


_started = False


def start_scheduler() -> None:
    global _started
    if _started or D.env("SENDERGRADE_SCHEDULER", "on").lower() == "off":
        return
    _started = True
    threading.Thread(target=_scheduler_loop, name="sendergrade-scheduler", daemon=True).start()
