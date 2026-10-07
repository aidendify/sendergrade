"""SenderGrade: self-hosted SPF/DKIM/DMARC/MX monitor for agencies, with a branded lead page."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import checks as C
import db as D
import monitor as M

app = Flask(__name__)
app.secret_key = D.secret_key()
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.teardown_appcontext(D.close_db)

if D.env_bool("TRUST_PROXY_HEADERS", False):
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

OPEN_ENDPOINTS = {"health", "login", "logout", "public_check", "report", "static"}
GRADE_ORDER = {"fail": 0, "warn": 1, "pass": 2, None: 3}

D.init_schema()
M.start_scheduler()


@app.context_processor
def inject_globals() -> dict:
    return {
        "brand": D.branding(),
        "marketing_url": D.marketing_url(),
        "logged_in": bool(session.get("owner")),
        "smtp_configured": D.smtp_configured(),
        "public_base_url": D.public_base_url(),
        "label": M.LABEL,
        "check_names": C.CHECKS,
    }


@app.template_filter("fromjson")
def fromjson(value):
    try:
        return json.loads(value or "null")
    except ValueError:
        return None


@app.before_request
def protect_owner_routes():
    if request.endpoint in OPEN_ENDPOINTS or request.endpoint is None:
        return None
    if session.get("owner"):
        return None
    nxt = request.path if request.method == "GET" else "/"
    return redirect(url_for("login", next=nxt))


def _safe_next(val: str | None) -> str:
    raw = (val or "").strip()
    if raw.startswith("/") and not raw.startswith("//"):
        return raw
    return url_for("index")


# --------------------------------------------------------------------------- public


@app.get("/health")
def health():
    conn = D.get_db()
    n = conn.execute("SELECT COUNT(*) AS n FROM clients WHERE active = 1").fetchone()["n"]
    last = conn.execute("SELECT MAX(finished_at) AS t FROM check_runs").fetchone()["t"]
    return jsonify({"status": "ok", "smtp_configured": D.smtp_configured(), "domains": n, "last_run_at": last})


@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = _safe_next(request.values.get("next"))
    if session.get("owner"):
        return redirect(nxt)
    error = None
    if not D.owner_password():
        error = "OWNER_PASSWORD is not set. Add it to .env and restart."
    elif request.method == "POST":
        provided = (request.form.get("password") or "").encode("utf-8")
        expected = D.owner_password().encode("utf-8")
        if secrets.compare_digest(provided, expected):
            session.clear()
            session["owner"] = True
            return redirect(nxt)
        error = "Incorrect password."
    return render_template("login.html", next=nxt, error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def view_from_result(res: dict) -> dict:
    return {
        "grade": res["grade"],
        "lookup_count": res.get("lookup_count"),
        "found": res["dkim"].get("found", []),
        "checked_at": D.now_iso(),
        "checks": [{"name": c, "label": M.LABEL[c], "status": res[c]["status"], "raw": res[c].get("raw", ""),
                    "findings": res[c].get("findings", [])} for c in C.CHECKS],
    }


def view_from_row(row) -> dict | None:
    if row is None:
        return None
    findings = json.loads(row["findings_json"] or "{}")
    found = json.loads(row["dkim_found_json"] or "[]")
    raws = {"spf": row["spf_raw"], "dmarc": row["dmarc_raw"], "mx": row["mx_raw"], "dkim": M.dkim_text(found)}
    return {
        "grade": row["grade"],
        "lookup_count": row["lookup_count"],
        "found": found,
        "checked_at": row["checked_at"],
        "domain": row["domain"],
        "checks": [{"name": c, "label": M.LABEL[c], "status": row[f"{c}_status"], "raw": raws[c] or "",
                    "findings": findings.get(c, [])} for c in C.CHECKS],
    }


def latest_check(conn, client_id: int):
    return conn.execute(
        "SELECT * FROM domain_checks WHERE client_id = ? ORDER BY id DESC LIMIT 1", (client_id,)
    ).fetchone()


@app.get("/r/<token>")
def report(token: str):
    conn = D.get_db()
    client = conn.execute("SELECT * FROM clients WHERE report_token = ?", (token,)).fetchone()
    if client is None:
        abort(404)
    check = latest_check(conn, client["id"])
    changes = conn.execute(
        "SELECT * FROM alerts WHERE client_id = ? ORDER BY id DESC LIMIT 10", (client["id"],)
    ).fetchall()
    return render_template("report.html", client=client, view=view_from_row(check), changes=changes, public=True)


def _ip_hash(ip: str) -> str:
    return hashlib.sha256((D.secret_key() + "|" + (ip or "")).encode("utf-8")).hexdigest()


def _since_hour() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _valid_email(email: str) -> bool:
    if not email or len(email) > 254 or " " in email or email.count("@") != 1:
        return False
    local, _, dom = email.partition("@")
    return bool(local) and C.domain_error(dom.lower()) is None


def _notify_lead(lead: dict) -> None:
    if not (D.smtp_configured() and D.alert_email()):
        return
    body = (f"New lead from your SenderGrade check page.\n\nEmail: {lead['email']}\nName: {lead['name']}\n"
            f"Company: {lead['company']}\nDomain: {lead['domain']}\nGrade: {lead['grade']}\n\n"
            f"Leads: {D.public_base_url()}/leads")

    def _send():
        try:
            M.send_email(D.alert_email(), f"[SenderGrade] New lead: {lead['domain']} ({lead['grade']})", body)
        except Exception as exc:
            print(f"[sendergrade] lead notify failed: {exc}", flush=True)

    threading.Thread(target=_send, daemon=True).start()


@app.route("/check", methods=["GET", "POST"])
def public_check():
    conn = D.get_db()
    if not D.public_check_enabled(conn):
        abort(404)
    brand = D.branding(conn)
    form = {k: (request.form.get(k) or "").strip() for k in ("domain", "email", "name", "company")}
    if request.method == "GET":
        return render_template("check.html", form=form, result=None, error=None, public=True)
    if request.form.get("website"):  # honeypot
        return render_template("check.html", form={}, result=None, error="Submission rejected.", public=True), 400
    raw_domain = form["domain"]
    domain = C.normalize_domain(raw_domain)
    error = None
    if C.is_ip(raw_domain.strip()) or C.is_ip(domain):
        error = "IP addresses are not accepted. Enter a domain name."
    else:
        error = C.domain_error(domain, public=True)
    if not error and not form["email"]:
        error = "Email is required."
    elif not error and not _valid_email(form["email"]):
        error = "Enter a valid email address."
    consent = request.form.get("consent") == "on"
    if not error and brand["consent_text"] and not consent:
        error = "Please tick the consent box."
    if error:
        return render_template("check.html", form=form, result=None, error=error, public=True), 400
    ip_hash = _ip_hash(request.remote_addr or "")
    since = _since_hour()
    per_ip = conn.execute("SELECT COUNT(*) AS n FROM public_checks WHERE ip_hash = ? AND created_at >= ?",
                          (ip_hash, since)).fetchone()["n"]
    total = conn.execute("SELECT COUNT(*) AS n FROM public_checks WHERE created_at >= ?", (since,)).fetchone()["n"]
    if per_ip >= D.rate_per_hour() or total >= D.global_rate_per_hour():
        msg = "Too many checks from your network this hour. Please try again later."
        if per_ip < D.rate_per_hour():
            msg = "This page is busy right now. Please try again later."
        return render_template("check.html", form=form, result=None, error=msg, public=True), 429
    conn.execute("INSERT INTO public_checks(ip_hash, created_at) VALUES(?, ?)", (ip_hash, D.now_iso()))
    conn.execute("DELETE FROM public_checks WHERE created_at < ?",
                 ((datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),))
    conn.commit()
    result = C.check_domain(domain)
    lead = {"email": form["email"][:254], "name": form["name"][:120], "company": form["company"][:120],
            "domain": domain, "grade": result["grade"]}
    conn.execute(
        "INSERT INTO leads(email, name, company, domain, grade, findings_json, ip_hash, consent, created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (lead["email"], lead["name"], lead["company"], domain, result["grade"],
         json.dumps(M.all_findings(result)), ip_hash, 1 if consent else 0, D.now_iso()),
    )
    conn.commit()
    _notify_lead(lead)
    return render_template("check.html", form=form, result=view_from_result(result), error=None, public=True)


# --------------------------------------------------------------------------- owner


def _client_rows(conn):
    rows = conn.execute(
        """SELECT c.*, dc.grade, dc.spf_status, dc.dkim_status, dc.dmarc_status, dc.mx_status,
                  dc.lookup_count, dc.checked_at, dc.dkim_found_json
           FROM clients c
           LEFT JOIN domain_checks dc ON dc.id = (SELECT MAX(id) FROM domain_checks WHERE client_id = c.id)
           ORDER BY c.client_name COLLATE NOCASE"""
    ).fetchall()
    return sorted(rows, key=lambda r: (0 if r["active"] else 1, GRADE_ORDER.get(r["grade"], 3)))


@app.get("/")
def index():
    conn = D.get_db()
    rows = _client_rows(conn)
    counts = {"pass": 0, "warn": 0, "fail": 0, "unchecked": 0}
    for r in rows:
        if r["active"]:
            counts[r["grade"] or "unchecked"] += 1
    last_run = conn.execute("SELECT * FROM check_runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    recent_alerts = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("dashboard.html", rows=rows, counts=counts, last_run=last_run,
                           recent_alerts=recent_alerts, check_hour=D.check_hour_utc())


@app.get("/clients")
def clients():
    return render_template("clients.html", rows=_client_rows(D.get_db()))


def _client_form_values():
    return {
        "client_name": (request.form.get("client_name") or "").strip()[:120],
        "domain": C.normalize_domain(request.form.get("domain")),
        "dkim_selectors": ", ".join(C.parse_selectors(request.form.get("dkim_selectors"))),
        "notes": (request.form.get("notes") or "").strip()[:1000],
        "active": 1 if request.form.get("active") == "on" else 0,
    }


@app.route("/clients/new", methods=["GET", "POST"])
def client_new():
    vals = {"client_name": "", "domain": "", "dkim_selectors": "", "notes": "", "active": 1}
    if request.method == "POST":
        vals = _client_form_values()
        err = C.domain_error(vals["domain"]) or (None if vals["client_name"] else "Client name is required.")
        conn = D.get_db()
        if not err and conn.execute("SELECT 1 FROM clients WHERE domain = ?", (vals["domain"],)).fetchone():
            err = "That domain is already a client."
        if err:
            flash(err, "error")
        else:
            cur = conn.execute(
                "INSERT INTO clients(client_name, domain, dkim_selectors, notes, active, report_token, created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (vals["client_name"], vals["domain"], vals["dkim_selectors"], vals["notes"], vals["active"],
                 D.new_token(), D.now_iso()),
            )
            conn.commit()
            flash("Client added. Click Run checks to grade it.", "ok")
            return redirect(url_for("client_detail", client_id=cur.lastrowid))
    return render_template("client_form.html", vals=vals)


@app.route("/clients/<int:client_id>", methods=["GET", "POST"])
def client_detail(client_id: int):
    conn = D.get_db()
    client = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client is None:
        abort(404)
    if request.method == "POST":
        action = request.form.get("action", "save")
        if action == "save":
            vals = _client_form_values()
            err = C.domain_error(vals["domain"]) or (None if vals["client_name"] else "Client name is required.")
            if not err and conn.execute("SELECT 1 FROM clients WHERE domain = ? AND id != ?",
                                        (vals["domain"], client_id)).fetchone():
                err = "Another client already uses that domain."
            if err:
                flash(err, "error")
            else:
                conn.execute(
                    "UPDATE clients SET client_name=?, domain=?, dkim_selectors=?, notes=?, active=? WHERE id=?",
                    (vals["client_name"], vals["domain"], vals["dkim_selectors"], vals["notes"], vals["active"], client_id),
                )
                conn.commit()
                flash("Client saved. Run checks to see the new result.", "ok")
        elif action == "save_selectors":
            check = latest_check(conn, client_id)
            found = [f["selector"] for f in json.loads(check["dkim_found_json"] or "[]")
                     if f.get("status") in ("ok", "weak")] if check else []
            merged = C.parse_selectors(client["dkim_selectors"])
            for sel in found:
                if sel not in merged:
                    merged.append(sel)
            conn.execute("UPDATE clients SET dkim_selectors = ? WHERE id = ?", (", ".join(merged), client_id))
            conn.commit()
            flash(f"Saved selectors: {', '.join(merged) or '(none found)'}", "ok")
        elif action == "regenerate_token":
            conn.execute("UPDATE clients SET report_token = ? WHERE id = ?", (D.new_token(), client_id))
            conn.commit()
            flash("New report link created. The old link now returns 404.", "ok")
        elif action == "delete":
            conn.execute("DELETE FROM alerts WHERE client_id = ?", (client_id,))
            conn.execute("DELETE FROM domain_checks WHERE client_id = ?", (client_id,))
            conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
            conn.commit()
            flash("Client deleted.", "ok")
            return redirect(url_for("clients"))
        return redirect(url_for("client_detail", client_id=client_id))
    check = latest_check(conn, client_id)
    return render_template("client_detail.html", client=client, view=view_from_row(check), vals=client)


@app.get("/clients/<int:client_id>/history")
def client_history(client_id: int):
    conn = D.get_db()
    client = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client is None:
        abort(404)
    checks_ = conn.execute("SELECT * FROM domain_checks WHERE client_id = ? ORDER BY id DESC LIMIT 50",
                           (client_id,)).fetchall()
    alerts = conn.execute("SELECT * FROM alerts WHERE client_id = ? ORDER BY id DESC LIMIT 50", (client_id,)).fetchall()
    return render_template("history.html", client=client, checks=checks_, alerts=alerts)


def import_csv_text(conn, text: str) -> tuple[int, int, list[str]]:
    added, skipped, errors = 0, 0, []
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    if not reader.fieldnames or "domain" not in [f.strip().lower() for f in reader.fieldnames]:
        return 0, 0, ["CSV needs a header row: client_name,domain,dkim_selectors,notes"]
    for i, raw in enumerate(reader, start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
        domain = C.normalize_domain(row.get("domain"))
        err = C.domain_error(domain)
        if err:
            errors.append(f"Line {i}: {row.get('domain') or '(blank)'}: {err}")
            continue
        if conn.execute("SELECT 1 FROM clients WHERE domain = ?", (domain,)).fetchone():
            skipped += 1
            continue
        conn.execute(
            "INSERT INTO clients(client_name, domain, dkim_selectors, notes, active, report_token, created_at)"
            " VALUES(?,?,?,?,1,?,?)",
            ((row.get("client_name") or domain)[:120], domain, ", ".join(C.parse_selectors(row.get("dkim_selectors"))),
             (row.get("notes") or "")[:1000], D.new_token(), D.now_iso()),
        )
        added += 1
    conn.commit()
    return added, skipped, errors


@app.post("/clients/import")
def clients_import():
    conn = D.get_db()
    if request.form.get("sample") == "1":
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample-clients.csv"), encoding="utf-8") as fh:
            text = fh.read()
    else:
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Choose a CSV file to import.", "error")
            return redirect(url_for("clients"))
        text = upload.read().decode("utf-8", "replace")
    added, skipped, errors = import_csv_text(conn, text)
    flash(f"Imported {added} client(s); {skipped} already existed.", "ok" if added or not errors else "error")
    for e in errors[:10]:
        flash(e, "error")
    return redirect(url_for("clients"))


@app.post("/checks/run")
def checks_run():
    client_id = request.form.get("client_id", type=int)
    res = M.run_checks("manual", client_id=client_id)
    msg = f"Checked {res['domains']} domain(s); {res['alerts']} change alert(s)."
    if res["alerts"]:
        msg += f" Delivery: {res['delivery']}."
    flash(msg, "ok")
    if client_id:
        return redirect(url_for("client_detail", client_id=client_id))
    return redirect(request.form.get("back") if request.form.get("back") in ("/clients", "/alerts") else url_for("index"))


@app.get("/alerts")
def alerts():
    rows = D.get_db().execute(
        "SELECT a.*, c.client_name FROM alerts a LEFT JOIN clients c ON c.id = a.client_id ORDER BY a.id DESC LIMIT 200"
    ).fetchall()
    return render_template("alerts.html", rows=rows)


@app.post("/alerts/test")
def alerts_test():
    status = M.send_test_alert()
    flash(f"Test alert recorded. Delivery: {status}.", "ok" if status == "sent" else "error")
    return redirect(url_for("alerts"))


@app.get("/leads")
def leads():
    rows = D.get_db().execute("SELECT * FROM leads ORDER BY id DESC LIMIT 500").fetchall()
    return render_template("leads.html", rows=rows, enabled=D.public_check_enabled())


def _csv_response(name: str, header: list[str], rows: list[list]) -> Response:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(["'" + str(v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for v in r])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={name}"})


@app.get("/export/leads.csv")
def export_leads():
    rows = D.get_db().execute("SELECT * FROM leads ORDER BY id").fetchall()
    return _csv_response("leads.csv", ["created_at", "email", "name", "company", "domain", "grade", "consent"],
                         [[r["created_at"], r["email"], r["name"], r["company"], r["domain"], r["grade"],
                           "yes" if r["consent"] else "no"] for r in rows])


@app.get("/export/domains.csv")
def export_domains():
    out = []
    for r in _client_rows(D.get_db()):
        found = ", ".join(f["selector"] for f in json.loads(r["dkim_found_json"] or "[]") if f.get("status") in ("ok", "weak"))
        out.append([r["client_name"], r["domain"], "yes" if r["active"] else "no", r["grade"] or "", r["spf_status"] or "",
                    r["dkim_status"] or "", r["dmarc_status"] or "", r["mx_status"] or "",
                    "" if r["lookup_count"] is None else r["lookup_count"], found, r["dkim_selectors"],
                    r["checked_at"] or "", f"{D.public_base_url()}/r/{r['report_token']}"])
    return _csv_response("domains.csv", ["client_name", "domain", "active", "grade", "spf", "dkim", "dmarc", "mx",
                                         "spf_lookups", "dkim_found", "dkim_selectors", "last_checked_utc", "report_url"], out)


@app.route("/settings", methods=["GET", "POST"])
def settings():
    conn = D.get_db()
    if request.method == "POST":
        for key in ("agency_name", "agency_logo_url", "agency_accent_color", "check_headline",
                    "agency_cta_text", "agency_cta_url", "consent_text"):
            value = (request.form.get(key) or "").strip()[:500]
            if not value and key != "consent_text":
                conn.execute("DELETE FROM settings WHERE key = ?", (key,))
                conn.commit()
            else:
                D.set_setting(key, value, conn)
        D.set_setting("public_check_enabled", "true" if request.form.get("public_check_enabled") == "on" else "false", conn)
        flash("Settings saved.", "ok")
        return redirect(url_for("settings"))
    vals = {k: D.get_setting(k, conn) for k in D.BRAND_KEYS}
    return render_template("settings.html", vals=vals, env_enabled=D.env_bool("PUBLIC_CHECK_ENABLED", True),
                           selectors=C.load_selectors(), check_hour=D.check_hour_utc(),
                           alert_email=D.alert_email(), rate=D.rate_per_hour())


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html", public=True), 404
