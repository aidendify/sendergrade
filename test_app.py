"""SenderGrade tests: engine rules with mocked DNS, change detection, routes."""

import io
import os
import shutil
import tempfile
import unittest
import base64

_TMP = tempfile.mkdtemp(prefix="sendergrade-test-")
os.environ.update({
    "DATABASE_PATH": os.path.join(_TMP, "sendergrade.db"),
    "SENDERGRADE_SCHEDULER": "off",
    "OWNER_PASSWORD": "testpass",
    "SECRET_KEY": "test-secret",
    "AGENCY_NAME": "Harbor Email Co",
    "PUBLIC_BASE_URL": "http://127.0.0.1:8080",
    "PUBLIC_CHECK_RATE_PER_HOUR": "3",
    "MARKETING_URL": "",
})
for _k in ("SMTP_HOST", "SMTP_FROM", "ALERT_EMAIL", "PUBLIC_CHECK_ENABLED"):
    os.environ.pop(_k, None)

import checks as C  # noqa: E402
import db as D  # noqa: E402
import monitor as M  # noqa: E402
import app as A  # noqa: E402


# ----------------------------------------------------------------- fake DNS

class FakeLookup:
    def __init__(self, records):
        self.records = {(k[0].lower(), k[1]): v for k, v in records.items()}

    def query(self, name, rdtype):
        val = self.records.get((name.lower().rstrip("."), rdtype))
        if val == "NX":
            raise C.NXDomain(name)
        if val == "TIMEOUT":
            raise C.DNSTimeout(name)
        return list(val or [])


def _der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + body


def rsa_p(bits):
    modulus = ((1 << (bits - 1)) | 1).to_bytes(bits // 8, "big")
    rsa = _der(0x30, _der(0x02, b"\x00" + modulus) + _der(0x02, b"\x01\x00\x01"))
    algid = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
    spki = _der(0x30, algid + _der(0x03, b"\x00" + rsa))
    return base64.b64encode(spki).decode()


def good_domain(domain="good.test", spf="v=spf1 include:_spf.esp.test -all", dmarc="v=DMARC1; p=reject; rua=mailto:r@good.test",
                dkim_sel="s1", bits=2048):
    recs = {
        (domain, "TXT"): [spf, "google-site-verification=x"],
        ("_spf.esp.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        (f"_dmarc.{domain}", "TXT"): [dmarc],
        (domain, "MX"): [f"10 mx.{domain}."],
        (f"mx.{domain}", "A"): ["192.0.2.10"],
    }
    if dkim_sel:
        recs[(f"{dkim_sel}._domainkey.{domain}", "TXT")] = [f"v=DKIM1; k=rsa; p={rsa_p(bits)}"]
    return recs


def run(domain, recs, given=None, guess=("s1", "google", "selector1")):
    return C.check_domain(domain, given or [], lookup=FakeLookup(recs), guess=list(guess))


# ----------------------------------------------------------------- engine

class EngineTests(unittest.TestCase):
    def test_all_pass(self):
        r = run("good.test", good_domain())
        self.assertEqual(r["grade"], "pass", r)
        self.assertEqual(r["lookup_count"], 1)
        self.assertEqual([f["selector"] for f in r["dkim"]["found"]], ["s1"])

    def test_spf_lookup_count_over_10_fails(self):
        recs = good_domain()
        incs = " ".join(f"include:i{i}.test" for i in range(6))
        recs[("good.test", "TXT")] = [f"v=spf1 {incs} a mx -all"]
        for i in range(6):
            recs[(f"i{i}.test", "TXT")] = [f"v=spf1 include:n{i}.test -all"]
            recs[(f"n{i}.test", "TXT")] = ["v=spf1 ip4:192.0.2.1 -all"]
        spf = C.check_spf(FakeLookup(recs), "good.test")
        self.assertEqual(spf["status"], "fail")
        self.assertGreater(spf["lookup_count"], 10)
        self.assertTrue(any(f["code"] == "spf_too_many" for f in spf["findings"]))

    def test_spf_8_to_10_warns(self):
        recs = good_domain()
        recs[("good.test", "TXT")] = ["v=spf1 " + " ".join(f"include:i{i}.test" for i in range(4)) + " a mx -all"]
        for i in range(4):
            recs[(f"i{i}.test", "TXT")] = [f"v=spf1 include:n{i}.test -all"] if i < 3 else ["v=spf1 ip4:192.0.2.1 -all"]
            recs[(f"n{i}.test", "TXT")] = ["v=spf1 ip4:192.0.2.1 -all"]
        spf = C.check_spf(FakeLookup(recs), "good.test")
        self.assertEqual(spf["lookup_count"], 9)
        self.assertEqual(spf["status"], "warn")

    def test_spf_rules(self):
        lk = lambda txt: FakeLookup({("d.test", "TXT"): txt})  # noqa: E731
        self.assertEqual(C.check_spf(lk([]), "d.test")["status"], "fail")
        self.assertEqual(C.check_spf(lk(["v=spf1 -all", "v=spf1 ~all"]), "d.test")["status"], "fail")
        self.assertEqual(C.check_spf(lk(["v=spf1 +all"]), "d.test")["status"], "fail")
        self.assertEqual(C.check_spf(lk(["v=spf1 bogus:x -all"]), "d.test")["status"], "fail")
        self.assertEqual(C.check_spf(lk(["v=spf1 ip4:192.0.2.1 ?all"]), "d.test")["status"], "warn")
        self.assertEqual(C.check_spf(lk(["v=spf1 ptr -all"]), "d.test")["status"], "warn")
        self.assertEqual(C.check_spf(lk(["v=spf1 ip4:192.0.2.1 ~all"]), "d.test")["status"], "pass")

    def test_dkim_key_sizes(self):
        weak = run("good.test", good_domain(bits=1024))
        self.assertEqual(weak["dkim"]["status"], "warn")
        self.assertEqual(weak["dkim"]["found"][0]["bits"], 1024)
        strong = run("good.test", good_domain(bits=2048))
        self.assertEqual(strong["dkim"]["status"], "pass")
        self.assertEqual(strong["dkim"]["found"][0]["bits"], 2048)
        recs = good_domain(dkim_sel=None)
        recs[("s1._domainkey.good.test", "TXT")] = ["v=DKIM1; p="]
        self.assertEqual(run("good.test", recs)["dkim"]["status"], "fail")
        none = run("good.test", good_domain(dkim_sel=None))
        self.assertEqual(none["dkim"]["status"], "fail")
        self.assertEqual(none["grade"], "fail")

    def test_dkim_given_selector_and_guess(self):
        recs = good_domain(dkim_sel="custom1")
        self.assertEqual(run("good.test", recs)["dkim"]["status"], "fail")
        self.assertEqual(run("good.test", recs, given=["custom1"])["dkim"]["status"], "pass")

    def test_dmarc_rules(self):
        self.assertEqual(run("good.test", good_domain(dmarc="v=DMARC1; p=none; rua=mailto:a@b.test"))["dmarc"]["status"], "warn")
        self.assertEqual(run("good.test", good_domain(dmarc="v=DMARC1; p=reject"))["dmarc"]["status"], "warn")
        self.assertEqual(run("good.test", good_domain(dmarc="v=DMARC1; p=quarantine; rua=mailto:a@b.test; pct=50"))["dmarc"]["status"], "warn")
        self.assertEqual(run("good.test", good_domain(dmarc="v=DMARC1; p=bogus"))["dmarc"]["status"], "fail")
        recs = good_domain()
        recs[("_dmarc.good.test", "TXT")] = "NX"
        self.assertEqual(run("good.test", recs)["dmarc"]["status"], "fail")

    def test_mx_null_warn_and_nxdomain_fail(self):
        recs = good_domain()
        recs[("good.test", "MX")] = ["0 ."]
        mx = run("good.test", recs)["mx"]
        self.assertEqual(mx["status"], "warn")
        self.assertTrue(any(f["code"] == "mx_null" for f in mx["findings"]))
        nx = {("gone.test", "TXT"): "NX", ("gone.test", "MX"): "NX", ("_dmarc.gone.test", "TXT"): "NX"}
        r = run("gone.test", nx)
        self.assertEqual(r["grade"], "fail")
        for c in ("spf", "dmarc", "mx", "dkim"):
            self.assertEqual(r[c]["status"], "fail", c)

    def test_timeout_is_error_shown_as_warn(self):
        recs = good_domain()
        recs[("_dmarc.good.test", "TXT")] = "TIMEOUT"
        r = run("good.test", recs)
        self.assertEqual(r["dmarc"]["status"], "error")
        self.assertEqual(r["grade"], "warn")

    def test_domain_validation(self):
        self.assertIsNone(C.domain_error("example.com", public=True))
        for bad in ("", "192.0.2.1", "localhost", "intranet", "printer.local", "db.internal", "exa mple.com", "-a.com"):
            self.assertIsNotNone(C.domain_error(C.normalize_domain(bad), public=True), bad)
        self.assertEqual(C.normalize_domain("https://Example.COM/path"), "example.com")

    def test_selectors_file_loaded(self):
        sels = C.load_selectors()
        for s in ("google", "selector1", "selector2", "s1", "s2", "k1", "k2", "k3", "mandrill", "kl", "kl2", "default", "dkim", "mail"):
            self.assertIn(s, sels)


# ----------------------------------------------------------------- app

FAKE = {}


def fake_check_domain(domain, selectors=None, lookup=None, guess=None):
    recs = FAKE.get(domain, {(domain, "TXT"): "NX", (domain, "MX"): "NX", (f"_dmarc.{domain}", "TXT"): "NX"})
    return REAL_CHECK(domain, selectors, FakeLookup(recs), ["s1", "google"])


REAL_CHECK = C.check_domain


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._real = C.check_domain
        C.check_domain = fake_check_domain
        FAKE.clear()
        FAKE["goodco.com"] = good_domain("goodco.com")
        FAKE["weakco.com"] = good_domain("weakco.com", bits=1024)
        FAKE["google.com"] = good_domain("google.com", dkim_sel="google")
        FAKE["example.org"] = good_domain("example.org")

    @classmethod
    def tearDownClass(cls):
        C.check_domain = cls._real
        shutil.rmtree(_TMP, ignore_errors=True)

    def setUp(self):
        conn = D.connect()
        for t in ("alerts", "domain_checks", "check_runs", "clients", "leads", "public_checks", "settings"):
            conn.execute(f"DELETE FROM {t}")
        conn.commit()
        conn.close()
        os.environ.pop("PUBLIC_CHECK_ENABLED", None)
        self.c = A.app.test_client()

    def login(self):
        r = self.c.post("/login", data={"password": "testpass"})
        self.assertEqual(r.status_code, 302)

    def test_health_public_and_auth_gates(self):
        r = self.c.get("/health")
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertEqual(j["status"], "ok")
        self.assertIs(j["smtp_configured"], False)
        self.assertEqual(j["domains"], 0)
        self.assertIn("last_run_at", j)
        for path in ("/", "/clients", "/alerts", "/leads", "/settings", "/export/leads.csv", "/export/domains.csv"):
            self.assertEqual(self.c.get(path).status_code, 302, path)
        self.assertEqual(self.c.post("/checks/run").status_code, 302)
        self.assertEqual(self.c.get("/check").status_code, 200)
        self.assertEqual(self.c.post("/login", data={"password": "nope"}).status_code, 200)

    def test_import_sample_and_run(self):
        self.login()
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample-clients.csv"), "rb") as fh:
            r = self.c.post("/clients/import", data={"file": (io.BytesIO(fh.read()), "sample-clients.csv")},
                            content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"Imported 5 client", r.data)
        r = self.c.post("/checks/run", follow_redirects=True)
        self.assertIn(b"Checked 5 domain", r.data)
        conn = D.connect()
        rows = {r["domain"]: r for r in conn.execute("SELECT * FROM domain_checks")}
        conn.close()
        self.assertEqual(rows["nonexistent-sendergrade-test.invalid"]["grade"], "fail")
        self.assertEqual(rows["google.com"]["grade"], "pass")
        self.assertIn("google", rows["google.com"]["dkim_found_json"])
        self.assertEqual(self.c.get("/export/domains.csv").status_code, 200)
        self.assertEqual(self.c.get("/health").get_json()["domains"], 5)

    def _add(self, domain, name="Client", selectors=""):
        self.c.post("/clients/new", data={"client_name": name, "domain": domain, "dkim_selectors": selectors, "active": "on"})
        conn = D.connect()
        row = conn.execute("SELECT * FROM clients WHERE domain = ?", (domain,)).fetchone()
        conn.close()
        return row

    def _alerts(self):
        conn = D.connect()
        rows = conn.execute("SELECT * FROM alerts WHERE client_id IS NOT NULL ORDER BY id").fetchall()
        conn.close()
        return rows

    def test_change_detection_one_alert_then_no_duplicate(self):
        self.login()
        client = self._add("goodco.com", "Good Co")
        self.c.post("/checks/run")
        self.assertEqual(len(self._alerts()), 0)  # baseline
        self.c.post("/checks/run")
        self.assertEqual(len(self._alerts()), 0)  # unchanged
        self.c.post(f"/clients/{client['id']}", data={"action": "save", "client_name": "Good Co",
                                                      "domain": "weakco.com", "active": "on"})
        self.c.post("/checks/run")
        alerts = self._alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0]["old_grade"], alerts[0]["new_grade"]), ("pass", "warn"))
        self.assertEqual(alerts[0]["delivery_status"], "not_sent_smtp_unconfigured")
        self.c.post("/checks/run")
        self.assertEqual(len(self._alerts()), 1)
        self.assertIn(b"not_sent_smtp_unconfigured", self.c.get("/alerts").data)

    def test_dns_error_does_not_flap(self):
        self.login()
        self._add("example.org")
        self.c.post("/checks/run")
        FAKE["example.org"][("_dmarc.example.org", "TXT")] = "TIMEOUT"
        try:
            self.c.post("/checks/run")
            self.assertEqual(len(self._alerts()), 0)
        finally:
            FAKE["example.org"] = good_domain("example.org")
        self.c.post("/checks/run")
        self.assertEqual(len(self._alerts()), 0)

    def test_save_found_selectors_and_test_alert(self):
        self.login()
        client = self._add("google.com", "G")
        self.c.post("/checks/run", data={"client_id": client["id"]})
        self.c.post(f"/clients/{client['id']}", data={"action": "save_selectors"})
        conn = D.connect()
        self.assertEqual(conn.execute("SELECT dkim_selectors FROM clients WHERE id=?", (client["id"],)).fetchone()[0], "google")
        conn.close()
        r = self.c.post("/alerts/test", follow_redirects=True)
        self.assertIn(b"not_sent_smtp_unconfigured", r.data)

    def test_report_token_regenerate(self):
        self.login()
        client = self._add("goodco.com", "Good Co")
        self._add("weakco.com", "Other Co")
        self.c.post("/checks/run")
        anon = A.app.test_client()
        r = anon.get(f"/r/{client['report_token']}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"goodco.com", r.data)
        self.assertIn(b"Harbor Email Co", r.data)
        self.assertNotIn(b"weakco.com", r.data)
        self.assertNotIn(b"Powered by", r.data)
        self.c.post(f"/clients/{client['id']}", data={"action": "regenerate_token"})
        self.assertEqual(anon.get(f"/r/{client['report_token']}").status_code, 404)

    def _submit(self, domain="goodco.com", email="lead@prospect.test", ip="203.0.113.5", **extra):
        data = {"domain": domain, "email": email, "name": "Pat", "company": "Prospect", "consent": "on"}
        data.update(extra)
        return self.c.post("/check", data=data, environ_base={"REMOTE_ADDR": ip})

    def test_public_check_lead_validation_and_rate_limit(self):
        r = self._submit()
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Book a call", r.data)
        self.assertIn(b"Fix:", self._submit("weakco.com").data)
        for bad in ("192.0.2.1", "localhost", "nas.local", "not a domain"):
            self.assertEqual(self._submit(bad).status_code, 400, bad)
        self.assertEqual(self._submit(email="").status_code, 400)
        self.assertEqual(self._submit(website="spam").status_code, 400)
        self.assertEqual(self._submit("example.org").status_code, 200)  # 3rd accepted
        self.assertEqual(self._submit("goodco.com").status_code, 429)  # 4th accepted -> limited
        self.assertEqual(self._submit("goodco.com", ip="198.51.100.9").status_code, 200)
        self.login()
        self.assertIn(b"lead@prospect.test", self.c.get("/leads").data)
        csv_body = self.c.get("/export/leads.csv").data
        self.assertIn(b"lead@prospect.test", csv_body)
        self.assertEqual(csv_body.count(b"\n"), 5)
        conn = D.connect()
        lead = conn.execute("SELECT ip_hash FROM leads LIMIT 1").fetchone()
        conn.close()
        self.assertNotIn("203.0.113.5", lead["ip_hash"])

    def test_public_check_disabled(self):
        os.environ["PUBLIC_CHECK_ENABLED"] = "false"
        self.assertEqual(self.c.get("/check").status_code, 404)
        self.assertEqual(self._submit().status_code, 404)

    def test_marketing_footer_only_when_set(self):
        self.assertNotIn(b"Powered by", self.c.get("/check").data)
        os.environ["MARKETING_URL"] = "https://example.org/sendergrade"
        try:
            self.assertIn(b"Powered by SenderGrade", self.c.get("/check").data)
        finally:
            os.environ["MARKETING_URL"] = ""

    def test_scheduler_due_logic(self):
        from datetime import datetime, timezone
        conn = D.connect()
        now = datetime(2026, 10, 7, 4, 0, tzinfo=timezone.utc)
        self.assertFalse(M.startup_due(conn, now))  # no clients
        conn.execute("INSERT INTO clients(client_name, domain, report_token, created_at) VALUES('a','goodco.com','t1','x')")
        conn.commit()
        self.assertTrue(M.startup_due(conn, now))
        self.assertTrue(M.daily_due(conn, now, 3))
        self.assertFalse(M.daily_due(conn, now, 5))
        conn.execute("INSERT INTO check_runs(started_at, finished_at, kind) VALUES('2026-10-07T03:00:05Z','2026-10-07T03:00:09Z','scheduled')")
        conn.commit()
        self.assertFalse(M.daily_due(conn, now, 3))
        self.assertFalse(M.startup_due(conn, now))
        conn.close()


if __name__ == "__main__":
    unittest.main()
