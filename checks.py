"""SenderGrade check engine: SPF, DKIM, DMARC and MX rules (PRD section 3.2).

Pure DNS reads via dnspython. Deterministic rules, static fix hints, no network
calls other than DNS. The resolver is wrapped in ``Lookup`` so tests can swap in
a fake that returns canned records.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

RANK = {"pass": 0, "warn": 1, "error": 1, "fail": 2}
CHECKS = ("spf", "dkim", "dmarc", "mx")
DOMAIN_CAP_SECONDS = 20.0
SPF_LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists")
SPF_MECHS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")

HINTS = {
    "spf_missing": "No SPF record. Publish one TXT record like 'v=spf1 include:<your ESP> ~all' at the domain root.",
    "spf_multiple": "More than one SPF record. Receivers treat this as a permanent error. Merge them into a single v=spf1 TXT record.",
    "spf_syntax": "SPF syntax could not be parsed. Fix the term shown; receivers return permerror and may reject or spam-folder mail.",
    "spf_include_missing": "An included domain has no SPF record. Remove the include or fix the vendor domain; receivers return permerror.",
    "spf_too_many": "SPF has {n} DNS lookups. Remove unused includes or flatten. Receivers treat over-10 as a hard fail.",
    "spf_near_limit": "SPF has {n} DNS lookups (limit is 10). One more vendor include will break it. Remove unused includes now.",
    "spf_plus_all": "SPF ends in +all, which authorises the whole internet to send as this domain. Change it to ~all or -all.",
    "spf_neutral_all": "SPF uses ?all (neutral), which gives receivers no guidance. Use ~all or -all once all senders are listed.",
    "spf_ptr": "SPF uses the ptr mechanism, which is slow, deprecated and ignored by some receivers. Replace it with ip4/ip6/include.",
    "spf_ok": "SPF record is valid and within the 10-lookup limit.",
    "dkim_none": "No DKIM key found on the selectors checked. Add your ESP's real selector to this client (auto-guess is best effort), or publish DKIM in your ESP.",
    "dkim_revoked": "DKIM key is revoked (empty p=). Re-publish the current key from your ESP or remove the stale selector.",
    "dkim_invalid": "DKIM record could not be parsed. Copy the TXT value again from your ESP; it must contain a base64 p= public key.",
    "dkim_weak": "DKIM key on '{sel}' is {bits}-bit. Rotate to a 2048-bit key in your ESP; 1024-bit keys are being phased out.",
    "dkim_ok": "DKIM key on '{sel}' is valid ({bits}).",
    "dmarc_missing": "No DMARC record. Publish TXT at _dmarc.<domain>: 'v=DMARC1; p=none; rua=mailto:dmarc@<domain>' and tighten later.",
    "dmarc_multiple": "More than one DMARC record. Receivers ignore DMARC entirely. Keep exactly one v=DMARC1 record.",
    "dmarc_invalid": "DMARC record is invalid (missing or bad p= tag). It must start 'v=DMARC1; p=none|quarantine|reject'.",
    "dmarc_none": "DMARC policy is p=none (monitor only). Once SPF and DKIM pass for all senders, move to p=quarantine, then p=reject.",
    "dmarc_no_rua": "DMARC has no rua= address, so nobody sees aggregate reports. Add rua=mailto:<your reports inbox>.",
    "dmarc_pct": "DMARC pct={pct} applies the policy to only part of your mail. Raise it to 100 when ready.",
    "dmarc_ok": "DMARC enforces p={p} with aggregate reports enabled.",
    "mx_nxdomain": "Domain does not exist (NXDOMAIN). Check the spelling or the domain's registration and nameservers.",
    "mx_none": "No MX record and no A record fallback. Nobody can reply to or bounce mail for this domain. Add MX records.",
    "mx_a_fallback": "No MX record; senders fall back to the domain's A record. Publish explicit MX records for the mailbox provider.",
    "mx_null": "Null MX (0 .): this domain doesn't receive mail. Fine for send-only domains, but replies and bounces will fail.",
    "mx_unresolved": "MX hosts don't resolve to an address. Fix the MX hostnames with your mailbox provider.",
    "mx_ok": "MX records resolve.",
    "dns_error": "DNS lookup timed out or the resolver failed. Shown as warn and not alerted; it will be re-checked on the next run.",
}


def hint(code: str, **kw) -> str:
    text = HINTS.get(code, "")
    try:
        return text.format(**kw)
    except (KeyError, IndexError):
        return text


def finding(level: str, code: str, message: str, **kw) -> dict:
    return {"level": level, "code": code, "message": message, "hint": hint(code, **kw)}


def worst(statuses) -> str:
    """Grade = worst status. ``error`` (resolver trouble) counts as warn."""
    level = 0
    for st in statuses:
        level = max(level, RANK.get(st, 1))
    return {0: "pass", 1: "warn", 2: "fail"}[level]


def load_selectors(path: str | None = None) -> list[str]:
    path = path or os.environ.get(
        "SELECTORS_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "selectors.txt")
    )
    out: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                sel = line.split("#", 1)[0].strip().lower()
                if sel and sel not in out:
                    out.append(sel)
    except OSError:
        pass
    return out


def parse_selectors(raw: str | None) -> list[str]:
    out: list[str] = []
    for part in re.split(r"[,\s;]+", raw or ""):
        sel = part.strip().lower()
        if sel and re.fullmatch(r"[a-z0-9._-]{1,63}", sel) and sel not in out:
            out.append(sel)
    return out


# --------------------------------------------------------------------------- domains

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
INTERNAL_SUFFIXES = (
    "localhost", "local", "internal", "lan", "intranet", "localdomain", "home",
    "corp", "home.arpa", "arpa", "test", "invalid", "example", "onion",
)


def normalize_domain(raw: str | None) -> str:
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    d = d.rstrip(".")
    try:
        d = d.encode("idna").decode("ascii") if d and not d.isascii() else d
    except UnicodeError:
        return ""
    return d


def is_ip(value: str) -> bool:
    v = (value or "").strip().strip("[]")
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def domain_error(domain: str, public: bool = False) -> str | None:
    """Return an error string if ``domain`` is not acceptable, else None."""
    if not domain:
        return "Enter a domain like example.com."
    if is_ip(domain) or re.fullmatch(r"[0-9.]+", domain):
        return "IP addresses are not accepted. Enter a domain name."
    if len(domain) > 253:
        return "Domain is too long."
    labels = domain.split(".")
    if len(labels) < 2:
        return "Enter a full domain name (single-label names are not accepted)."
    if not all(_LABEL.match(lbl) for lbl in labels):
        return "That doesn't look like a valid domain name."
    tld = labels[-1]
    if not (tld.isalpha() or tld.startswith("xn--")):
        return "That doesn't look like a valid domain name."
    if public:
        for suf in INTERNAL_SUFFIXES:
            if domain == suf or domain.endswith("." + suf):
                return "Internal or reserved names are not accepted."
    return None


# --------------------------------------------------------------------------- DNS wrapper


class NXDomain(Exception):
    pass


class DNSTimeout(Exception):
    pass


class Lookup:
    """Per-domain DNS helper: per-query timeout, overall deadline, small cache.

    ``query`` returns a list of strings (TXT strings joined, MX as 'pref host'),
    returns [] for NoAnswer, raises NXDomain for NXDOMAIN and DNSTimeout for
    timeouts / SERVFAIL / no nameservers / deadline exhausted.
    """

    def __init__(self, timeout: float | None = None, nameserver: str | None = None,
                 cap: float = DOMAIN_CAP_SECONDS):
        self.timeout = float(timeout if timeout is not None else os.environ.get("DNS_TIMEOUT_SECONDS") or 3)
        self.deadline = time.monotonic() + cap
        ns = nameserver if nameserver is not None else (os.environ.get("DNS_RESOLVER") or "").strip()
        if ns:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.nameservers = [x.strip() for x in ns.split(",") if x.strip()]
        else:
            self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        self._cache: dict = {}
        self._lock = threading.Lock()

    def _raw(self, name: str, rdtype: str) -> list[str]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0.05:
            raise DNSTimeout("per-domain time cap reached")
        try:
            ans = self.resolver.resolve(name, rdtype, lifetime=min(self.timeout, remaining),
                                        raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN as exc:
            raise NXDomain(name) from exc
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as exc:
            raise DNSTimeout(str(exc)) from exc
        except dns.resolver.NoAnswer:
            return []
        except dns.exception.DNSException as exc:
            raise DNSTimeout(str(exc)) from exc
        if ans.rrset is None:
            return []
        out = []
        for rr in ans.rrset:
            if rdtype == "TXT":
                out.append(b"".join(rr.strings).decode("utf-8", "replace"))
            elif rdtype == "MX":
                out.append(f"{rr.preference} {rr.exchange.to_text()}")
            else:
                out.append(rr.to_text())
        return out

    def query(self, name: str, rdtype: str) -> list[str]:
        key = (name.lower().rstrip("."), rdtype)
        with self._lock:
            if key in self._cache:
                val = self._cache[key]
                if isinstance(val, Exception):
                    raise val
                return list(val)
        try:
            val = self._raw(key[0], rdtype)
        except (NXDomain, DNSTimeout) as exc:
            if isinstance(exc, NXDomain):
                with self._lock:
                    self._cache[key] = exc
            raise
        with self._lock:
            self._cache[key] = val
        return list(val)


# --------------------------------------------------------------------------- SPF


def _spf_records(txts: list[str]) -> list[str]:
    return [t.strip() for t in txts if re.match(r"(?i)^v=spf1(\s|$)", t.strip())]


class _SpfState:
    def __init__(self):
        self.count = 0
        self.ptr = False
        self.errors: list[dict] = []
        self.timeout = False


def _spf_walk(lk, domain: str, record: str, state: _SpfState, depth: int, seen: set) -> str | None:
    """Count lookups recursively. Returns the effective 'all' qualifier of this record."""
    terms = record.split()[1:]
    all_q = None
    redirect = None
    for term in terms:
        t = term.strip()
        if not t:
            continue
        low = t.lower()
        if "=" in low and not re.match(r"^[+\-~?]?(include|a|mx|ptr|exists|ip4|ip6)[:/]", low):
            name, _, value = low.partition("=")
            if not re.fullmatch(r"[a-z][a-z0-9_.-]*", name):
                state.errors.append(finding("fail", "spf_syntax", f"Unparseable SPF term '{t}'."))
                continue
            if name == "redirect":
                if not value:
                    state.errors.append(finding("fail", "spf_syntax", "redirect= has no domain."))
                    continue
                redirect = value
            continue  # exp= and unknown modifiers are allowed and not counted
        qual = "+"
        if low[0] in "+-~?":
            qual, low = low[0], low[1:]
        m = re.match(r"^([a-z0-9]+)([:/].*)?$", low)
        if not m or m.group(1) not in SPF_MECHS:
            state.errors.append(finding("fail", "spf_syntax", f"Unknown SPF mechanism '{t}'."))
            continue
        mech = m.group(1)
        rest = m.group(2) or ""
        arg = rest[1:] if rest.startswith(":") else ""
        if mech == "all":
            if rest:
                state.errors.append(finding("fail", "spf_syntax", f"Unparseable SPF term '{t}'."))
            all_q = qual
            continue
        if mech in ("ip4", "ip6"):
            try:
                ipaddress.ip_network(arg, strict=False)
            except ValueError:
                state.errors.append(finding("fail", "spf_syntax", f"Bad IP in SPF term '{t}'."))
            continue
        # lookup-costing mechanisms
        state.count += 1
        if mech == "ptr":
            state.ptr = True
        if mech in ("include", "exists") and not arg:
            state.errors.append(finding("fail", "spf_syntax", f"'{t}' has no domain."))
            continue
        if mech == "include" and "%" not in arg:
            if state.count > 10 or depth >= 10 or arg in seen:
                continue
            try:
                inc = _spf_records(lk.query(arg, "TXT"))
            except NXDomain:
                inc = []
            except DNSTimeout:
                state.timeout = True
                continue
            if len(inc) != 1:
                state.errors.append(finding("fail", "spf_include_missing",
                                            f"include:{arg} has {'no' if not inc else 'multiple'} SPF record(s)."))
                continue
            _spf_walk(lk, arg, inc[0], state, depth + 1, seen | {arg})
    if redirect and all_q is None:
        state.count += 1
        if "%" not in redirect and state.count <= 10 and depth < 10 and redirect not in seen:
            try:
                red = _spf_records(lk.query(redirect, "TXT"))
            except NXDomain:
                red = []
            except DNSTimeout:
                state.timeout = True
                return all_q
            if len(red) != 1:
                state.errors.append(finding("fail", "spf_include_missing",
                                            f"redirect={redirect} has no single SPF record."))
                return all_q
            return _spf_walk(lk, redirect, red[0], state, depth + 1, seen | {redirect})
    return all_q


def check_spf(lk, domain: str) -> dict:
    res = {"status": "pass", "raw": "", "findings": [], "lookup_count": None}
    try:
        txts = lk.query(domain, "TXT")
    except NXDomain:
        res.update(status="fail", findings=[finding("fail", "spf_missing", "Domain does not exist, so there is no SPF record.")])
        return res
    except DNSTimeout:
        res.update(status="error", findings=[finding("error", "dns_error", "SPF lookup timed out.")])
        return res
    recs = _spf_records(txts)
    res["raw"] = "\n".join(recs)
    if not recs:
        res.update(status="fail", findings=[finding("fail", "spf_missing", "No v=spf1 TXT record found.")])
        return res
    if len(recs) > 1:
        res.update(status="fail", findings=[finding("fail", "spf_multiple", f"{len(recs)} SPF records found.")])
        return res
    state = _SpfState()
    all_q = _spf_walk(lk, domain, recs[0], state, 0, {domain})
    res["lookup_count"] = state.count
    fails = list(state.errors)
    warns = []
    n = state.count
    if n > 10:
        fails.append(finding("fail", "spf_too_many", f"SPF needs {n} DNS lookups (limit 10).", n=n))
    elif n >= 8:
        warns.append(finding("warn", "spf_near_limit", f"SPF needs {n} DNS lookups (limit 10).", n=n))
    if all_q == "+":
        fails.append(finding("fail", "spf_plus_all", "SPF allows any sender (+all)."))
    elif all_q == "?":
        warns.append(finding("warn", "spf_neutral_all", "SPF ends in ?all (neutral)."))
    if state.ptr:
        warns.append(finding("warn", "spf_ptr", "SPF uses the ptr mechanism."))
    if fails:
        res.update(status="fail", findings=fails + warns)
    elif state.timeout:
        res.update(status="error", findings=[finding("error", "dns_error", "An SPF include lookup timed out; lookup count may be incomplete.")] + warns)
    elif warns:
        res.update(status="warn", findings=warns)
    else:
        res["findings"] = [finding("pass", "spf_ok", f"SPF valid, {n} DNS lookup{'s' if n != 1 else ''}.")]
    return res


# --------------------------------------------------------------------------- DKIM


def _der_len(buf: bytes, i: int) -> tuple[int, int]:
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    nbytes = first & 0x7F
    if nbytes == 0 or nbytes > 4:
        raise ValueError("bad DER length")
    return int.from_bytes(buf[i:i + nbytes], "big"), i + nbytes


def _der_children(buf: bytes) -> list[tuple[int, bytes]]:
    out = []
    i = 0
    while i < len(buf):
        tag = buf[i]
        length, start = _der_len(buf, i + 1)
        end = start + length
        if end > len(buf):
            raise ValueError("truncated DER")
        out.append((tag, buf[start:end]))
        i = end
    return out


def rsa_bits(der: bytes) -> int:
    """Modulus size of an RSA public key in SubjectPublicKeyInfo or PKCS#1 DER."""
    outer = _der_children(der)
    if not outer or outer[0][0] != 0x30:
        raise ValueError("not a DER sequence")
    kids = _der_children(outer[0][1])
    if kids and kids[0][0] == 0x30 and len(kids) >= 2 and kids[1][0] == 0x03:
        inner = _der_children(kids[1][1][1:])  # skip unused-bits byte
        if not inner or inner[0][0] != 0x30:
            raise ValueError("bad SPKI")
        kids = _der_children(inner[0][1])
    if not kids or kids[0][0] != 0x02:
        raise ValueError("no RSA modulus")
    return int.from_bytes(kids[0][1].lstrip(b"\x00"), "big").bit_length()


def parse_dkim(txt: str) -> dict:
    """Classify one DKIM TXT value. status: ok | weak | revoked | invalid | notkey."""
    tags = {}
    for part in txt.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = re.sub(r"\s+", "", v)
    if "p" not in tags:
        return {"status": "notkey"}
    v = tags.get("v")
    if v is not None and v.upper() != "DKIM1":
        return {"status": "invalid", "detail": "v= is not DKIM1"}
    key = tags["p"]
    if key == "":
        return {"status": "revoked", "key_type": tags.get("k", "rsa")}
    ktype = (tags.get("k") or "rsa").lower()
    try:
        der = base64.b64decode(key + "=" * (-len(key) % 4), validate=True)
    except (binascii.Error, ValueError):
        return {"status": "invalid", "detail": "p= is not valid base64", "key_type": ktype}
    if ktype == "ed25519":
        if len(der) != 32:
            return {"status": "invalid", "detail": "ed25519 key is not 32 bytes", "key_type": ktype}
        return {"status": "ok", "key_type": "ed25519", "bits": 256}
    if ktype != "rsa":
        return {"status": "invalid", "detail": f"unknown key type k={ktype}", "key_type": ktype}
    try:
        bits = rsa_bits(der)
    except (ValueError, IndexError):
        return {"status": "invalid", "detail": "RSA key could not be parsed", "key_type": ktype}
    return {"status": "ok" if bits >= 2048 else "weak", "key_type": "rsa", "bits": bits}


def _probe_selector(lk, domain: str, sel: str) -> dict:
    name = f"{sel}._domainkey.{domain}"
    try:
        txts = lk.query(name, "TXT")
    except NXDomain:
        return {"selector": sel, "status": "absent"}
    except DNSTimeout:
        return {"selector": sel, "status": "timeout"}
    best = None
    for t in txts:
        info = parse_dkim(t)
        if info["status"] == "notkey":
            continue
        info.update(selector=sel, record=t)
        order = {"ok": 0, "weak": 1, "revoked": 2, "invalid": 3}
        if best is None or order[info["status"]] < order[best["status"]]:
            best = info
    return best or {"selector": sel, "status": "absent"}


def check_dkim(lk, domain: str, given: list[str], guess: list[str]) -> dict:
    selectors = []
    for sel in list(given) + list(guess):
        if sel not in selectors:
            selectors.append(sel)
    res = {"status": "fail", "raw": "", "findings": [], "found": [], "checked": selectors}
    if not selectors:
        res["findings"] = [finding("fail", "dkim_none", "No selectors to check (selectors.txt is empty).")]
        return res
    with ThreadPoolExecutor(max_workers=min(8, len(selectors))) as ex:
        probes = list(ex.map(lambda s: _probe_selector(lk, domain, s), selectors))
    found = [p for p in probes if p["status"] in ("ok", "weak", "revoked", "invalid")]
    timed_out = any(p["status"] == "timeout" for p in probes)
    res["found"] = [
        {k: p.get(k) for k in ("selector", "status", "key_type", "bits", "record") if p.get(k) is not None}
        for p in found
    ]
    res["raw"] = "\n".join(f"{p['selector']}: {p.get('record', '')}" for p in found)
    valid = [p for p in found if p["status"] in ("ok", "weak")]
    strong = [p for p in valid if p["status"] == "ok"]
    weak = [p for p in valid if p["status"] == "weak"]
    for sel in given:
        if not any(p["selector"] == sel for p in found):
            res["findings"].append(finding("warn" if valid else "fail", "dkim_none", f"Selector '{sel}' has no DKIM record."))
    if strong:
        res["status"] = "pass"
        for p in strong:
            label = "ed25519" if p.get("key_type") == "ed25519" else f"{p['bits']}-bit RSA"
            res["findings"].append(finding("pass", "dkim_ok", f"'{p['selector']}' valid, {label}.", sel=p["selector"], bits=label))
        for p in weak:
            res["findings"].append(finding("warn", "dkim_weak", f"'{p['selector']}' is {p['bits']}-bit RSA.", sel=p["selector"], bits=p["bits"]))
        res["findings"] = [f for f in res["findings"] if f["code"] != "dkim_none" or f["level"] != "fail"]
        return res
    if weak:
        res["status"] = "warn"
        for p in weak:
            res["findings"].append(finding("warn", "dkim_weak", f"'{p['selector']}' is {p['bits']}-bit RSA (< 2048).", sel=p["selector"], bits=p["bits"]))
        return res
    if timed_out:
        res["status"] = "error"
        res["findings"].append(finding("error", "dns_error", "Some DKIM selector lookups timed out."))
        return res
    res["status"] = "fail"
    revoked = [p for p in found if p["status"] == "revoked"]
    invalid = [p for p in found if p["status"] == "invalid"]
    if revoked:
        res["findings"].append(finding("fail", "dkim_revoked",
                                       "Key revoked (empty p=) on: " + ", ".join(p["selector"] for p in revoked) + "."))
    if invalid:
        res["findings"].append(finding("fail", "dkim_invalid",
                                       "Unparseable DKIM record on: " + ", ".join(f"{p['selector']} ({p.get('detail')})" for p in invalid) + "."))
    if not revoked and not invalid:
        res["findings"].append(finding("fail", "dkim_none", f"No DKIM key found on {len(selectors)} selector(s) checked."))
    return res


# --------------------------------------------------------------------------- DMARC


def check_dmarc(lk, domain: str) -> dict:
    res = {"status": "pass", "raw": "", "findings": []}
    try:
        txts = lk.query(f"_dmarc.{domain}", "TXT")
    except NXDomain:
        txts = []
    except DNSTimeout:
        res.update(status="error", findings=[finding("error", "dns_error", "DMARC lookup timed out.")])
        return res
    recs = [t.strip() for t in txts if re.match(r"(?i)^v\s*=\s*dmarc1\s*(;|$)", t.strip())]
    res["raw"] = "\n".join(recs)
    if not recs:
        res.update(status="fail", findings=[finding("fail", "dmarc_missing", "No _dmarc TXT record.")])
        return res
    if len(recs) > 1:
        res.update(status="fail", findings=[finding("fail", "dmarc_multiple", f"{len(recs)} DMARC records found.")])
        return res
    tags = {}
    for part in recs[0].split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        res.update(status="fail", findings=[finding("fail", "dmarc_invalid", "DMARC p= tag is missing or invalid.")])
        return res
    warns = []
    if p == "none":
        warns.append(finding("warn", "dmarc_none", "Policy is p=none (monitor only)."))
    if not tags.get("rua"):
        warns.append(finding("warn", "dmarc_no_rua", "No rua= aggregate report address."))
    pct_raw = tags.get("pct")
    if pct_raw is not None:
        try:
            pct = int(pct_raw)
        except ValueError:
            pct = -1
        if pct < 100:
            warns.append(finding("warn", "dmarc_pct", f"pct={pct_raw}.", pct=pct_raw))
    if warns:
        res.update(status="warn", findings=warns)
    else:
        res["findings"] = [finding("pass", "dmarc_ok", f"p={p} with rua.", p=p)]
    return res


# --------------------------------------------------------------------------- MX


def _resolves(lk, host: str) -> bool | None:
    timed = False
    for rdtype in ("A", "AAAA"):
        try:
            if lk.query(host, rdtype):
                return True
        except NXDomain:
            return False
        except DNSTimeout:
            timed = True
    return None if timed else False


def check_mx(lk, domain: str) -> dict:
    res = {"status": "pass", "raw": "", "findings": []}
    try:
        mxs = lk.query(domain, "MX")
    except NXDomain:
        res.update(status="fail", findings=[finding("fail", "mx_nxdomain", "NXDOMAIN: the domain does not exist.")])
        return res
    except DNSTimeout:
        res.update(status="error", findings=[finding("error", "dns_error", "MX lookup timed out.")])
        return res
    parsed = []
    for m in mxs:
        pref, _, host = m.partition(" ")
        try:
            parsed.append((int(pref), host.strip()))
        except ValueError:
            continue
    parsed.sort()
    res["raw"] = "\n".join(f"{p} {h}" for p, h in parsed)
    if not parsed:
        ok = _resolves(lk, domain)
        if ok is None:
            res.update(status="error", findings=[finding("error", "dns_error", "A-record fallback lookup timed out.")])
        elif ok:
            res.update(status="warn", findings=[finding("warn", "mx_a_fallback", "No MX record; A record fallback only.")])
        else:
            res.update(status="fail", findings=[finding("fail", "mx_none", "No MX and no A record.")])
        return res
    if len(parsed) == 1 and parsed[0][1] in (".", ""):
        res.update(status="warn", findings=[finding("warn", "mx_null", "Null MX: domain doesn't receive mail.")])
        return res
    any_timeout = False
    for _, host in parsed[:3]:
        ok = _resolves(lk, host.rstrip("."))
        if ok:
            res["findings"] = [finding("pass", "mx_ok", f"{len(parsed)} MX host(s); {host} resolves.")]
            return res
        if ok is None:
            any_timeout = True
    if any_timeout:
        res.update(status="error", findings=[finding("error", "dns_error", "MX host address lookup timed out.")])
    else:
        res.update(status="fail", findings=[finding("fail", "mx_unresolved", "None of the MX hosts resolve.")])
    return res


# --------------------------------------------------------------------------- domain run


def check_domain(domain: str, selectors: list[str] | None = None, lookup=None,
                 guess: list[str] | None = None) -> dict:
    """Run all four checks for one domain. Never raises for DNS trouble."""
    lk = lookup or Lookup()
    guess = load_selectors() if guess is None else guess
    given = list(selectors or [])
    started = time.monotonic()
    out = {"domain": domain}
    for name, fn in (
        ("spf", lambda: check_spf(lk, domain)),
        ("dmarc", lambda: check_dmarc(lk, domain)),
        ("mx", lambda: check_mx(lk, domain)),
        ("dkim", lambda: check_dkim(lk, domain, given, guess)),
    ):
        try:
            out[name] = fn()
        except (DNSTimeout, NXDomain):
            out[name] = {"status": "error", "raw": "", "findings": [finding("error", "dns_error", f"{name.upper()} lookup failed.")]}
        except Exception as exc:  # defensive: a parser bug must not kill the run
            out[name] = {"status": "error", "raw": "", "findings": [finding("error", "dns_error", f"{name.upper()} check error: {exc}")]}
    out["dkim"].setdefault("found", [])
    out["grade"] = worst(out[c]["status"] for c in C_CHECKS_PLACEHOLDER)
    out["lookup_count"] = out["spf"].get("lookup_count")
    out["elapsed"] = round(time.monotonic() - started, 2)
    return out
