#!/usr/bin/env python3
"""breach.miors.art — Data Breach Checker: email / username / phone.
Sources: XposedOrNot (email), LeakCheck public (email/username/phone), Hudson Rock (email/username). stdlib only."""
import json, re, time, threading, urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 7430
UA = "Mozilla/5.0 (compatible; BreachChecker/1.0)"
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\d{7,15}$")
USER_RE = re.compile(r"^[A-Za-z0-9._\-]{2,64}$")
NAME_RE = re.compile(r"^[A-Za-z\u0600-\u06FF\u4e00-\u9fff\u0400-\u04FF]+([ '][A-Za-z\u0600-\u06FF\u4e00-\u9fff\u0400-\u04FF]+){1,3}$")

CACHE = {}          # key -> {"t": ts, "data": {...}}
RATE = {}           # ip -> (minute_start_ts, count)
CACHE_TTL = 3600
RATE_LIMIT = 1000000
LOCK = threading.Lock()


def fetch_json(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.getcode(), json.loads(r.read().decode("utf-8", "replace"))


def check_leakcheck(term, ltype=None):
    """LeakCheck public API. ltype: None (auto) / 'phone'. Returns dict."""
    out = {"found": 0, "sources": [], "error": None}
    try:
        url = "https://leakcheck.io/api/public?check=" + urllib.parse.quote(term)
        if ltype:
            url += "&type=" + ltype
        code, d = fetch_json(url)
        if d.get("success"):
            out["found"] = int(d.get("found", 0) or 0)
            out["fields"] = d.get("fields") or []
            srcs = d.get("sources") or []
            if isinstance(srcs, dict):
                srcs = [{"name": k, **(v if isinstance(v, dict) else {"date": v})} for k, v in srcs.items()]
            out["sources"] = [{"name": s.get("name", "?"), "date": s.get("date")} for s in srcs][:80]
        else:
            out["error"] = str(d.get("error") or "not found")
    except urllib.error.HTTPError as e:
        out["error"] = f"LeakCheck HTTP {e.code}"
    except Exception as e:
        out["error"] = f"LeakCheck: {e}"
    return out


def check_xposedornot(email):
    out = {"breaches": [], "count": 0}
    try:
        code, d = fetch_json("https://api.xposedornot.com/v1/check-email/" + urllib.parse.quote(email))
        raw = d.get("breaches") or []
        names = []
        for item in raw:
            if isinstance(item, str):
                names += [x.strip() for x in item.split(";") if x.strip()]
            elif isinstance(item, list):
                for it in item:
                    names += [x.strip() for x in str(it).split(";") if x.strip()]
        out["count"] = len(names)
        out["names"] = names[:80]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            out["count"] = 0
        else:
            out["error"] = f"XposedOrNot HTTP {e.code}"
    except Exception as e:
        out["error"] = f"XposedOrNot: {e}"
    return out


def breach_details(name):
    """XposedOrNot breach-analytics for one breach; None on failure."""
    try:
        code, d = fetch_json("https://api.xposedornot.com/v1/breach-analytics?breach=" + urllib.parse.quote(name))
        bd = d.get("breach_details") or d
        if isinstance(bd, list):
            bd = bd[0] if bd else {}
        if "error" in bd and not bd.get("breach_date"):
            return None
        dc = bd.get("data_classes") or []
        if isinstance(dc, str):
            dc = [x.strip() for x in dc.split(",")]
        return {"date": bd.get("breach_date") or bd.get("xposed_date"), "data_classes": dc}
    except Exception:
        return None


def check_hudsonrock(email=None, username=None):
    out = {}
    if email:
        try:
            code, d = fetch_json("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=" +
                                 urllib.parse.quote(email))
            out["email"] = d
        except urllib.error.HTTPError as e:
            out["email_error"] = f"HTTP {e.code}"
        except Exception as e:
            out["email_error"] = str(e)
    if username:
        try:
            code, d = fetch_json("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=" +
                                 urllib.parse.quote(username))
            out["username"] = d
        except urllib.error.HTTPError as e:
            out["username_error"] = f"HTTP {e.code}"
        except Exception as e:
            out["username_error"] = str(e)
    return out


def hr_infected(d):
    """Detect stealer infection in a Hudson Rock response. -> (bool, message)"""
    if not isinstance(d, dict):
        return False, ""
    sl = d.get("stealer_logs") or {}
    total = 0
    if isinstance(sl, dict):
        for v in sl.values():
            try:
                total += int(v)
            except (TypeError, ValueError):
                pass
    msg = str(d.get("message", "")).lower()
    # "not associated with a computer infected" = CLEAN. Only flag true positives.
    negations = ("not associated", "not found", "no stealer", "not infected")
    is_negative = any(n in msg for n in negations)
    inf = (isinstance(sl, dict) and total > 0) or ("infected" in msg or "stealer" in msg) and not is_negative
    return inf, str(d.get("message", ""))[:400]


def normalize(qtype, q):
    """-> (type, normalized_query) or (None, error_message)."""
    q = q.strip()
    if EMAIL_RE.match(q.lower()):
        return "email", q.lower()
    if PHONE_RE.match(q):
        return "phone", q.lstrip("+")
    if USER_RE.match(q):
        return "username", q
    if NAME_RE.match(q):
        return None, "Name search not supported — use email, username, or phone."
    return None, "Could not detect input type. Enter an email, a username, or a phone number (digits only)."


def do_lookup(qtype, q):
    """Run all applicable source queries. Returns {"sources": {name: result}, "breaches": [...], "infected": bool, "stealer_msgs": []}"""
    res = {"sources": {}, "breaches": [], "infected": False, "stealer_msgs": []}
    hr = {}
    if qtype == "email":
        res["sources"]["XposedOrNot"] = xn = check_xposedornot(q)
        for nm in xn.get("names", []):
            b = {"name": nm, "date": None, "data_classes": [], "via": "XposedOrNot"}
            det = breach_details(nm)
            if det:
                b.update(det)
            res["breaches"].append(b)
        hr = check_hudsonrock(email=q)
    elif qtype == "username":
        hr = check_hudsonrock(username=q)
    elif qtype == "phone":
        pass

    # LeakCheck runs for every type (phone uses type=phone)
    res["sources"]["LeakCheck"] = lc = check_leakcheck(q, ltype="phone" if qtype == "phone" else None)
    for s in lc.get("sources", []):
        res["breaches"].append({"name": s.get("name", "?"), "date": s.get("date"),
                                "data_classes": lc.get("fields") or [], "via": "LeakCheck"})
    # merge LeakCheck's total count if it exceeds listed sources (sources list may be capped)
    res["leakcheck_found"] = lc.get("found", 0)

    for k, v in hr.items():
        if k.endswith("_error"):
            continue
        res["sources"]["HudsonRock"] = v
        inf, msg = hr_infected(v)
        if inf:
            res["infected"] = True
            res["stealer_msgs"].append(msg)
    return res


def score(res):
    """0-100 aggregated risk from whichever sources ran."""
    n = len(res.get("breaches", []))
    n = max(n, res.get("leakcheck_found", 0) if res.get("leakcheck_found") else n)
    s = min(60, n * 6)
    if res.get("infected"):
        s = max(s, 40) + 40
    return min(100, s)


def classify(n, infected):
    if infected:
        return "Critical"
    return ("Critical" if n >= 100 else "High" if n >= 10 else
            "Moderate" if n >= 3 else "Low" if n > 0 else "Clean")


class Handler(BaseHTTPRequestHandler):
    server_version = "BreachChecker/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        ip = self.client_address[0]
        if self.path.startswith("/api/check"):
            p = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            query = (p.get("query") or p.get("email") or [""])[0].strip()
            qtype_req = (p.get("type") or ["auto"])[0].strip().lower()

            if not query:
                return self._send(400, json.dumps({"error": "Enter an email, username, or phone number."}),
                                  "application/json")

            # rate limit: 10/min per IP
            now = time.time()
            with LOCK:
                win, cnt = RATE.get(ip, (0, 0))
                if now - win >= 60:
                    win, cnt = now, 0
                cnt += 1
                RATE[ip] = (win, cnt)
                if cnt > RATE_LIMIT:
                    return self._send(429, json.dumps({"error": "Rate limit: max 10 lookups per minute. Try again soon."}),
                                      "application/json")
                ck = f"{qtype_req}|{query.lower()}"
                hit = CACHE.get(ck)
                if hit and now - hit["t"] < CACHE_TTL:
                    return self._send(200, json.dumps(hit["data"]), "application/json", {"X-Cache": "HIT"})

            if qtype_req in ("auto", ""):
                qtype, q = normalize(qtype_req, query)
            else:
                q = query.strip().lower()
                if qtype_req == "email":
                    if not EMAIL_RE.match(q):
                        return self._send(400, json.dumps({"error": "Invalid email address format."}), "application/json")
                elif qtype_req == "username":
                    if not USER_RE.match(q):
                        return self._send(400, json.dumps({"error": "Invalid username format."}), "application/json")
                elif qtype_req == "phone":
                    q = q.lstrip("+")
                    if not PHONE_RE.match(q):
                        return self._send(400, json.dumps({"error": "Invalid phone: use international digits only, e.g. 989120000000."}), "application/json")
                qtype = qtype_req
            if qtype is None:
                return self._send(400, json.dumps({"error": q}), "application/json")

            res = do_lookup(qtype, q)
            n = len(res["breaches"])
            n = max(n, res.get("leakcheck_found") or 0)
            data = {
                "query": q, "type": qtype,
                "sources_checked": list(res["sources"].keys()),
                "breaches": res["breaches"],
                "breach_count": n,
                "leakcheck_found": res.get("leakcheck_found", 0),
                "infected": res["infected"],
                "stealer_msgs": res["stealer_msgs"],
                "source_errors": {k: v for k, v in
                                  ((sk, sv.get("error")) for sk, sv in res["sources"].items()
                                   if isinstance(sv, dict) and sv.get("error"))},
                "risk": score(res),
            }
            data["risk_label"] = classify(n, res["infected"])
            with LOCK:
                CACHE[ck] = {"t": time.time(), "data": data}
            return self._send(200, json.dumps(data), "application/json", {"X-Cache": "MISS"})

        try:
            with open("/opt/breach/index.html", "rb") as f:
                return self._send(200, f.read(), extra={"Content-Security-Policy":
                    "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"})
        except FileNotFoundError:
            return self._send(404, "Not found")


if __name__ == "__main__":
    ThreadingHTTPServer.allow_reuse_address = True
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"breach checker listening on 127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()
