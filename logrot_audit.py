#!/usr/bin/env python3
"""logrot-audit — compact daily summary of an Apache/Nginx access log."""
import re, sys, json, collections

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)
SCANNERS = ("gobuster", "dirbuster", "ffuf", "nikto", "sqlmap", "nmap", "wpscan")
TRAVERSAL = re.compile(r'(\.\./|%2e%2e|/etc/|^/)', re.I)

def parse(path):
    paths = collections.Counter()
    ips = collections.Counter()
    status = collections.Counter()
    susp = []
    total = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = LOG_RE.match(line)
            if not m:
                continue
            total += 1
            d = m.groupdict()
            paths[d["path"].split("?")[0]] += 1
            ips[d["ip"]] += 1
            status[d["status"][0] + "xx"] += 1
            ua = d["ua"].lower()
            if any(s in ua for s in SCANNERS):
                susp.append(("scanner UA", d["ip"], d["method"] + " " + d["path"]))
            elif TRAVERSAL.search(d["path"]):
                susp.append(("traversal-ish", d["ip"], d["method"] + " " + d["path"]))
    return total, ips, paths, status, susp

def main():
    args = [a for a in sys.argv[1:] if a != "--json"]
    as_json = "--json" in sys.argv
    if not args:
        print("usage: logrot_audit.py [--json] <access.log>", file=sys.stderr)
        sys.exit(2)
    total, ips, paths, status, susp = parse(args[0])
    if as_json:
        print(json.dumps({
            "requests": total,
            "unique_ips": len(ips),
            "status": dict(status),
            "top_paths": paths.most_common(15),
            "suspicious": susp[:50],
        }, indent=2))
        return
    print(f"== logrot-audit ==")
    print(f"requests {total}  unique IPs {len(ips)}  4xx/5xx {status['4xx']}/{status['5xx']}")
    print("\ntop paths")
    for p, c in paths.most_common(15):
        print(f"  {c:6}  {p}")
    print("\nsuspicious")
    for kind, ip, req in susp[:25]:
        print(f"  {kind:14}  {ip:15}  {req}")

if __name__ == "__main__":
    main()
