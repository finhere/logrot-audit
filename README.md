# logrot-audit

Parses Apache/Nginx access logs and emits a compact daily summary: top client
IPs, top requested paths, status-code histogram, and a short list of "suspicious"
requests (traversal-looking paths, known scanner User-Agents, bursts from a
single IP).

It's a reporting tool, not a blocking tool. It tells you what already happened;
it does not stop anything.

## Usage

```bash
python3 logrot_audit.py /var/log/apache2/access.log
python3 logrot_audit.py --json /var/log/nginx/access.log > report.json
```

## Output

```
== logrot-audit  2026-10-12 ==
requests        48213
unique IPs       1174
4xx / 5xx        512 / 7

top paths
  2219  /
   881  /index.php
   410  /assets/index.js
   ...

suspicious
   33  traversal-ish    203.0.113.9   GET /?doc=../../../etc/passwd
   18  scanner UA        198.51.100.4  gobuster/3.6
```

## Heuristics

- **traversal-ish**: path or query contains `../`, `%2e%2e`, or an absolute path.
- **scanner UA**: User-Agent matches a small built-in list.
- **burst**: >200 requests from one IP within the file.

These are intentionally crude; the goal is a quick eyeball, not detection you'd
alert on. Tune the lists at the top of the script.

## License

MIT.
