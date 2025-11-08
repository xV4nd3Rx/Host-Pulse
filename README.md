# Host-Pulse

<img width="1258" height="720" alt="image" src="https://github.com/user-attachments/assets/ec0387eb-e1c4-4042-91cb-2c79bde362f8" />


![Status](https://img.shields.io/badge/status-ready-blue)
![Target](https://img.shields.io/badge/target-Domain%20Liveness-orange)
![Python](https://img.shields.io/badge/python-3.8%2B-informational)
![License](https://img.shields.io/badge/license-MIT-green)

> 🔎 **Host-Pulse** - a fast, lightweight domain liveness probe for pentesters and security engineers.  
> Scans large domain lists, quickly skips dead targets, detects reachable hosts (including 403/401/5xx), and produces clean `alive.txt` and compact `results.csv` reports.

---

## ✨ Highlights

- ⚡ **Fast-skip dead targets** - DNS resolution with a timeout; unresolved domains are dropped quickly.  
- 🎯 **Alive logic tuned for pentesting** - considers status codes `<400` and `403` as "alive" (useful to spot misconfigs, auth walls, and error pages).  
- 🧩 **Randomized User-Agent** per request to avoid simple UA-based filtering.  
- 🔁 **Parallel workers + controlled delays** - configurable workers and per-request random delay to avoid accidental overload.  
- 🔐 **Insecure HTTPS requests** are supported (suppressed warnings) so scanning continues even with untrusted certs; cert metadata is optionally collected.  
- 📄 **Outputs:** `alive.txt` (one domain per line) and `results.csv` (compact, pentester-oriented fields).  
- 🧰 Small dependency footprint: `requests` ± `rich`/`tqdm` for progress.

---

## ⚠️ Safety & Ethics

- ✅ Intended **only** for systems you own or are explicitly authorized to test.  
- ✅ The tool is **non-destructive** in normal operation (it performs HTTP GETs); nevertheless, scanning may trigger alerts.  
- ⚖️ Always check local laws and organizational policies before scanning. Use responsibly.

---

## 🚀 Quick Start

Install dependencies:

```bash
python3 -m pip install --user requests
# optional (nice progress bar): pip install rich tqdm
```
Running:
```
# single-run using a domains file
python3 hostpulse.py --input targets.txt --out-base hostpulse_results --workers 8 --timeout 6 --dns-timeout 2

# minimal example
python3 hostpulse.py -i targets.txt -o hostpulse
```
## 📸 Screenshot

Below is a preview of **HostPulse** in action:

<img width="833" height="264" alt="image" src="https://github.com/user-attachments/assets/57740962-9a3d-4977-87df-e28e9cbca1be" />

---

## 📥 Example input

`targets.txt` (one domain per line):
```
example.com
github.com
dead-domain.example
```
---

## 📤 Outputs

- **results_alive.txt** - plain list of alive domains (one per line).  
- **results.csv** - compact CSV with columns useful for pentesters:

| Field | Description |
|:------|:-------------|
| `domain` | Original domain |
| `attempted_url` | Scheme + domain that was probed |
| `resolved_ips` | Semicolon-delimited IPs found via DNS |
| `status_code` | HTTP status code (e.g., 200, 403, 503) |
| `server_header` | Value of `Server` header (if present) |
| `content_type` | `Content-Type` header |
| `title` | HTML `<title>` (if retrievable) |
| `response_time_ms` | Elapsed time for the request |
| `final_url` | Redirect target (if any) |
| `cert_subject` | Short certificate subject (when HTTPS used) |
| `error` | Errors encountered (timeouts, DNS failures, etc.) |

> The CSV includes **only alive hosts** (as defined above) to keep the output focused.

---

## 🛠️ Common options

| Option | Description |
|:--------|:-------------|
| `--input, -i` | File with domains (one domain per line) |
| `--out-base, -o` | Output base name (produces `<base>_alive.txt` and `<base>.csv`) |
| `--workers, -w` | Number of parallel workers (default: `8`) |
| `--delay-min` | Minimum per-request delay in seconds |
| `--delay-max` | Maximum per-request delay in seconds |
| `--timeout` | Total read timeout in seconds (`connect timeout = min(3, timeout)`) |
| `--dns-timeout` | DNS resolution timeout in seconds (fast-skip dead names) |

---

## 🧩 Contributing

Contributions, bug reports, and pull requests are welcome.  
Please follow standard open-source etiquette - open an issue first to discuss major changes.

---

## 📬 Contacts
- [LinkedIn](https://www.linkedin.com/in/yurii-tsarienko-a1453aa4)
- [SecForgeHub Telegram](https://t.me/SecForgeHub)

---

## 📜 License
**Host-Pulse** is released under the **MIT License** - see `LICENSE` for details.
