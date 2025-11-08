# Host-Pulse

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

# single-run using a domains file
python3 hostpulse.py --input targets.txt --out-base hostpulse_results --workers 8 --timeout 6 --dns-timeout 2

# minimal example
python3 hostpulse.py -i targets.txt -o hostpulse
```
