#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import random
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, Future, TimeoutError
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

try:
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except Exception:
    TQDM_AVAILABLE = False

import requests


import re
import shutil

def print_banner():
    C0 = "\033[0m"
    C1 = "\033[38;5;213m"  # title (pink)
    C2 = "\033[38;5;45m"   # body (cyan)
    C3 = "\033[38;5;201m"  # accent (magenta)

    title    = f"{C1}Host-Pulse v1.0{C0}"
    subtitle = f"{C2}Fast Domain Liveness Probe for Pentesters & Researchers{C0}"
    meta     = f"{C2}Author: {C3}xV4nd3Rx{C0}   |   GitHub: {C3}https://github.com/xV4nd3Rx{C0}"

    def strip_ansi(s: str) -> str:
        return re.sub(r"\x1b\\[[0-9;]*m", "", s)

    def visual_len(s: str) -> int:
        return len(re.sub(r"\x1b\[[0-9;]*m", "", s))

    lines = [title, subtitle, meta]
    inner_width = max(visual_len(s) for s in lines)
    inner_width = max(inner_width, 64)  # minimal nice width
    term_cols = shutil.get_terminal_size((80, 20)).columns
    max_width = max(64, min(term_cols - 4, 120))  # keep margin, cap at 120
    inner_width = min(inner_width, max_width)

    def center(s: str, width: int) -> str:
        pad = width - visual_len(s)
        left = pad // 2
        right = pad - left
        return " " * left + s + " " * right

    top =  "+" + "-" * (inner_width + 2) + "+"
    bot =  "+" + "-" * (inner_width + 2) + "+"
    body = [f"| {center(line, inner_width)} |" for line in lines]

    print()
    print(top)
    for b in body:
        print(b)
    print(bot)
    print()


COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def read_domains_from_file(path: str) -> List[str]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    return out


def extract_title(text: str) -> Optional[str]:
    m = TITLE_RE.search(text)
    if m:
        t = m.group(1).strip()
        t = re.sub(r"\s+", " ", t)
        return t[:200]
    return None


def _resolve_sync(domain: str) -> List[str]:
    try:
        res = socket.gethostbyname_ex(domain)
        return list(set(res[2]))
    except Exception:
        return []


def resolve_ips_with_timeout(domain: str, timeout: float = 2.0) -> List[str]:
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut: Future = ex.submit(_resolve_sync, domain)
        try:
            return fut.result(timeout=timeout)
        except TimeoutError:
            return []
        except Exception:
            return []


def fetch_certificate_info(hostname: str, port: int = 443, timeout: float = 3.0) -> Tuple[Optional[str], Optional[str]]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subj = cert.get("subject")
                issuer = cert.get("issuer")

                def _fmt(name):
                    if not name:
                        return None
                    parts = []
                    for tup in name:
                        try:
                            if isinstance(tup, tuple) and len(tup) > 0 and isinstance(tup[0], tuple):
                                parts.append("=".join(tup[0]))
                            else:
                                parts.append(str(tup))
                        except Exception:
                            parts.append(str(tup))
                    return ", ".join(parts)[:200]

                return _fmt(subj), _fmt(issuer)
    except Exception:
        return None, None


def probe_domain(domain: str,
                 worker_id: int,
                 schemes: List[str] = ("https://", "http://"),
                 timeout: float = 8.0,
                 delay_min: float = 0.2,
                 delay_max: float = 0.6,
                 dns_timeout: float = 2.0) -> Dict[str, Optional[str]]:
    result: Dict[str, Optional[str]] = {
        "domain": domain,
        "attempted_url": None,
        "resolved_ips": None,
        "status": "down",
        "status_code": None,
        "reason": None,
        "server_header": None,
        "content_type": None,
        "content_length": None,
        "title": None,
        "response_time_ms": None,
        "final_url": None,
        "cert_subject": None,
        "cert_issuer": None,
        "error": None
    }

    ips = resolve_ips_with_timeout(domain, timeout=dns_timeout)
    if not ips:
        result["resolved_ips"] = ""
        result["error"] = f"no-dns-or-resolve-timeout({dns_timeout}s)"
        result["status"] = "down"
        return result
    result["resolved_ips"] = ";".join(ips)

    session = requests.Session()
    ua = random.choice(COMMON_USER_AGENTS)
    session.headers.update({
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })

    connect_timeout = min(3.0, timeout)
    req_timeout = (connect_timeout, timeout)

    for scheme in schemes:
        url = f"{scheme}{domain}"
        result["attempted_url"] = url
        start = time.time()
        try:
            r = session.get(url, allow_redirects=True, timeout=req_timeout, verify=False, stream=False)
            elapsed_ms = int((time.time() - start) * 1000)
            result["response_time_ms"] = str(elapsed_ms)
            result["status_code"] = str(r.status_code)
            result["reason"] = r.reason
            result["final_url"] = r.url
            result["server_header"] = r.headers.get("Server", "")
            result["content_type"] = r.headers.get("Content-Type", "")
            cl = r.headers.get("Content-Length")
            if cl:
                result["content_length"] = cl
            else:
                try:
                    body_sample = r.content
                    result["content_length"] = str(len(body_sample))
                    ct = result["content_type"] or ""
                    if "text/html" in ct.lower() or body_sample:
                        try:
                            text = body_sample.decode('utf-8', errors='ignore')
                        except Exception:
                            text = ""
                        title = extract_title(text)
                        if title:
                            result["title"] = title
                except Exception:
                    result["content_length"] = ""
            sc = r.status_code
            if (sc < 400) or (sc == 403):
                result["status"] = "alive"
            else:
                result["status"] = "down"
            if scheme.startswith("https"):
                subj, issuer = fetch_certificate_info(domain)
                if subj:
                    result["cert_subject"] = subj
                if issuer:
                    result["cert_issuer"] = issuer
            break
        except requests.exceptions.RequestException as e:
            result["error"] = repr(e)
            result["status"] = "down"
        except Exception as e:
            result["error"] = repr(e)
        finally:
            time.sleep(random.uniform(delay_min, delay_max))
    return result


def write_csv(path: str, rows: List[Dict[str, Optional[str]]]):
    fieldnames = [
        "domain",
        "attempted_url",
        "resolved_ips",
        "status_code",
        "server_header",
        "content_type",
        "title",
        "response_time_ms",
        "final_url",
        "cert_subject",
        "error"
    ]
    with open(path, "w", encoding="utf-8", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: (r.get(k) if r.get(k) is not None else "") for k in fieldnames})


def write_alive_list(path: str, rows: List[Dict[str, Optional[str]]]):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(f"{r.get('domain')}\n")


def parse_args():
    ap = argparse.ArgumentParser(description="Domain liveness probe (fast-skip dead DNS) for pentesters")
    ap.add_argument("--input", "-i", required=True, help="File with a list of domains (one domain per line)")
    ap.add_argument("--out-base", "-o", default="results", help="Output base prefix; when set, resulting files will be <prefix>_results_alive.txt and <prefix>_results.csv. Default names: results_alive.txt and results.csv")
    ap.add_argument("--workers", "-w", type=int, default=8, help="Number of parallel workers (default: 8)")
    ap.add_argument("--delay-min", type=float, default=0.1, help="Minimum delay after each request (seconds)")
    ap.add_argument("--delay-max", type=float, default=0.4, help="Maximum delay after each request (seconds)")
    ap.add_argument("--timeout", type=float, default=8.0, help="Total read timeout (seconds). Connect timeout = min(3, timeout).")
    ap.add_argument("--dns-timeout", type=float, default=2.0, help="DNS resolve timeout (seconds) for fast skipping of dead domains")
    return ap.parse_args()


def main():
    print_banner()
    args = parse_args()
    domains = read_domains_from_file(args.input)
    if not domains:
        print("Domain list is empty. Check the input file.", file=sys.stderr)
        sys.exit(2)

    total = len(domains)
    results: List[Dict[str, Optional[str]]] = []

    if RICH_AVAILABLE:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        )
        task = progress.add_task("Probing domains", total=total)
        progress.start()
        try:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futures = {
                    ex.submit(probe_domain, d, i, ("https://", "http://"), args.timeout, args.delay_min, args.delay_max, args.dns_timeout): d
                    for i, d in enumerate(domains)
                }
                for fut in as_completed(futures):
                    dom = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = {
                            "domain": dom, "attempted_url": None, "resolved_ips": "",
                            "status": "error", "status_code": "", "server_header": "",
                            "content_type": "", "title": "", "response_time_ms": "",
                            "final_url": "", "cert_subject": "", "cert_issuer": "", "error": repr(e)
                        }
                    results.append(res)
                    progress.advance(task)
        finally:
            progress.stop()
    elif TQDM_AVAILABLE:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {
                ex.submit(probe_domain, d, i, ("https://", "http://"), args.timeout, args.delay_min, args.delay_max, args.dns_timeout): d
                for i, d in enumerate(domains)
            }
            for fut in tqdm(as_completed(futures), total=total, desc="Probing"):
                dom = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {
                        "domain": dom, "attempted_url": None, "resolved_ips": "",
                        "status": "error", "status_code": "", "server_header": "",
                        "content_type": "", "title": "", "response_time_ms": "",
                        "final_url": "", "cert_subject": "", "cert_issuer": "", "error": repr(e)
                    }
                results.append(res)
    else:
        print(f"Probing {total} domains with {args.workers} workers...")
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {
                ex.submit(probe_domain, d, i, ("https://", "http://"), args.timeout, args.delay_min, args.delay_max, args.dns_timeout): d
                for i, d in enumerate(domains)
            }
            completed = 0
            for fut in as_completed(futures):
                dom = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {
                        "domain": dom, "attempted_url": None, "resolved_ips": "",
                        "status": "error", "status_code": "", "server_header": "",
                        "content_type": "", "title": "", "response_time_ms": "",
                        "final_url": "", "cert_subject": "", "cert_issuer": "", "error": repr(e)
                    }
                results.append(res)
                completed += 1
                print(f"[{completed}/{total}] {dom} -> {res.get('status')} ({res.get('status_code')})")

    results_sorted = sorted(results, key=lambda r: (0 if r.get("status") == "alive" else 1, r.get("domain")))
    alive_only = [r for r in results_sorted if r.get("status") == "alive"]
    skipped_count = len(results_sorted) - len(alive_only)

    prefix = "" if args.out_base == "results" else f"{args.out_base}_"
    alive_txt = f"{prefix}results_alive.txt"
    csv_path = f"{prefix}results.csv"
    write_alive_list(alive_txt, alive_only)
    write_csv(csv_path, alive_only)

    now = datetime.now(timezone.utc).isoformat()
    print(f"\nReport generated: {now} (UTC)")
    print(f"Alive: {len(alive_only)}/{len(results_sorted)} (skipped not-alive: {skipped_count})")
    print(f"Alive list saved to: {alive_txt}")
    print(f"CSV (compact) saved to: {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
