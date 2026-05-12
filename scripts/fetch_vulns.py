#!/usr/bin/env python3
"""
Weekly Vulnerability Fetcher
Sources: NVD (Linux + Kubernetes), Kubernetes CVE Feed, Red Hat Security Advisories
"""

import json
import re
import sys
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ── Config ────────────────────────────────────────────────────────────────────

DAYS_BACK = 7          # How many days to look back
OUTPUT_DIR = Path("reports")
OUTPUT_DIR.mkdir(exist_ok=True)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
K8S_CVE_FEED = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
RHSA_FEED = "https://access.redhat.com/hydra/rest/securitydata/cvrf.json"

KEYWORDS = {
    "linux":      ["linux kernel", "linux", "ubuntu", "rhel", "coreos", "kernel"],
    "kubernetes": ["kubernetes", "kubectl", "etcd", "kubelet", "kube-apiserver", "cri-o", "containerd", "crun", "runc"],
    "openshift":  ["openshift", "ose-", "okd", "microshift", "red hat openshift"],
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# ── Helpers ───────────────────────────────────────────────────────────────────

def http_get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-report-bot/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8")
    except Exception as e:
        print(f"  [WARN] GET {url} → {e}", file=sys.stderr)
        return None


def parse_date(s):
    """Parse ISO-8601 strings tolerantly."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt[:len(fmt)]).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def since():
    return (datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)).strftime("%Y-%m-%dT00:00:00.000")


def classify(text):
    text_lower = (text or "").lower()
    matches = []
    for category, kws in KEYWORDS.items():
        if any(kw in text_lower for kw in kws):
            matches.append(category)
    return matches if matches else ["other"]


def severity_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ── Fetchers ──────────────────────────────────────────────────────────────────

def fetch_nvd(keyword, label):
    """Fetch CVEs from NVD API v2 for a given keyword."""
    print(f"  Fetching NVD: {keyword}")
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "pubStartDate": since(),
        "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": 50,
    })
    raw = http_get(f"{NVD_BASE}?{params}")
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description available."
        )
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break

        severity = severity_from_score(score)
        pub_date = cve.get("published", "")[:10]
        refs = [r["url"] for r in cve.get("references", [])[:3]]

        results.append({
            "id": cve_id,
            "title": desc[:120] + ("…" if len(desc) > 120 else ""),
            "description": desc,
            "severity": severity,
            "score": score,
            "published": pub_date,
            "source": "NVD",
            "categories": classify(f"{keyword} {desc}"),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "refs": refs,
        })
    return results


def fetch_k8s_feed():
    """Fetch official Kubernetes CVE JSON feed."""
    print("  Fetching Kubernetes official CVE feed")
    raw = http_get(K8S_CVE_FEED)
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)
    results = []
    for item in data.get("items", []):
        pub = parse_date(item.get("date_published", ""))
        if pub and pub < cutoff:
            continue

        cve_id = item.get("id", "unknown")
        title = item.get("title", "")
        summary = item.get("summary", "")
        url = item.get("url", f"https://kubernetes.io/docs/reference/issues-security/official-cve-feed/")

        # Try to extract CVSS score from summary text
        score = None
        m = re.search(r"CVSS[^:]*:\s*([\d.]+)", summary, re.I)
        if m:
            try:
                score = float(m.group(1))
            except ValueError:
                pass

        results.append({
            "id": cve_id,
            "title": title[:120],
            "description": summary or title,
            "severity": severity_from_score(score),
            "score": score,
            "published": (pub.strftime("%Y-%m-%d") if pub else "unknown"),
            "source": "Kubernetes Official",
            "categories": ["kubernetes"],
            "url": url,
            "refs": [],
        })
    return results


def fetch_redhat_advisories():
    """Fetch Red Hat security advisories (RHSA) via their REST API."""
    print("  Fetching Red Hat Security Advisories")
    after = (datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)).strftime("%Y-%m-%d")
    params = urllib.parse.urlencode({
        "after": after,
        "product": "Red Hat Enterprise Linux",
        "limit": 50,
    })
    raw = http_get(f"{RHSA_FEED}?{params}")
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    results = []
    for item in data:
        rhsa_id = item.get("RHSA", item.get("id", "unknown"))
        severity = item.get("severity", "UNKNOWN").upper()
        if severity not in SEVERITY_ORDER:
            severity = "UNKNOWN"
        synopsis = item.get("synopsis", "")
        url = item.get("resource_url", f"https://access.redhat.com/errata/{rhsa_id}")
        issued = item.get("issued", "")[:10]
        cves = item.get("CVEs", [])

        results.append({
            "id": rhsa_id,
            "title": synopsis[:120],
            "description": synopsis,
            "severity": severity,
            "score": None,
            "published": issued,
            "source": "Red Hat",
            "categories": classify(synopsis),
            "url": url,
            "refs": [f"https://access.redhat.com/security/cve/{c}" for c in (cves or [])[:3]],
        })
    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def fetch_all():
    print("Fetching vulnerabilities…")
    vulns = []

    # NVD queries
    for kw in ["linux kernel", "kubernetes", "openshift"]:
        vulns += fetch_nvd(kw, kw)

    # Kubernetes official feed
    vulns += fetch_k8s_feed()

    # Red Hat advisories
    vulns += fetch_redhat_advisories()

    # Deduplicate by CVE/advisory ID
    seen = {}
    for v in vulns:
        vid = v["id"]
        if vid not in seen:
            seen[vid] = v
        else:
            # Merge categories
            seen[vid]["categories"] = list(set(seen[vid]["categories"] + v["categories"]))

    unique = list(seen.values())

    # Sort: severity first, then date
    unique.sort(key=lambda x: (
        SEVERITY_ORDER.get(x["severity"], 4),
        x["published"],
    ), reverse=False)

    print(f"  Total unique entries: {len(unique)}")
    return unique


def save_json(vulns):
    out = OUTPUT_DIR / "vulns.json"
    with open(out, "w") as f:
        json.dump({
            "generated": datetime.now(timezone.utc).isoformat(),
            "days_back": DAYS_BACK,
            "count": len(vulns),
            "vulnerabilities": vulns,
        }, f, indent=2)
    print(f"  Saved {out}")
    return out


if __name__ == "__main__":
    vulns = fetch_all()
    save_json(vulns)
    print("Done.")
