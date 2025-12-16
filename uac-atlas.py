#!/usr/bin/env python3
"""
UAC Fleet AI Analyzer
- Extracts high-value UNIX artifacts from UAC collections
- Sends compact, structured evidence to an AI endpoint (OpenAI-compatible)
- Returns: findings w/ ATT&CK tags, model + regex IOC extraction, confidence scoring
- Correlates across multiple hosts (fleet correlation)

Usage:
  export OPENAI_API_KEY="..."
  python3 uac_fleet_ai.py --fleet-root /path/to/fleet --out ./results

Local-only:
  python3 uac_fleet_ai.py --fleet-root /path/to/fleet --out ./results --skip-ai
"""

import os
import re
import json
import time
import csv
import hashlib
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import requests

# --------------------------
# Defaults / Config
# --------------------------

DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")
DEFAULT_ENDPOINT = os.environ.get("OPENAI_ENDPOINT", "https://api.openai.com/v1/chat/completions")
DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# Keep payload sane: send summaries/metadata, not huge blobs
MAX_CHARS_PER_FILE = 12000
MAX_BYTES_PER_TEXT = 350_000

# --------------------------
# IOC Regex (local extraction)
# --------------------------

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "url": re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
    # Linux-ish paths (tune as needed; avoid overmatching)
    "path": re.compile(r"(?:(?:/[\w\.\-]+)+)"),
}

# Reduce false positives (common benign domains)
BENIGN_DOMAIN_DENYLIST = {
    "localhost",
    "localdomain",
    "example.com",
    "example.org",
    "example.net",
}

# --------------------------
# Helpers
# --------------------------

def read_text_file(path: Path, max_bytes: int = MAX_BYTES_PER_TEXT) -> Optional[str]:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(max_bytes)
    except Exception:
        return None


def truncate(text: Optional[str], limit: int = MAX_CHARS_PER_FILE) -> Optional[str]:
    if text is None:
        return None
    if len(text) > limit:
        return text[:limit] + "\n...[TRUNCATED]"
    return text


def sha256_file(path: Path) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------
# UAC Artifact Mapping (best-effort)
# --------------------------
# UAC profiles differ. This uses flexible probing:
# - looks for common filenames AND common logical directories if present.
# - missing artifacts are fine.
#

COMMON_TARGET_FILES = [
    # Identity / privilege
    "system/etc/passwd",
    "system/etc/group",
    "system/etc/shadow",  # may exist; treat carefully
    "system/etc/sudoers",
    # SSH
    "system/etc/ssh/sshd_config",
    "system/etc/ssh/ssh_config",
    # Network state snapshots
    "network/ip_addr.txt",
    "network/ip_route.txt",
    "network/ss_tulpn.txt",
    "network/netstat_tulpn.txt",
    "network/resolv.conf",
    "network/hosts",
    # Process snapshots
    "processes/ps_aux.txt",
    "processes/pstree.txt",
    # Packages
    "packages/dpkg.txt",
    "packages/rpm.txt",
    # Kernel / modules
    "system/uname.txt",
    "system/lsmod.txt",
    # Login history (if collected)
    "logs/lastlog.txt",
    "logs/wtmp.txt",
    "logs/btmp.txt",
]

COMMON_TARGET_DIRS = [
    # Persistence / sched
    "persistence",
    "cron",
    "systemd",
    "services",
    "users",  # may include per-user shell rc, authorized_keys, etc.
]

# Some files you may want to redact or hash-only
SENSITIVE_PATH_HINTS = [
    "shadow",
    "authorized_keys",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
]


def is_sensitive(rel: str) -> bool:
    r = rel.lower()
    return any(h in r for h in SENSITIVE_PATH_HINTS)


def collect_files(host_root: Path, relative_paths: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for rel in relative_paths:
        p = host_root / rel
        if p.exists() and p.is_file():
            content = read_text_file(p)
            if content is None:
                continue

            entry: Dict[str, Any] = {
                "sha256": sha256_file(p),
                "size": p.stat().st_size,
                "mtime": int(p.stat().st_mtime),
            }
            if is_sensitive(rel):
                # safer default: truncate aggressively
                entry["content"] = truncate(content, limit=2000)
            else:
                entry["content"] = truncate(content)

            out[rel] = entry
    return out


def collect_dirs(host_root: Path, relative_dirs: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for rel_dir in relative_dirs:
        base = host_root / rel_dir
        if not base.exists() or not base.is_dir():
            continue
        for f in base.rglob("*"):
            if not f.is_file():
                continue
            rel = safe_relpath(f, host_root)
            content = read_text_file(f)
            if content is None:
                continue
            entry: Dict[str, Any] = {
                "sha256": sha256_file(f),
                "size": f.stat().st_size,
                "mtime": int(f.stat().st_mtime),
            }
            if is_sensitive(rel):
                entry["content"] = truncate(content, limit=2000)
            else:
                entry["content"] = truncate(content)
            out[rel] = entry
    return out


def build_artifact_bundle(host_root: Path) -> Dict[str, Any]:
    # Best-effort: gather common files + “likely” dirs
    bundle = {
        "host_root": str(host_root),
        "collected_at": now_ts(),
        "files": collect_files(host_root, COMMON_TARGET_FILES),
        "dirs": collect_dirs(host_root, COMMON_TARGET_DIRS),
    }

    # Remove empties
    bundle["files"] = {k: v for k, v in bundle["files"].items() if v}
    bundle["dirs"] = {k: v for k, v in bundle["dirs"].items() if v}
    return bundle


# --------------------------
# Local IOC extraction
# --------------------------

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {k: [] for k in IOC_PATTERNS.keys()}
    for k, pat in IOC_PATTERNS.items():
        matches = pat.findall(text)
        if not matches:
            continue

        flat: List[str] = []
        for m in matches:
            if isinstance(m, tuple):
                flat.append("".join(m))
            else:
                flat.append(m)

        normed: List[str] = []
        for val in flat:
            v = val.strip().strip(".,;:()[]{}<>\"'")
            if k == "domain" and v.lower() in BENIGN_DOMAIN_DENYLIST:
                continue
            normed.append(v)

        seen = set()
        uniq: List[str] = []
        for v in normed:
            if v not in seen:
                seen.add(v)
                uniq.append(v)

        found[k] = uniq[:500]  # cap per artifact text
    return {k: v for k, v in found.items() if v}


def extract_iocs_from_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    agg: Dict[str, List[str]] = {}

    def merge(new: Dict[str, List[str]]):
        for k, vals in new.items():
            if k not in agg:
                agg[k] = []
            for v in vals:
                if v not in agg[k]:
                    agg[k].append(v)

    for _, entry in bundle.get("files", {}).items():
        c = entry.get("content")
        if isinstance(c, str):
            merge(extract_iocs_from_text(c))

    for _, entry in bundle.get("dirs", {}).items():
        c = entry.get("content")
        if isinstance(c, str):
            merge(extract_iocs_from_text(c))

    return {"regex_iocs": agg}


# --------------------------
# AI call + strict JSON output
# --------------------------

AI_SYSTEM_PROMPT = """You are a DFIR + threat-hunting analyst.
You will be given high-value UNIX host artifacts from a UAC collection (compact, not huge logs).

Your job:
1) Identify suspicious findings and explain evidence.
2) Tag each finding with MITRE ATT&CK technique IDs and names (e.g., T1053.003 Cron, T1543.002 Systemd Service).
3) Extract IOCs from evidence (IPs, domains, URLs, hashes, file paths, usernames, process names).
4) Provide confidence scoring for each finding (0.0-1.0) with short rationale.
5) Provide an overall host compromise likelihood score (0.0-1.0).

OUTPUT MUST BE VALID JSON ONLY (no markdown) matching this schema:

{
  "host_summary": {
    "overall_compromise_likelihood": 0.0,
    "overall_rationale": "string",
    "key_risks": ["string", ...],
    "recommended_next_steps": ["string", ...]
  },
  "findings": [
    {
      "title": "string",
      "description": "string",
      "evidence": ["string", ...],
      "attack": [{"technique_id":"Txxxx","technique_name":"string","tactic":["string", ...]}],
      "iocs": {
        "ip": ["string", ...],
        "domain": ["string", ...],
        "url": ["string", ...],
        "hash": ["string", ...],
        "path": ["string", ...],
        "user": ["string", ...],
        "process": ["string", ...]
      },
      "confidence": 0.0,
      "confidence_rationale": "string",
      "severity": "low|medium|high|critical"
    }
  ],
  "model_iocs": {
    "ip": ["string", ...],
    "domain": ["string", ...],
    "url": ["string", ...],
    "hash": ["string", ...],
    "path": ["string", ...]
  }
}

If there is insufficient evidence, say so explicitly and keep findings minimal.
"""


def call_ai(endpoint: str, api_key: str, model: str, payload: Dict[str, Any], timeout: int = 180) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
        "temperature": 0.1,
    }
    r = requests.post(endpoint, headers=headers, json=body, timeout=timeout)
    r.raise_for_status()
    data = r.json()

    content = data["choices"][0]["message"]["content"]

    try:
        return json.loads(content)
    except Exception:
        return {"_parse_error": True, "_raw_model_output": content}


# --------------------------
# Fleet correlation
# --------------------------

def normalize_ioc_dict(d: Dict[str, Any]) -> Dict[str, List[str]]:
    if not isinstance(d, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for k, v in d.items():
        if isinstance(v, list):
            out[k] = [str(x) for x in v if str(x).strip()]
    return out


def gather_host_features(host: str, ai_result: Dict[str, Any], regex_iocs: Dict[str, Any]) -> Dict[str, Any]:
    findings = ai_result.get("findings", []) if isinstance(ai_result, dict) else []
    host_summary = ai_result.get("host_summary", {}) if isinstance(ai_result, dict) else {}
    compromise = host_summary.get("overall_compromise_likelihood", None)

    # Collect techniques used
    techniques: List[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for a in f.get("attack", []) if isinstance(f.get("attack"), list) else []:
            if not isinstance(a, dict):
                continue
            tid = a.get("technique_id")
            if tid and tid not in techniques:
                techniques.append(tid)

    # Collect model IOCs
    model_iocs = normalize_ioc_dict(ai_result.get("model_iocs", {})) if isinstance(ai_result, dict) else {}

    # Collect regex IOCs
    rx = regex_iocs.get("regex_iocs", {}) if isinstance(regex_iocs, dict) else {}
    rx_norm = normalize_ioc_dict(rx)

    # Severity counts
    sev_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = f.get("severity")
        if sev in sev_counts:
            sev_counts[sev] += 1

    return {
        "host": host,
        "overall_compromise_likelihood": compromise,
        "techniques": techniques,
        "severity_counts": sev_counts,
        "model_iocs": model_iocs,
        "regex_iocs": rx_norm,
        "finding_titles": [f.get("title", "") for f in findings if isinstance(f, dict)],
    }


def correlate_fleet(host_features: List[Dict[str, Any]]) -> Dict[str, Any]:
    technique_hosts: Dict[str, List[str]] = {}
    ioc_hosts: Dict[Tuple[str, str], List[str]] = {}  # (type, value) -> hosts

    def add_ioc(ioc_type: str, value: str, host: str):
        key = (ioc_type, value)
        if key not in ioc_hosts:
            ioc_hosts[key] = []
        if host not in ioc_hosts[key]:
            ioc_hosts[key].append(host)

    for hf in host_features:
        host = hf["host"]

        for t in hf.get("techniques", []):
            technique_hosts.setdefault(t, [])
            if host not in technique_hosts[t]:
                technique_hosts[t].append(host)

        # Combine model + regex iocs for correlation
        for src in ("model_iocs", "regex_iocs"):
            iocs = hf.get(src, {})
            if not isinstance(iocs, dict):
                continue
            for typ, vals in iocs.items():
                if not isinstance(vals, list):
                    continue
                for v in vals:
                    add_ioc(str(typ), str(v), host)

    shared_techniques = [
        {"technique_id": t, "hosts": hs, "host_count": len(hs)}
        for t, hs in technique_hosts.items()
        if len(hs) >= 2
    ]
    shared_techniques.sort(key=lambda x: x["host_count"], reverse=True)

    shared_iocs = [
        {"type": typ, "value": val, "hosts": hs, "host_count": len(hs)}
        for (typ, val), hs in ioc_hosts.items()
        if len(hs) >= 2
    ]
    shared_iocs.sort(key=lambda x: x["host_count"], reverse=True)

    # High risk host ordering
    scored = []
    for hf in host_features:
        s = hf.get("overall_compromise_likelihood")
        if isinstance(s, (int, float)):
            scored.append((hf["host"], float(s)))
    scored.sort(key=lambda x: x[1], reverse=True)

    return {
        "fleet_summary": {
            "host_count": len(host_features),
            "highest_risk_hosts": [{"host": h, "score": s} for h, s in scored[:10]],
            "shared_techniques": shared_techniques[:50],
            "shared_iocs": shared_iocs[:200],
        }
    }


# --------------------------
# Main
# --------------------------

def find_host_collections(fleet_root: Path) -> List[Path]:
    hosts = [p for p in fleet_root.iterdir() if p.is_dir()]
    hosts.sort()
    return hosts


def write_json(path: Path, obj: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser(description="Analyze UAC collections against an AI endpoint + fleet correlation.")
    ap.add_argument("--fleet-root", required=True, help="Directory containing per-host UAC collection directories.")
    ap.add_argument("--out", default="./results", help="Output directory.")
    ap.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="Chat Completions endpoint URL.")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Model name.")
    ap.add_argument("--api-key", default=DEFAULT_API_KEY, help="API key (or set OPENAI_API_KEY).")
    ap.add_argument("--skip-ai", action="store_true", help="Only run local regex IOC extraction + fleet correlation.")
    args = ap.parse_args()

    fleet_root = Path(args.fleet_root).expanduser().resolve()
    out_root = Path(args.out).expanduser().resolve()

    if not fleet_root.exists() or not fleet_root.is_dir():
        raise SystemExit(f"fleet-root does not exist or is not a dir: {fleet_root}")

    if not args.skip_ai and not args.api_key:
        raise SystemExit("No API key provided. Set --api-key or OPENAI_API_KEY, or use --skip-ai.")

    host_dirs = find_host_collections(fleet_root)
    if not host_dirs:
        raise SystemExit(f"No host directories found under: {fleet_root}")

    fleet_features: List[Dict[str, Any]] = []

    for host_dir in host_dirs:
        host = host_dir.name
        print(f"[*] Host: {host}")

        bundle = build_artifact_bundle(host_dir)
        regex_iocs = extract_iocs_from_bundle(bundle)

        payload = {
            "host": host,
            "uac_bundle": bundle,
            "regex_iocs": regex_iocs.get("regex_iocs", {}),
            "notes": "Compact UAC artifacts; large raw logs were intentionally excluded."
        }

        host_out_dir = out_root / host
        write_json(host_out_dir / "bundle.json", bundle)
        write_json(host_out_dir / "regex_iocs.json", regex_iocs)

        ai_result: Dict[str, Any]
        if args.skip_ai:
            ai_result = {
                "host_summary": {"overall_compromise_likelihood": None, "overall_rationale": "AI skipped."},
                "findings": [],
                "model_iocs": {}
            }
        else:
            print(f"    [-] Calling AI ({args.model})...")
            ai_result = call_ai(args.endpoint, args.api_key, args.model, payload)
        write_json(host_out_dir / "analysis.json", ai_result)

        feats = gather_host_features(host, ai_result, regex_iocs)
        fleet_features.append(feats)

    fleet = correlate_fleet(fleet_features)
    write_json(out_root / "fleet_summary.json", fleet)
    write_json(out_root / "fleet_features.json", fleet_features)

    csv_path = out_root / "fleet_summary.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "host",
            "overall_compromise_likelihood",
            "sev_low", "sev_medium", "sev_high", "sev_critical",
            "technique_count",
            "top_titles"
        ])
        for hf in fleet_features:
            sc = hf.get("overall_compromise_likelihood")
            sev = hf.get("severity_counts", {})
            titles = "; ".join([t for t in hf.get("finding_titles", []) if t][:5])
            w.writerow([
                hf["host"],
                sc if isinstance(sc, (int, float)) else "",
                sev.get("low", 0), sev.get("medium", 0), sev.get("high", 0), sev.get("critical", 0),
                len(hf.get("techniques", [])),
                titles
            ])

    print(f"[+] Done. Results in: {out_root}")
    print(f"[+] Fleet CSV: {csv_path}")


if __name__ == "__main__":
    main()
