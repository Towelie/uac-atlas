# uac-fleet-ai

Post-collection analysis and fleet correlation for  
**UAC (Unix-like Artifact Collector)** outputs using an OpenAI-compatible LLM.

This tool reads existing UAC collections from disk, extracts a fixed set of artifacts,
performs local IOC extraction, submits compact evidence to an AI endpoint, stores the
model’s JSON output, and correlates results across multiple hosts.

All operations are read-only.

---

## Overview

uac-fleet-ai is designed to sit **after UAC collection** and assist analysts with
initial host triage and fleet-level pattern discovery.

It does not collect artifacts, access live systems, or perform remediation.

---

## What it does

- Reads a predefined set of files and directories from UAC collections
- Records file metadata (SHA-256, size, mtime) and truncated content
- Performs local regex-based IOC extraction
- Sends artifacts and local IOCs to an OpenAI-compatible Chat Completions API
- Stores model-generated JSON output without modification or validation
- Correlates model output and extracted IOCs across hosts

---

## Artifacts read

For each host directory under `--fleet-root`, the following paths are read **if present**.

### Files
- system/etc/passwd  
- system/etc/group  
- system/etc/shadow  
- system/etc/sudoers  
- system/etc/ssh/sshd_config  
- system/etc/ssh/ssh_config  
- system/uname.txt  
- system/lsmod.txt  
- network/ip_addr.txt  
- network/ip_route.txt  
- network/ss_tulpn.txt  
- network/netstat_tulpn.txt  
- network/resolv.conf  
- network/hosts  
- processes/ps_aux.txt  
- processes/pstree.txt  
- packages/dpkg.txt  
- packages/rpm.txt  
- logs/lastlog.txt  
- logs/wtmp.txt  
- logs/btmp.txt  

### Directories (recursive file reads only)
- persistence/  
- cron/  
- systemd/  
- services/  
- users/  

For each file, SHA-256, size, mtime, and truncated content are recorded.  
Sensitive paths are truncated more aggressively.

---

## Analysis performed

### Local
- Regex-based IOC extraction:
  - IP addresses (IPv4/IPv6)
  - Domains
  - URLs
  - MD5 / SHA1 / SHA256 hashes
  - Email addresses
  - UNIX-like file paths

### AI-assisted
- Requests model-generated:
  - Findings with evidence
  - MITRE ATT&CK technique IDs
  - Model-extracted IOCs
  - Confidence scores and severity
  - Overall compromise likelihood

AI output is stored as-is and is not validated beyond JSON parsing.

---

## Fleet correlation

After all hosts are processed, the tool correlates:
- Shared ATT&CK technique IDs across hosts
- Shared IOCs across hosts
- Hosts ranked by model-provided compromise likelihood

Correlation is string-based and result-driven only.

---

## Usage

Set `OPENAI_API_KEY`, then run:

python3 uac_fleet_ai.py --fleet-root /path/to/uac_collections --out ./results

Use `--skip-ai` to disable AI calls while keeping local IOC extraction
and fleet correlation.

---

## Out of scope

- Artifact collection
- Live system access
- Validation of AI output
- Detection guarantees
- Remediation or response actions
