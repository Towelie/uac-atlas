# uac-fleet-ai

AI-assisted post-collection analysis and fleet correlation for UAC (Unix-like Artifact Collector) outputs.

This tool reads existing UAC collections from disk, extracts a fixed set of artifacts, sends truncated evidence to an OpenAI-compatible Chat Completions API, stores the model’s JSON response, and correlates results across multiple hosts.

It is read-only and post-collection.

## What it reads

For each host directory under `--fleet-root`, the tool attempts to read the following paths if they exist.

Explicit files:
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

Directory ingestion (recursive file reads only):
- persistence/
- cron/
- systemd/
- services/
- users/

For each file read, the tool records SHA-256, size, mtime, and truncated content.  
Some sensitive paths are truncated more aggressively.

## Analysis performed

Local:
- Regex-based IOC extraction over collected text (IPs, domains, URLs, hashes, emails, paths)

AI-assisted:
- Sends extracted artifacts and local IOCs to the model
- Expects strict JSON containing:
  - Overall compromise likelihood
  - Findings with evidence
  - MITRE ATT&CK technique IDs
  - Model-extracted IOCs
  - Confidence and severity

## Fleet correlation

After all hosts are processed, the tool correlates:
- Shared ATT&CK techniques across hosts
- Shared IOCs across hosts
- Hosts ranked by model-provided compromise likelihood

## Output

Per host:
- bundle.json
- regex_iocs.json
- analysis.json

Fleet-level:
- fleet_summary.json
- fleet_features.json
- fleet_summary.csv

## Usage

Set OPENAI_API_KEY, then run:

python3 uac_fleet_ai.py --fleet-root /path/to/uac_collections --out ./results
