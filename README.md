# uac-atlas

High-signal analysis and fleet correlation for Unix-like Artifact Collector (UAC) output.

---

## Overview

`uac-atlas` is a post-collection analysis framework for **Unix-like Artifact Collector (UAC)** data.  
It focuses on extracting and analyzing **high-value host artifacts** (identity, persistence, execution, scheduling, and network state) rather than ingesting large raw logs or full disk images.

The project is designed to support:

- Rapid host compromise assessment
- Fleet-wide correlation across multiple UAC collections
- Evidence-based triage with explicit confidence scoring
- Analyst review, not automated remediation

Optional LLM-assisted enrichment can be used to map findings to **MITRE ATT&CK**, extract higher-level indicators, and assess likelihood of compromise.

---

## Design Goals

- **High signal, low noise**  
  Prioritize artifacts attackers commonly abuse and forget to clean up.

- **Explainable output**  
  Every finding includes evidence, technique mapping, and confidence rationale.

- **Fleet-aware**  
  Identify shared indicators and techniques across multiple hosts.

- **Analyst-first**  
  The tool assists investigation; it does not make decisions for you.

---

## Non-Goals

`uac-atlas` intentionally does **not** attempt to:

- Replace full forensic analysis
- Ingest or analyze large raw logs (syslog, auditd, PCAPs)
- Perform live response or containment
- Automatically remediate or block activity
- Act as an EDR or detection engine

---

## What It Analyzes

From UAC collections, `uac-atlas` targets:

- **Identity & privilege**
  - Users, groups, sudo configuration
- **Persistence mechanisms**
  - systemd services, init scripts, cron jobs
- **Scheduled execution**
  - cron, timers
- **Process & execution state**
  - process listings, command lines, parent-child trees
- **Network**
