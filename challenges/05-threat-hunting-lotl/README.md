# INCIDENT 0505 — Operation CloudSnoop: Advanced Threat Hunt

## Threat Hunting Briefing

Threat Intelligence reports that an adversary group is actively targeting our industry with stealthy Living-off-the-Land (LotL) techniques and low-and-slow DNS data exfiltration.

The hunt hypothesis states:

> "An adversary may have achieved code execution on an internal workstation, masqueraded a process as a legitimate Windows service, and established a DNS tunneling channel to exfiltrate proprietary data."

## Datasets Available

Located in `/workspace/data/`:

1. `sysmon_processes.csv` — Endpoint process execution telemetry (ParentImage, Image, CommandLine, User, Timestamp).
2. `dns_queries.csv` — Comprehensive recursive DNS telemetry (Timestamp, ClientIP, QueryName, QueryType).

## Your Mission

Using your interactive Python Marimo environment:

1. Hunt for abnormal parent-child process chains and masqueraded execution paths.
2. Formulate a detection query for suspicious binary locations.
3. Compute subdomain character lengths and Shannon entropy on DNS query records to detect the tunneling channel.
4. Extract the exfiltrated flag payload and submit it to CTFd.

**Flag Format**: `FLAG{...}`
