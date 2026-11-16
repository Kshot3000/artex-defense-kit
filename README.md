# ARTEX Defense Kit

**Find your own exposure to the ARTEX AI attack campaigns, and harden against the documented playbook — before an agent does it for you.**

I'm a solo developer, not a bank and not a security vendor. I built this kit because the ARTEX campaigns are aimed squarely at the kind of internet-facing apps, payment APIs, and public code repos that people like me run every day. Everything here is defensive: detection, hardening, and reporting. There is no ARTEX code in this repo, no exploit content, and nothing that helps run an attack.

## What ARTEX is

ARTEX is an open-source, LLM-driven autonomous penetration-testing framework written in Go. Released on GitHub in July 2026 by a developer ("Autumn-27") as a security-testing tool, it chains large language models (DeepSeek, Claude, GPT, GLM, Grok, Kimi) into agents that run reconnaissance, vulnerability discovery, exploitation, privilege escalation, and exfiltration with minimal human direction.

Threat actors picked it up almost immediately. Per the FBI, malicious actors have used ARTEX in campaigns since **at least August 2026**, and it **"significantly reduces the time required to chain attack techniques, with some intrusions progressing from initial targeting to privileged access in under three hours."** The original developer removed the GitHub repository on October 8, 2026 after abuse reports — but forks, mirrors, localized variants, archived copies, and a commercial "ARTEX PRO" keep it in circulation.

Documented impact so far:

- **South Korean financial institutions** — personal information of approximately **67,000 individuals** exfiltrated (FBI / CrowdStrike).
- **ConnectWise Cloud Backup supply-chain compromise** — access to **more than 2,250 downstream Microsoft 365 tenants** (FBI / Microsoft).
- **Storm-3358**, a financially motivated group Microsoft tracks, using ARTEX against financial organizations since October 2026 (Microsoft, Nov 6).
- **Credential theft at "industrial scale"** — Amazon Threat Intelligence watched ARTEX agents steal AI API keys between October 3 and November 5, 2026, and a second campaign generating **deepfake videos to defeat live selfie (KYC) checks** at cryptocurrency exchanges (AWS).
- **India's financial sector** — CERT-In advisory CIAD-2026-0058 (Nov 4, 2026) describes the "CRAFTY FALCON" actor abusing payment and disbursement APIs at non-banking financial companies, digital lenders, fintechs, and payment providers.

On **November 13, 2026**, the FBI issued **FLASH-20261113-001**, a public TLP:CLEAR advisory with tactics, techniques, and indicators for ARTEX. That advisory is the backbone of this kit.

## Who is affected

- Banks and credit unions — especially **peripheral systems**: loan-broker portals, employee mobile support apps, sales-support systems. ARTEX excels at the overlooked edges, not the flagship app.
- Fintechs, payment processors, and anyone exposing **payment/disbursement APIs**.
- Cryptocurrency exchanges (deepfake KYC bypass) and anyone running **LLM gateways or AI app builders** whose API keys are worth stealing.
- Cloud tenants — Microsoft 365 / Azure / AWS shops with over-privileged app consents, exposed publishing interfaces (Kudu/SCM), or secrets sitting in repos and pipelines.
- Really, any organization with internet-facing applications, self-service portals, or partner/supplier systems. The FBI lists financial services, government, technology, defense, semiconductor, energy, healthcare, manufacturing, telecommunications, and legal among targeted sectors.

## ⚠️ Warning: do NOT install ARTEX — the circulating Docker image is backdoored

If you go looking for ARTEX "to test it," you will find poisoned copies:

- The Docker image **`tomicdd/artex`** — and a re-push under **`congdonglinux/artex`** — is **backdoored with an unauthenticated root shell hidden in the login handler** (Sophos detects it as **Troj/Bckdr-SDA**). As of early November 2026, **637 GitHub repositories still pointed their Docker Compose files at that image** — meaning hundreds of people deployed an attacker's shell alongside the tool.
- The original upstream repo is gone. Anything you download now is a fork, a mirror, or worse, and cannot be trusted by provenance.
- If you have a legitimate, authorized need to evaluate this class of tooling: **pin images by digest, build only from reviewed source, and never expose a console to the internet.** Better yet, don't run it at all — use this kit to check whether someone else is running it *against* you, or whether *your* console is exposed.

Over **1,600 ARTEX consoles were publicly exposed** as of early November 2026 (FBI; Censys counted 1,465 hosts on Nov 3–4). An exposed console is both a liability and a confession — see [DETECTION.md](DETECTION.md).

## What this kit does

| File | What it's for |
|---|---|
| [DETECTION.md](DETECTION.md) | Fingerprints of an exposed ARTEX console (page titles, ports, favicon hash, Shodan/Censys queries), the campaigns' behavioral signals, and the FBI/Microsoft IOC lists (defanged). |
| [HARDENING.md](HARDENING.md) | A consolidated, source-attributed checklist from the FBI, Microsoft, AWS, and CERT-In advisories. |
| [tools/self-scan.sh](tools/self-scan.sh) | A self-assessment script you run against **your own** GitHub account and **your own** hosts: open secret-scanning alerts per repo, and ARTEX console fingerprints on hosts you operate. |
| [REPORTING.md](REPORTING.md) | Where to report — FBI IC3, CISA, KrCERT/CC, CERT-In — and what to include. |

## Primary sources

Read the advisories themselves; this kit is a companion, not a substitute.

- FBI FLASH-20261113-001, "Threat Overview of ARTEX Autonomous Penetration Testing Framework" (Nov 13, 2026) — https://www.ic3.gov/CSA/2026/261113.pdf
- Microsoft Threat Intelligence, "ARTEX abuse expands as cybercriminals target financial sector" (Nov 6, 2026) — https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/
- Microsoft Threat Intelligence, "Threat actors use agentic AI tooling to find and abuse exposed secrets" (Nov 5, 2026) — https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- Amazon Threat Intelligence, "Amazon Threat Intelligence observes threat actors running cybercrime campaigns with ARTEX AI agents" — https://aws.amazon.com/blogs/security/amazon-threat-intelligence-observes-threat-actors-running-cybercrime-campaigns-with-artex-ai-agents/
- Censys, "ARTEX: Agentic Asbestos" (Nov 5, 2026) — https://censys.com/blog/artex-agentic-asbestos/
- CrowdStrike, "Unknown Threat Actor Uses AI-Driven ARTEX to Target South Korean Finance" (Oct 7, 2026) — https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/
- MalwareMustDie, MMD-072-2026 ARTEX detection signature pack — community detection rules (YARA/Sigma-style) published by the MalwareMustDie team. Linked here with credit; their rules are **not** copied into this repo — get them from the source: https://blog.malwaremustdie.org/2026/11/mmd-072-2026-artex-detection-signature.html

## Responsible use

This kit is for **defensive purposes only**: assessing and hardening systems you own or are authorized to test, and reporting criminal activity to the authorities listed in [REPORTING.md](REPORTING.md). Do not use anything here to scan, probe, or access systems that aren't yours. If you find an exposed ARTEX console that isn't yours, the right move is to report it (see REPORTING.md), not to log in to it.

---

Built by Kyle Cox — @kshot9000 (https://x.com/kshot9000) · Tips: BTC 3GnR7TWBXAB3pPztBWpNF4LMNEX5yX8vZK
