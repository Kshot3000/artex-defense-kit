# Reporting: where to send ARTEX findings

Found an exposed console, campaign IOCs in your logs, or an intrusion that smells like ARTEX? Report it. These campaigns move across organizations at machine speed; your report is how the next target gets warned. Preserve evidence first (logs, sign-in records, console screenshots/configs if it's *your* system) — but don't delay containment to assemble a perfect package.

## United States — FBI

- **FBI Internet Crime Complaint Center (IC3):** https://www.ic3.gov
- Or your local FBI field office / Cyber Squad: https://www.fbi.gov/contact-us/field-offices

### What the FBI FLASH asks you to include

FLASH-20261113-001 ("Information Requested") lists what helps investigators most. Include what you have:

1. **ARTEX infrastructure artifacts** — source code or screenshots of suspected ARTEX console interfaces; ARTEX configuration files.
2. **Authentication and access logs** — service-principal sign-in logs showing unusual source networks, ASNs, hosting providers, or geographies; user-agent strings from suspicious authentication attempts; IP addresses and timestamps; authentication from previously unseen infrastructure.
3. **Application and API activity** — Microsoft Graph activity; Entra and Microsoft 365 audit records showing reconnaissance; sequential lookups or unusually high records-accessed-per-session on partner/employee portals; rate-limit violations and volumetric API anomalies.
4. **LLM/SI infrastructure indicators** — outbound connections to LLM API endpoints; self-hosted LLM gateway or reseller software in your environment (e.g., CLIProxyAPI, New API); unfamiliar LLM proxies in egress logs; **token-consumption or API billing anomalies**.
5. **Cloud and container activity** — AWS IAM logs; Azure ARM deployment validation dry-runs; test blob write/delete operations with sub-second timing; compromised Kudu/SCM credentials or unusual Kudu API activity; container orchestration logs; cloud metadata service queries; unexpected IAM role assumptions / PassRole operations / instance-profile changes.
6. **Exploitation and persistence artifacts** — web shells; BLOODALCHEMY components; open-source RAT indicators (WISP, vshell, AdaptixC2); newly created accounts; application credential modifications to OAuth apps; SSH key additions; Elastic IP allocations; unexpected EC2/Azure VM launches.
7. **Attack characteristics** — compressed bursts of activity; high volumes of failed attempts with iterative, incremental changes; signs of multiple sub-agents overwriting each other or duplicating requests; mass notification/email broadcasts from compromised applications.
8. **Loss and impact** — number of compromised accounts/affected users; types and volumes of data accessed or exfiltrated; time from initial suspicious activity to detection, and detection to containment; total attempted loss amounts.

General reporting notice from the FLASH: include the date, time, location, type of activity, number of people and type of equipment involved, your organization's name, and a designated point of contact.

## United States — CISA

- **Report a cyber incident:** https://www.cisa.gov/report
- **Email:** Report@CISA.gov

CISA is the right door for incidents affecting U.S. critical infrastructure and for coordinated vulnerability/infrastructure reporting.

## South Korea — KrCERT/CC

The heaviest confirmed bank breaches were Korean (Shinhan, KB Kookmin, Hana, and others). The named Korean banks **do not publish a `security.txt`**, so there is no direct, published security-contact route to the banks themselves — **KrCERT/CC is the working route for Korea**:

- **KrCERT/CC (Korea Internet & Security Agency):** https://www.boho.or.kr
- **Email:** first-team@krcert.or.kr

## India — CERT-In

For incidents in India's banking/financial sector — the sector covered by advisory CIAD-2026-0058 (CRAFTY FALCON) — report to the Indian Computer Emergency Response Team:

- **Email:** incident@cert-in.org.in
- CERT-In's finance-sector team (CSIRT-Fin) issued the CRAFTY FALCON advisory; reference **CIAD-2026-0058** when reporting matching activity (payment/disbursement API abuse, AI-assisted intrusion tooling).

## A note on exposed consoles that aren't yours

If your hunt turns up an ARTEX console on infrastructure you don't own: **do not log in to it, do not interact with it.** Screenshot the fingerprint (title, IP, port, timestamp) from your scan results and report it through the channels above. Accessing it — even "just to look" — can contaminate an investigation and may be unlawful where you live. Report, don't poke.
